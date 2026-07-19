// RecoverAndDecompilePLC.java
// One-click, in-Ghidra recovery for an already imported PLC binary.
//
// The script creates no external reports and never modifies executable bytes.
// It changes only the current Ghidra program database by creating instructions,
// functions, bookmarks, and conservative decompiler parameter information.
//
// @category PLC Analysis
// @menupath Tools.PLC Analysis.Recover and Decompile PLC

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.DecompilerParameterIdCmd;
import ghidra.app.decompiler.*;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

import javax.swing.JOptionPane;
import java.util.*;

public class RecoverAndDecompilePLC extends GhidraScript {

    private static final int MAX_RECOVERY_PASSES = 5;
    private static final int MAX_TOTAL_CREATED_FUNCTIONS = 10000;
    private static final int MAX_CANDIDATES_PER_PASS = 20000;
    private static final int MAX_FUNCTION_SPAN_BYTES = 0x20000;
    private static final int PSEUDO_MAX_INSTRUCTIONS = 2500;
    private static final int MIN_CONTIGUOUS_INSTRUCTIONS = 4;
    private static final int MIN_NONRETURN_CONTIGUOUS_INSTRUCTIONS = 12;
    private static final int DECOMPILER_TIMEOUT_SECONDS = 30;
    private static final long RAW_FIXED_WIDTH_SCAN_LIMIT_BYTES = 16L * 1024L * 1024L;
    private static final int MAX_GAP_SCAN_CANDIDATES = 2500;

    private static final String BOOKMARK_TYPE = "Analysis";
    private static final String BOOKMARK_PREFIX = "PLC Recovery/";

    private final Map<String, Candidate> candidates = new LinkedHashMap<>();
    private final List<Address> newlyCreatedEntries = new ArrayList<>();

    private int createdFunctions;
    private int failedFunctionCreations;
    private int decompileSuccesses;
    private int decompileFailures;
    private int parameterIdFunctions;

    private boolean rawLike;
    private String processorName;
    private int instructionAlignment;

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("No program is open.");
            return;
        }

        initializeProgramFacts();
        clearOldRecoveryBookmarks();
        printProgramSummary();

        if (rawLike) {
            makeInitializedBlocksExecutableWhenNecessary();
        }

        monitor.setMessage("Running Ghidra auto-analysis...");
        analyzeAll(currentProgram);

        monitor.setMessage("Collecting initial function candidates...");
        collectBlockStarts();
        collectSymbolCandidates();
        collectDirectCallTargets();
        scanArchitecturePrologues();
        recoverCandidateBatch("initial recovery");

        for (int pass = 1;
             pass <= MAX_RECOVERY_PASSES &&
             !monitor.isCancelled() &&
             createdFunctions < MAX_TOTAL_CREATED_FUNCTIONS;
             pass++) {

            int before = createdFunctions;
            collectSymbolCandidates();
            collectDirectCallTargets();
            recoverCandidateBatch("call-target pass " + pass);

            if (createdFunctions > before) {
                analyzeChanges(currentProgram);
            }
            else {
                break;
            }
        }

        if (shouldRunFixedWidthGapScan() &&
            createdFunctions < MAX_TOTAL_CREATED_FUNCTIONS &&
            !monitor.isCancelled()) {

            monitor.setMessage("Scanning aligned undefined regions...");
            collectValidatedGapCandidates();
            recoverCandidateBatch("fixed-width raw gap scan");
        }

        monitor.setMessage("Running final Ghidra analysis...");
        analyzeChanges(currentProgram);

        runDecompilerParameterIdentification();
        validateAllFunctionsWithDecompiler();
        bookmarkLikelyPlcFunctions();

        Address destination = chooseNavigationDestination();
        if (destination != null) {
            goTo(destination);
        }

        showSummary();
    }

    // ------------------------------------------------------------------
    // Program setup
    // ------------------------------------------------------------------

    private void initializeProgramFacts() {
        String format = safe(currentProgram.getExecutableFormat()).toLowerCase(Locale.ROOT);
        rawLike = format.contains("raw") || format.equals("binary") || format.contains("raw binary");
        processorName = currentProgram.getLanguage().getProcessor().toString().toLowerCase(Locale.ROOT);
        instructionAlignment = Math.max(1, currentProgram.getLanguage().getInstructionAlignment());
    }

    private void printProgramSummary() {
        println("============================================================");
        println("RecoverAndDecompilePLC");
        println("Program: " + currentProgram.getName());
        println("Format: " + safe(currentProgram.getExecutableFormat()));
        println("Language: " + currentProgram.getLanguageID());
        println("Processor: " + processorName);
        println("Raw-like import: " + rawLike);
        println("============================================================");
    }

    private void makeInitializedBlocksExecutableWhenNecessary() {
        Memory memory = currentProgram.getMemory();

        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isInitialized() && block.isExecute()) {
                return;
            }
        }

        int changed = 0;
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized()) {
                continue;
            }
            try {
                block.setExecute(true);
                changed++;
            }
            catch (Exception e) {
                println("Could not enable execute permission on " + block.getName() + ": " + e.getMessage());
            }
        }

        if (changed > 0) {
            println("Raw import: enabled execute permission on " + changed + " initialized block(s).");
        }
    }

    // ------------------------------------------------------------------
    // Candidate collection
    // ------------------------------------------------------------------

    private void collectBlockStarts() {
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (shouldInspectBlock(block)) {
                addCandidate(block.getStart(), 70, "initialized memory-block start");
            }
        }
    }

    private void collectSymbolCandidates() {
        SymbolIterator iterator = currentProgram.getSymbolTable().getSymbolIterator(true);
        int processed = 0;

        while (iterator.hasNext() && !monitor.isCancelled() && processed < MAX_CANDIDATES_PER_PASS) {
            Symbol symbol = iterator.next();
            processed++;

            Address address = symbol.getAddress();
            if (!isCandidateAddress(address)) {
                continue;
            }

            boolean functionSymbol = symbol.getSymbolType() == SymbolType.FUNCTION;
            boolean strongSource = symbol.getSource() == SourceType.IMPORTED ||
                                   symbol.getSource() == SourceType.USER_DEFINED;
            boolean plcName = looksLikePlcName(symbol.getName());

            if (functionSymbol || strongSource || plcName) {
                int priority = functionSymbol ? 100 : plcName ? 95 : 85;
                addCandidate(address, priority, "symbol: " + symbol.getName());
            }
        }
    }

    private void collectDirectCallTargets() {
        Listing listing = currentProgram.getListing();
        ReferenceManager referenceManager = currentProgram.getReferenceManager();
        InstructionIterator instructions = listing.getInstructions(true);
        int processed = 0;

        while (instructions.hasNext() && !monitor.isCancelled() && processed < 5000000) {
            Instruction instruction = instructions.next();
            processed++;

            for (Reference reference : referenceManager.getReferencesFrom(instruction.getAddress())) {
                if (!reference.getReferenceType().isCall()) {
                    continue;
                }
                Address target = normalizeCodeAddress(reference.getToAddress());
                if (isCandidateAddress(target)) {
                    addCandidate(target, 100,
                        "direct call target from " + addressText(instruction.getAddress()));
                }
            }

            if (instruction.getFlowType().isCall()) {
                for (Address flow : instruction.getFlows()) {
                    Address target = normalizeCodeAddress(flow);
                    if (isCandidateAddress(target)) {
                        addCandidate(target, 100,
                            "call-flow target from " + addressText(instruction.getAddress()));
                    }
                }
            }
        }
    }

    private void scanArchitecturePrologues() {
        Memory memory = currentProgram.getMemory();
        boolean bigEndian = currentProgram.getLanguage().isBigEndian();

        for (MemoryBlock block : memory.getBlocks()) {
            if (!shouldInspectBlock(block) || monitor.isCancelled()) {
                continue;
            }

            int alignment = prologueScanAlignment();
            Address cursor = alignUp(block.getStart(), alignment);

            while (cursor != null && cursor.compareTo(block.getEnd()) <= 0 && !monitor.isCancelled()) {
                boolean matched = false;

                try {
                    if (processorName.contains("aarch64")) {
                        int word = memory.getInt(cursor, bigEndian);
                        // STP X29, X30, [SP, #-imm]!
                        matched = (word & 0xffc07fff) == 0xa9807bfd;
                    }
                    else if (processorName.contains("arm")) {
                        String languageId = currentProgram.getLanguageID().toString().toLowerCase(Locale.ROOT);
                        boolean thumbDefault = instructionAlignment <= 2 ||
                            languageId.contains("v7t") || languageId.contains("v8t");

                        if (thumbDefault) {
                            int halfword = readUnsignedShort(cursor, bigEndian);
                            // Thumb PUSH {..., LR}
                            matched = (halfword & 0xff00) == 0xb500;
                        }
                        else {
                            int word = memory.getInt(cursor, bigEndian);
                            // ARM A32 STMDB SP!, {..., LR}
                            matched = (word & 0x0fff0000) == 0x092d0000 &&
                                      (word & 0x00004000) != 0;
                        }
                    }
                    else if (processorName.contains("x86")) {
                        matched = matchesX86Prologue(cursor);
                    }
                    else if (processorName.contains("mips")) {
                        int word = memory.getInt(cursor, bigEndian);
                        // ADDIU SP, SP, negative_imm
                        matched = (word & 0xffff0000) == 0x27bd0000 &&
                                  (word & 0x00008000) != 0;
                    }
                    else if (processorName.contains("powerpc")) {
                        int word = memory.getInt(cursor, bigEndian);
                        // STWU R1, negative_imm(R1)
                        matched = (word & 0xffff0000) == 0x94210000 &&
                                  (word & 0x00008000) != 0;
                    }
                }
                catch (Exception ignored) {
                    matched = false;
                }

                if (matched) {
                    addCandidate(cursor, 90, "architecture function-prologue pattern");
                }

                cursor = safeAdd(cursor, alignment);
            }
        }
    }

    private boolean matchesX86Prologue(Address address) {
        byte[] bytes = new byte[8];

        try {
            if (currentProgram.getMemory().getBytes(address, bytes) < 2) {
                return false;
            }
        }
        catch (Exception e) {
            return false;
        }

        int b0 = bytes[0] & 0xff;
        int b1 = bytes[1] & 0xff;
        int b2 = bytes[2] & 0xff;
        int b3 = bytes[3] & 0xff;
        int b4 = bytes[4] & 0xff;

        return
            (b0 == 0x55 && b1 == 0x8b && b2 == 0xec) ||
            (b0 == 0x55 && b1 == 0x89 && b2 == 0xe5) ||
            (b0 == 0x55 && b1 == 0x48 && b2 == 0x89 && b3 == 0xe5) ||
            (b0 == 0x48 && b1 == 0x83 && b2 == 0xec) ||
            (b0 == 0x48 && b1 == 0x81 && b2 == 0xec) ||
            (b0 == 0x40 && b1 == 0x53) ||
            (b0 == 0x48 && b1 == 0x89 && b2 == 0x5c && b3 == 0x24) ||
            (b0 == 0x4c && b1 == 0x8b && b2 == 0xdc) ||
            (b0 == 0xf3 && b1 == 0x0f && b2 == 0x1e && b3 == 0xfa && b4 == 0x55);
    }

    private void collectValidatedGapCandidates() {
        PseudoDisassembler pseudo = new PseudoDisassembler(currentProgram);
        pseudo.setMaxInstructions(PSEUDO_MAX_INSTRUCTIONS);
        int added = 0;

        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!shouldInspectBlock(block) || monitor.isCancelled() ||
                added >= MAX_GAP_SCAN_CANDIDATES) {
                break;
            }

            Address cursor = alignUp(block.getStart(), instructionAlignment);

            while (cursor != null && cursor.compareTo(block.getEnd()) <= 0 &&
                   !monitor.isCancelled() && added < MAX_GAP_SCAN_CANDIDATES) {

                if (isUndefinedCandidateLocation(cursor) && !looksLikePadding(cursor)) {
                    boolean valid = false;
                    try {
                        valid = pseudo.checkValidSubroutine(cursor, false, true, true);
                    }
                    catch (Exception ignored) {
                        valid = false;
                    }

                    if (valid && pseudo.getLastCheckValidInstructionCount() >= 8) {
                        addCandidate(cursor, 50, "validated aligned raw-code gap");
                        added++;
                    }
                }

                cursor = safeAdd(cursor, instructionAlignment);
            }
        }

        println("Fixed-width gap scan added " + added + " validated candidate(s).");
    }

    // ------------------------------------------------------------------
    // Candidate validation and creation
    // ------------------------------------------------------------------

    private void recoverCandidateBatch(String stage) {
        if (candidates.isEmpty() || createdFunctions >= MAX_TOTAL_CREATED_FUNCTIONS) {
            return;
        }

        List<Candidate> batch = new ArrayList<>(candidates.values());
        candidates.clear();

        batch.sort(new Comparator<Candidate>() {
            @Override
            public int compare(Candidate left, Candidate right) {
                if (left.priority != right.priority) {
                    return right.priority - left.priority;
                }
                return left.address.compareTo(right.address);
            }
        });

        println("Recovery stage '" + stage + "': " + batch.size() + " candidate(s).");
        int processed = 0;

        for (Candidate candidate : batch) {
            if (monitor.isCancelled() || createdFunctions >= MAX_TOTAL_CREATED_FUNCTIONS ||
                processed >= MAX_CANDIDATES_PER_PASS) {
                break;
            }

            processed++;
            if (recoverCandidate(candidate)) {
                createdFunctions++;
                newlyCreatedEntries.add(candidate.address);
                addBookmark(candidate.address,
                    BOOKMARK_PREFIX + "Recovered Function",
                    "Created from " + join(candidate.reasons, "; ") +
                    "; validation priority=" + candidate.priority);
            }
        }

        if (!newlyCreatedEntries.isEmpty()) {
            analyzeChanges(currentProgram);
        }
    }

    private boolean recoverCandidate(Candidate candidate) {
        Address address = normalizeCodeAddress(candidate.address);

        if (!isCandidateAddress(address) || getFunctionAt(address) != null ||
            getFunctionContaining(address) != null) {
            return false;
        }

        Listing listing = currentProgram.getListing();
        Data definedData = listing.getDefinedDataContaining(address);
        if (definedData != null) {
            return false;
        }

        Instruction existingInstruction = listing.getInstructionAt(address);
        PseudoDisassembler pseudo = new PseudoDisassembler(currentProgram);
        pseudo.setMaxInstructions(PSEUDO_MAX_INSTRUCTIONS);

        boolean validTerminating = false;
        boolean validNonTerminating = false;

        try {
            validTerminating = pseudo.checkValidSubroutine(
                address, existingInstruction != null, true, true);
        }
        catch (Exception ignored) {
            validTerminating = false;
        }

        int contiguous = pseudo.getLastCheckValidInstructionCount();

        if (!validTerminating && candidate.priority >= 90) {
            try {
                validNonTerminating = pseudo.checkValidSubroutine(
                    address, existingInstruction != null, false, true);
            }
            catch (Exception ignored) {
                validNonTerminating = false;
            }
            contiguous = Math.max(contiguous, pseudo.getLastCheckValidInstructionCount());
        }

        boolean accepted =
            (validTerminating && contiguous >= MIN_CONTIGUOUS_INSTRUCTIONS) ||
            (validNonTerminating && contiguous >= MIN_NONRETURN_CONTIGUOUS_INSTRUCTIONS);

        if (!accepted) {
            return false;
        }

        if (existingInstruction == null) {
            MemoryBlock block = currentProgram.getMemory().getBlock(address);
            if (block == null) {
                return false;
            }

            Address restrictedEnd = chooseRestrictedEnd(address, block);
            DisassembleCommand command = new DisassembleCommand(
                address, new AddressSet(address, restrictedEnd), true);
            command.enableCodeAnalysis(false);

            boolean disassembled = command.applyTo(currentProgram, monitor);
            if (!disassembled && listing.getInstructionAt(address) == null) {
                return false;
            }
        }

        Function created = createFunction(address, null);
        if (created == null) {
            failedFunctionCreations++;
            return false;
        }

        return true;
    }

    private Address chooseRestrictedEnd(Address start, MemoryBlock block) {
        Address end = block.getEnd();
        try {
            Address max = start.add(MAX_FUNCTION_SPAN_BYTES - 1L);
            if (max.compareTo(end) < 0) {
                end = max;
            }
        }
        catch (Exception ignored) {
        }
        return end;
    }

    // ------------------------------------------------------------------
    // Decompiler passes
    // ------------------------------------------------------------------

    private void runDecompilerParameterIdentification() {
        AddressSet entries = new AddressSet();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);

        while (functions.hasNext() && !monitor.isCancelled()) {
            Function function = functions.next();
            if (function.isExternal() || function.isThunk()) {
                continue;
            }
            entries.add(function.getEntryPoint(), function.getEntryPoint());
            parameterIdFunctions++;
        }

        if (entries.isEmpty()) {
            return;
        }

        monitor.setMessage("Running decompiler parameter identification...");
        DecompilerParameterIdCmd command = new DecompilerParameterIdCmd(
            "PLC Decompiler Parameter Identification",
            entries,
            SourceType.ANALYSIS,
            false,
            false,
            DECOMPILER_TIMEOUT_SECONDS);

        if (!command.applyTo(currentProgram, monitor)) {
            println("Decompiler Parameter ID reported: " + safe(command.getStatusMsg()));
        }
    }

    private void validateAllFunctionsWithDecompiler() {
        DecompInterface decompiler = new DecompInterface();

        try {
            DecompileOptions options = new DecompileOptions();
            try {
                options.grabFromProgram(currentProgram);
            }
            catch (Exception ignored) {
            }
            decompiler.setOptions(options);

            if (!decompiler.openProgram(currentProgram)) {
                println("Decompiler could not open the current program.");
                return;
            }

            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                if (function.isExternal()) {
                    continue;
                }

                monitor.setMessage("Decompiler validation: " + function.getName());
                try {
                    DecompileResults results = decompiler.decompileFunction(
                        function, DECOMPILER_TIMEOUT_SECONDS, monitor);

                    if (results != null && results.decompileCompleted() &&
                        results.getDecompiledFunction() != null) {
                        decompileSuccesses++;
                    }
                    else {
                        decompileFailures++;
                        addBookmark(function.getEntryPoint(),
                            BOOKMARK_PREFIX + "Decompiler Failure",
                            results == null ? "No decompiler result" : safe(results.getErrorMessage()));
                    }
                }
                catch (Exception e) {
                    decompileFailures++;
                    addBookmark(function.getEntryPoint(),
                        BOOKMARK_PREFIX + "Decompiler Failure",
                        "Decompiler exception: " + safe(e.getMessage()));
                }
            }
        }
        finally {
            try {
                decompiler.dispose();
            }
            catch (Exception ignored) {
            }
        }
    }

    // ------------------------------------------------------------------
    // PLC-oriented navigation
    // ------------------------------------------------------------------

    private void bookmarkLikelyPlcFunctions() {
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function function = functions.next();
            if (looksLikePlcName(function.getName())) {
                addBookmark(function.getEntryPoint(),
                    BOOKMARK_PREFIX + "Likely PLC Function",
                    "PLC-related function name: " + function.getName());
            }
        }
    }

    private boolean looksLikePlcName(String name) {
        if (name == null) {
            return false;
        }
        String upper = name.toUpperCase(Locale.ROOT);
        return
            upper.equals("PLC_PRG") || upper.contains("PLC_PRG") ||
            upper.contains("PROGRAM0_BODY") || upper.startsWith("__PROGRAM0__") ||
            upper.startsWith("DT_PR_") || upper.startsWith("DT_FN_") ||
            upper.startsWith("DT_FB_") || upper.contains("MAINTASK") ||
            upper.startsWith("TASK") || upper.contains("CODESYS") ||
            upper.contains("OPENPLC") || upper.contains("IEC_") ||
            upper.contains("REAL32__") || upper.contains("REAL64__");
    }

    private Address chooseNavigationDestination() {
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (looksLikePlcName(function.getName())) {
                return function.getEntryPoint();
            }
        }

        if (!newlyCreatedEntries.isEmpty()) {
            return newlyCreatedEntries.get(0);
        }

        FunctionIterator all = currentProgram.getFunctionManager().getFunctions(true);
        return all.hasNext() ? all.next().getEntryPoint() : null;
    }

    // ------------------------------------------------------------------
    // Bookmarks and summary
    // ------------------------------------------------------------------

    private void clearOldRecoveryBookmarks() {
        BookmarkManager manager = currentProgram.getBookmarkManager();
        List<Bookmark> remove = new ArrayList<>();
        Iterator<Bookmark> iterator = manager.getBookmarksIterator(BOOKMARK_TYPE);

        while (iterator.hasNext()) {
            Bookmark bookmark = iterator.next();
            if (bookmark.getCategory() != null &&
                bookmark.getCategory().startsWith(BOOKMARK_PREFIX)) {
                remove.add(bookmark);
            }
        }

        for (Bookmark bookmark : remove) {
            manager.removeBookmark(bookmark);
        }
    }

    private void addBookmark(Address address, String category, String comment) {
        try {
            currentProgram.getBookmarkManager().setBookmark(
                address, BOOKMARK_TYPE, category, comment);
        }
        catch (Exception e) {
            println("Could not create bookmark at " + addressText(address) + ": " + e.getMessage());
        }
    }

    private void showSummary() {
        int totalFunctions = countFunctions();
        String message =
            "PLC recovery finished.\n\n" +
            "Processor: " + processorName + "\n" +
            "Raw-like import: " + rawLike + "\n" +
            "Functions created: " + createdFunctions + "\n" +
            "Function-creation failures: " + failedFunctionCreations + "\n" +
            "Total functions now present: " + totalFunctions + "\n" +
            "Functions passed to Parameter ID: " + parameterIdFunctions + "\n" +
            "Decompiler successes: " + decompileSuccesses + "\n" +
            "Decompiler failures: " + decompileFailures + "\n\n" +
            "Open Window -> Bookmarks and filter for 'PLC Recovery/' to review results.";

        println("");
        println(message.replace("\n", System.lineSeparator()));
        JOptionPane.showMessageDialog(null, message,
            "PLC Recovery Complete", JOptionPane.INFORMATION_MESSAGE);
    }

    private int countFunctions() {
        int count = 0;
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            iterator.next();
            count++;
        }
        return count;
    }

    // ------------------------------------------------------------------
    // Candidate and memory helpers
    // ------------------------------------------------------------------

    private void addCandidate(Address address, int priority, String reason) {
        if (address == null || candidates.size() >= MAX_CANDIDATES_PER_PASS) {
            return;
        }

        Address normalized = normalizeCodeAddress(address);
        if (!isCandidateAddress(normalized)) {
            return;
        }

        String key = addressKey(normalized);
        Candidate candidate = candidates.get(key);
        if (candidate == null) {
            candidate = new Candidate(normalized, priority);
            candidates.put(key, candidate);
        }
        else {
            candidate.priority = Math.max(candidate.priority, priority);
        }
        candidate.reasons.add(reason);
    }

    private boolean isCandidateAddress(Address address) {
        if (address == null || !address.isMemoryAddress() ||
            !currentProgram.getMemory().contains(address)) {
            return false;
        }
        MemoryBlock block = currentProgram.getMemory().getBlock(address);
        return block != null && block.isInitialized() && shouldInspectBlock(block);
    }

    private boolean shouldInspectBlock(MemoryBlock block) {
        if (block == null || !block.isInitialized()) {
            return false;
        }
        String name = block.getName() == null ? "" :
            block.getName().toLowerCase(Locale.ROOT);
        if (name.equals("external") ||
            (name.contains("overlay") && name.contains("external"))) {
            return false;
        }
        return rawLike || block.isExecute();
    }

    private boolean isUndefinedCandidateLocation(Address address) {
        Listing listing = currentProgram.getListing();
        return listing.getInstructionContaining(address) == null &&
               listing.getDefinedDataContaining(address) == null &&
               getFunctionContaining(address) == null;
    }

    private boolean looksLikePadding(Address address) {
        int length = Math.max(4, instructionAlignment);
        byte[] bytes = new byte[length];
        try {
            int read = currentProgram.getMemory().getBytes(address, bytes);
            if (read <= 0) {
                return true;
            }
            boolean allZero = true;
            boolean allFF = true;
            for (int i = 0; i < read; i++) {
                int value = bytes[i] & 0xff;
                if (value != 0x00) {
                    allZero = false;
                }
                if (value != 0xff) {
                    allFF = false;
                }
            }
            return allZero || allFF;
        }
        catch (Exception e) {
            return true;
        }
    }

    private boolean shouldRunFixedWidthGapScan() {
        if (!rawLike || processorName.contains("x86") ||
            processorName.contains("jvm") || processorName.contains("dalvik") ||
            instructionAlignment <= 1) {
            return false;
        }

        long initializedBytes = 0;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (shouldInspectBlock(block)) {
                initializedBytes += block.getSize();
                if (initializedBytes > RAW_FIXED_WIDTH_SCAN_LIMIT_BYTES) {
                    return false;
                }
            }
        }
        return initializedBytes > 0;
    }

    private int prologueScanAlignment() {
        return processorName.contains("x86") ? 1 : instructionAlignment;
    }

    private Address normalizeCodeAddress(Address address) {
        if (address == null) {
            return null;
        }
        if (processorName.contains("arm") && !processorName.contains("aarch64") &&
            (address.getOffset() & 1L) != 0) {
            try {
                return address.subtract(1);
            }
            catch (Exception ignored) {
            }
        }
        return address;
    }

    private Address alignUp(Address address, int alignment) {
        if (address == null || alignment <= 1) {
            return address;
        }
        long remainder = Math.floorMod(address.getOffset(), (long) alignment);
        return remainder == 0 ? address : safeAdd(address, alignment - remainder);
    }

    private Address safeAdd(Address address, long amount) {
        try {
            return address.add(amount);
        }
        catch (Exception e) {
            return null;
        }
    }

    private int readUnsignedShort(Address address, boolean bigEndian) throws Exception {
        byte[] bytes = new byte[2];
        if (currentProgram.getMemory().getBytes(address, bytes) != 2) {
            throw new Exception("Insufficient bytes");
        }
        int first = bytes[0] & 0xff;
        int second = bytes[1] & 0xff;
        return bigEndian ? (first << 8) | second : first | (second << 8);
    }

    private String addressKey(Address address) {
        return address == null ? "" : address.toString();
    }

    private String addressText(Address address) {
        return address == null ? "" : "0x" + address.toString().toUpperCase(Locale.ROOT);
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }

    private String join(Iterable<String> values, String delimiter) {
        StringBuilder output = new StringBuilder();
        boolean first = true;
        for (String value : values) {
            if (!first) {
                output.append(delimiter);
            }
            output.append(value);
            first = false;
        }
        return output.toString();
    }

    private static class Candidate {
        final Address address;
        int priority;
        final Set<String> reasons = new LinkedHashSet<>();

        Candidate(Address address, int priority) {
            this.address = address;
            this.priority = priority;
        }
    }
}
