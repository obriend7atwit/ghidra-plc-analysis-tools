// AnalyzePLCProgramPlus.java
// Conservative cross-toolchain PLC analysis assistant for imported PLC binaries.
// Never modifies executable bytes; optional changes affect only the Ghidra project.
// @category PLC Analysis
// @menupath Tools.PLC Analysis.Analyze PLC Program Plus

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.stream.Stream;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.regex.*;

public class AnalyzePLCProgramPlusV2 extends GhidraScript {

    private static final String VERSION = "2.2";
    private static final String SETTINGS_FILE = ".ghidra_plc_program_plus.properties";
    private static final String MANAGED_PREFIX = "[PLC-AUTO]";
    private static final String BOOKMARK_TYPE = "Analysis";
    private static final int CHUNK = 1024 * 1024;
    private static final int PSEUDO_ASSEMBLY_MAX_INSTRUCTIONS = 512;
    private static final int PSEUDO_ASSEMBLY_MAX_BYTES = 0x10000;
    private static final int UNDEFINED_PREVIEW_BYTES = 64;

    private Settings settings;
    private SourceInfo source = new SourceInfo();
    private Detection detection;
    private MetadataMatch metadataMatch = new MetadataMatch();
    private final List<String> warnings = new ArrayList<>();
    private final List<String> changes = new ArrayList<>();
    private final List<String> truncations = new ArrayList<>();

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("No program is open.");
            return;
        }

        Settings remembered = loadSettings();
        settings = showDialog(remembered);
        if (settings == null) {
            println("PLC analysis cancelled.");
            return;
        }

        saveSettings(settings);

        File base = resolveOutputDirectory(settings);
        if (base == null) {
            printerr("No output directory selected.");
            return;
        }

        // First-pass detection uses platform markers only.
        monitor.setMessage("Scanning PLC platform markers...");
        List<MarkerHit> markers = scanMarkers();
        detection = detect(markers);
        applyOverride();

        // Automatically find paired source and metadata where possible.
        File repositoryRoot = resolveRepositoryRoot(settings);
        if (settings.autoPairSource) {
            File paired = findBestPairedSource(repositoryRoot, detection.toolchain);
            if (paired != null) {
                source = parseSource(paired);
                println("Paired source: " + paired.getAbsolutePath());
            }
            else {
                warnings.add("No paired Structured Text source was found automatically.");
            }
        }

        metadataMatch = findMetadataMatch(repositoryRoot, detection.toolchain);

        // Re-scan with source POU/call names included, then re-evaluate detection.
        if (source.file != null) {
            monitor.setMessage("Scanning source-specific PLC markers...");
            markers = scanMarkers();
            detection = detect(markers);
            applyOverride();
        }

        List<CodesysCandidate> candidates = new ArrayList<>();
        if (detection.toolchain == Toolchain.CODESYS || settings.forceCodesysScan) {
            monitor.setMessage("Scoring CODESYS ARM function candidates...");
            candidates = scanCodesysCandidates();
        }

        Preflight preflight = runPreflight(candidates);
        boolean automationAllowed = preflight.automationAllowed;

        if (settings.applyChanges && !automationAllowed) {
            warnings.add(
                "Automatic project changes were disabled because the import preflight " +
                "did not meet the required confidence. Reports were still generated."
            );
        }

        if (settings.applyChanges && automationAllowed) {
            if (settings.labelMetadata) labelMetadata(markers);
            if (settings.recoverCodesys) recoverCodesys(candidates);
            if (settings.runAnalysis && !changes.isEmpty()) {
                analyzeChanges(currentProgram);
            }
        }

        monitor.setMessage("Analyzing functions and PLC data access...");
        AnalysisModel model = analyzeProgram();

        monitor.setMessage("Matching source constructs to recovered functions...");
        List<SourceMatch> sourceMatches = buildSourceMatches(model);
        applySourceMatchesToModel(model, sourceMatches);

        monitor.setMessage("Finding literal pools, variables, and duplicate functions...");
        List<LiteralRecord> literals = findLiteralPoolCandidates(model);
        List<VariableRecord> variables = buildVariableMatrix(model);
        List<FingerprintGroup> fingerprintGroups = buildFingerprintGroups(model);

        if (settings.applyChanges && automationAllowed) {
            applyHighConfidenceAnnotations(model, sourceMatches, literals, candidates);
        }

        String stamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        File out = uniqueDir(
            base,
            safeFile(currentProgram.getName()) + "_plc_plus_" + stamp
        );

        if (!out.mkdirs()) {
            printerr("Could not create output directory: " + out);
            return;
        }

        if (settings.exportDetails) {
            exportCoreDetails(out, model, sourceMatches);
        }

        writeReports(
            out,
            markers,
            candidates,
            model,
            preflight,
            sourceMatches,
            literals,
            variables,
            fingerprintGroups
        );

        println("");
        println("PLC Program Plus analysis complete.");
        println("Detected toolchain: " + detection.toolchain.label);
        println("Preflight: " + preflight.overallStatus);
        println("Core/source functions: " + model.core.size());
        println("Output: " + out.getAbsolutePath());
    }

    // ------------------------------------------------------------------
    // Dialog
    // ------------------------------------------------------------------

    private Settings showDialog(Settings remembered) {
        while (true) {
            final JComboBox<String> profile = new JComboBox<>(new String[] {
                "Automatic Safe", "Report Only", "Deep Report", "Custom"
            });
            final JComboBox<String> override = new JComboBox<>(new String[] {
                "Auto-detect", "CODESYS v3", "GEB", "OpenPLC v2",
                "OpenPLC v3", "OpenPLC family", "Unknown"
            });

            final JCheckBox apply =
                new JCheckBox("Apply only high-confidence Ghidra annotations", true);
            final JCheckBox recover =
                new JCheckBox("Recover high-confidence CODESYS ARM functions", true);
            final JCheckBox labels =
                new JCheckBox("Label exact PLC metadata strings", true);
            final JCheckBox bookmarks =
                new JCheckBox("Create PLC analysis bookmarks", true);
            final JCheckBox runAnalysis =
                new JCheckBox("Run incremental analysis after function recovery", true);
            final JCheckBox autoSource =
                new JCheckBox("Automatically pair Structured Text and metadata", true);
            final JCheckBox details =
                new JCheckBox("Export detailed files for likely control functions", true);
            final JCheckBox normalized =
                new JCheckBox("Export normalized instructions", true);
            final JCheckBox flows =
                new JCheckBox("Export control-flow edges", true);

            final JTextField confidence =
                new JTextField(String.valueOf(remembered.minConfidence), 8);
            final JTextField repoRoot =
                new JTextField(safe(remembered.repositoryRoot), 34);
            final JTextField outputDir =
                new JTextField(safe(remembered.outputDirectory), 34);

            final JTextField maxCandidates =
                new JTextField(String.valueOf(remembered.maxCandidates), 8);
            final JTextField maxSpan =
                new JTextField(String.valueOf(remembered.maxSpan), 8);
            final JTextField depth =
                new JTextField(String.valueOf(remembered.depth), 8);
            final JTextField maxInstructions =
                new JTextField(String.valueOf(remembered.maxInstructions), 8);

            profile.setSelectedItem(
                remembered.profile == null ? "Automatic Safe" : remembered.profile
            );
            override.setSelectedItem(
                remembered.override == null ? "Auto-detect" : remembered.override
            );

            apply.setSelected(remembered.applyChanges);
            recover.setSelected(remembered.recoverCodesys);
            labels.setSelected(remembered.labelMetadata);
            bookmarks.setSelected(remembered.createBookmarks);
            runAnalysis.setSelected(remembered.runAnalysis);
            autoSource.setSelected(remembered.autoPairSource);
            details.setSelected(remembered.exportDetails);
            normalized.setSelected(remembered.exportNormalized);
            flows.setSelected(remembered.exportFlows);

            profile.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent event) {
                    String selected = String.valueOf(profile.getSelectedItem());

                    if ("Custom".equals(selected)) return;

                    if ("Report Only".equals(selected)) {
                        apply.setSelected(false);
                        recover.setSelected(false);
                        labels.setSelected(false);
                        bookmarks.setSelected(false);
                        runAnalysis.setSelected(false);
                        confidence.setText("90");
                    }
                    else if ("Deep Report".equals(selected)) {
                        apply.setSelected(false);
                        recover.setSelected(false);
                        labels.setSelected(false);
                        bookmarks.setSelected(false);
                        runAnalysis.setSelected(false);
                        confidence.setText("85");
                        maxCandidates.setText("0");
                        maxSpan.setText("131072");
                        depth.setText("8");
                        maxInstructions.setText("15000");
                    }
                    else {
                        apply.setSelected(true);
                        recover.setSelected(true);
                        labels.setSelected(true);
                        bookmarks.setSelected(true);
                        runAnalysis.setSelected(true);
                        confidence.setText("90");
                        maxCandidates.setText("3000");
                        maxSpan.setText("65536");
                        depth.setText("5");
                        maxInstructions.setText("7000");
                    }
                }
            });

            JPanel panel = new JPanel(new GridBagLayout());
            GridBagConstraints g = new GridBagConstraints();
            g.insets = new Insets(3, 5, 3, 5);
            g.anchor = GridBagConstraints.WEST;
            g.fill = GridBagConstraints.HORIZONTAL;
            int row = 0;

            full(
                panel,
                g,
                row++,
                "<html><b>PLC Program Plus</b><br>" +
                "Automatic Safe is designed for minimal input and confidence-gated changes. " +
                "Executable bytes are never modified.</html>"
            );

            field(panel, g, row++, "Profile:", profile);
            field(panel, g, row++, "Toolchain override:", override);
            field(panel, g, row++, "Minimum confidence (0–100):", confidence);
            field(panel, g, row++, "PLC-BEAD/repository root (optional):", repoRoot);
            field(panel, g, row++, "Output directory (blank = ask):", outputDir);

            fullComp(panel, g, row++, apply);
            fullComp(panel, g, row++, recover);
            fullComp(panel, g, row++, labels);
            fullComp(panel, g, row++, bookmarks);
            fullComp(panel, g, row++, runAnalysis);
            fullComp(panel, g, row++, autoSource);
            fullComp(panel, g, row++, details);
            fullComp(panel, g, row++, normalized);
            fullComp(panel, g, row++, flows);

            field(panel, g, row++, "Max CODESYS candidates (0 = all):", maxCandidates);
            field(panel, g, row++, "Maximum candidate span bytes:", maxSpan);
            field(panel, g, row++, "Core call traversal depth:", depth);
            field(panel, g, row++, "Max detailed instructions/function:", maxInstructions);

            full(
                panel,
                g,
                row++,
                "<html>Settings are remembered. The script never automatically renames " +
                "functions or defines uncertain data.</html>"
            );

            int answer = JOptionPane.showConfirmDialog(
                null,
                panel,
                "Analyze PLC Program Plus",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
            );

            if (answer != JOptionPane.OK_OPTION) return null;

            try {
                Settings s = new Settings();
                s.profile = String.valueOf(profile.getSelectedItem());
                s.override = String.valueOf(override.getSelectedItem());
                s.applyChanges = apply.isSelected();
                s.recoverCodesys = recover.isSelected();
                s.forceCodesysScan = false;
                s.labelMetadata = labels.isSelected();
                s.createBookmarks = bookmarks.isSelected();
                s.annotateCore = apply.isSelected();
                s.annotateIndirect = apply.isSelected();
                s.runAnalysis = runAnalysis.isSelected();
                s.autoPairSource = autoSource.isSelected();
                s.exportDetails = details.isSelected();
                s.exportNormalized = normalized.isSelected();
                s.exportFlows = flows.isSelected();

                s.minConfidence =
                    boundedInt(confidence.getText(), "Minimum confidence", 0, 100);
                s.repositoryRoot = repoRoot.getText().trim();
                s.outputDirectory = outputDir.getText().trim();
                s.maxCandidates =
                    nonNegative(maxCandidates.getText(), "Max CODESYS candidates");
                s.maxSpan =
                    positive(maxSpan.getText(), "Maximum candidate span");
                s.depth =
                    nonNegative(depth.getText(), "Core traversal depth");
                s.maxInstructions =
                    positive(maxInstructions.getText(), "Max detailed instructions");

                // Retained compatibility limits from the original script.
                s.maxFunctions = 0;
                s.maxMarkerHits = 250;

                if (!s.applyChanges) {
                    s.recoverCodesys = false;
                    s.labelMetadata = false;
                    s.annotateCore = false;
                    s.annotateIndirect = false;
                    s.createBookmarks = false;
                    s.runAnalysis = false;
                }

                return s;
            }
            catch (IllegalArgumentException e) {
                JOptionPane.showMessageDialog(
                    null,
                    e.getMessage(),
                    "Invalid setting",
                    JOptionPane.ERROR_MESSAGE
                );
            }
        }
    }

    private int boundedInt(String text, String name, int minimum, int maximum) {
        int value = nonNegative(text, name);
        if (value < minimum || value > maximum) {
            throw new IllegalArgumentException(
                name + " must be between " + minimum + " and " + maximum + "."
            );
        }
        return value;
    }

    private Settings defaultSettings() {
        Settings s = new Settings();
        s.profile = "Automatic Safe";
        s.override = "Auto-detect";
        s.applyChanges = true;
        s.recoverCodesys = true;
        s.forceCodesysScan = false;
        s.labelMetadata = true;
        s.createBookmarks = true;
        s.annotateCore = true;
        s.annotateIndirect = true;
        s.runAnalysis = true;
        s.autoPairSource = true;
        s.exportDetails = true;
        s.exportNormalized = true;
        s.exportFlows = true;
        s.minConfidence = 90;
        s.maxCandidates = 3000;
        s.maxSpan = 65536;
        s.depth = 5;
        s.maxFunctions = 0;
        s.maxInstructions = 7000;
        s.maxMarkerHits = 250;
        s.repositoryRoot = "";
        s.outputDirectory = "";
        return s;
    }

    private File settingsFile() {
        String home = System.getProperty("user.home");
        if (home == null || home.trim().isEmpty()) home = ".";
        return new File(home, SETTINGS_FILE);
    }

    private Settings loadSettings() {
        Settings s = defaultSettings();
        File file = settingsFile();
        if (!file.isFile()) return s;

        Properties p = new Properties();
        try (FileInputStream input = new FileInputStream(file)) {
            p.load(input);
            s.profile = p.getProperty("profile", s.profile);
            s.override = p.getProperty("override", s.override);
            s.repositoryRoot = p.getProperty("repositoryRoot", s.repositoryRoot);
            s.outputDirectory = p.getProperty("outputDirectory", s.outputDirectory);
            s.minConfidence = propertyInt(p, "minConfidence", s.minConfidence);
            s.maxCandidates = propertyInt(p, "maxCandidates", s.maxCandidates);
            s.maxSpan = propertyInt(p, "maxSpan", s.maxSpan);
            s.depth = propertyInt(p, "depth", s.depth);
            s.maxInstructions = propertyInt(p, "maxInstructions", s.maxInstructions);
            s.applyChanges = propertyBool(p, "applyChanges", s.applyChanges);
            s.recoverCodesys = propertyBool(p, "recoverCodesys", s.recoverCodesys);
            s.labelMetadata = propertyBool(p, "labelMetadata", s.labelMetadata);
            s.createBookmarks = propertyBool(p, "createBookmarks", s.createBookmarks);
            s.runAnalysis = propertyBool(p, "runAnalysis", s.runAnalysis);
            s.autoPairSource = propertyBool(p, "autoPairSource", s.autoPairSource);
            s.exportDetails = propertyBool(p, "exportDetails", s.exportDetails);
            s.exportNormalized = propertyBool(p, "exportNormalized", s.exportNormalized);
            s.exportFlows = propertyBool(p, "exportFlows", s.exportFlows);
        }
        catch (Exception e) {
            warnings.add("Could not load remembered settings: " + e);
        }

        return s;
    }

    private void saveSettings(Settings s) {
        Properties p = new Properties();
        p.setProperty("profile", safe(s.profile));
        p.setProperty("override", safe(s.override));
        p.setProperty("repositoryRoot", safe(s.repositoryRoot));
        p.setProperty("outputDirectory", safe(s.outputDirectory));
        p.setProperty("minConfidence", String.valueOf(s.minConfidence));
        p.setProperty("maxCandidates", String.valueOf(s.maxCandidates));
        p.setProperty("maxSpan", String.valueOf(s.maxSpan));
        p.setProperty("depth", String.valueOf(s.depth));
        p.setProperty("maxInstructions", String.valueOf(s.maxInstructions));
        p.setProperty("applyChanges", String.valueOf(s.applyChanges));
        p.setProperty("recoverCodesys", String.valueOf(s.recoverCodesys));
        p.setProperty("labelMetadata", String.valueOf(s.labelMetadata));
        p.setProperty("createBookmarks", String.valueOf(s.createBookmarks));
        p.setProperty("runAnalysis", String.valueOf(s.runAnalysis));
        p.setProperty("autoPairSource", String.valueOf(s.autoPairSource));
        p.setProperty("exportDetails", String.valueOf(s.exportDetails));
        p.setProperty("exportNormalized", String.valueOf(s.exportNormalized));
        p.setProperty("exportFlows", String.valueOf(s.exportFlows));

        try (FileOutputStream output = new FileOutputStream(settingsFile())) {
            p.store(output, "AnalyzePLCProgramPlus settings");
        }
        catch (Exception e) {
            warnings.add("Could not save settings: " + e);
        }
    }

    private int propertyInt(Properties p, String key, int fallback) {
        try {
            return Integer.parseInt(p.getProperty(key, String.valueOf(fallback)).trim());
        }
        catch (Exception e) {
            return fallback;
        }
    }

    private boolean propertyBool(Properties p, String key, boolean fallback) {
        String value = p.getProperty(key);
        return value == null ? fallback : Boolean.parseBoolean(value);
    }

    private File resolveOutputDirectory(Settings s) throws Exception {
        if (s.outputDirectory != null && !s.outputDirectory.trim().isEmpty()) {
            File configured = new File(s.outputDirectory.trim());
            if ((configured.isDirectory() || configured.mkdirs()) && configured.canWrite()) {
                return configured;
            }
            warnings.add("Remembered output directory is unavailable: " + configured);
        }

        File chosen = askDirectory("Choose PLC analysis output directory", "Export");
        if (chosen != null) {
            s.outputDirectory = chosen.getAbsolutePath();
            saveSettings(s);
        }
        return chosen;
    }

    private File resolveRepositoryRoot(Settings s) {
        if (s.repositoryRoot != null && !s.repositoryRoot.trim().isEmpty()) {
            File configured = new File(s.repositoryRoot.trim());
            if (configured.isDirectory()) return configured;
        }

        File executable = new File(safe(currentProgram.getExecutablePath()));
        File cursor = executable.isFile() ? executable.getParentFile() : executable;
        for (int level = 0; cursor != null && level < 8; level++, cursor = cursor.getParentFile()) {
            if (new File(cursor, "PLC-BEAD").isDirectory()) {
                s.repositoryRoot = cursor.getAbsolutePath();
                saveSettings(s);
                return cursor;
            }
            if ("PLC-BEAD".equalsIgnoreCase(cursor.getName())) {
                File parent = cursor.getParentFile();
                if (parent != null) {
                    s.repositoryRoot = parent.getAbsolutePath();
                    saveSettings(s);
                    return parent;
                }
            }
        }

        return null;
    }

    private void field(JPanel p, GridBagConstraints g, int row, String label, Component c) {
        g.gridx=0; g.gridy=row; g.gridwidth=1; g.weightx=0; p.add(new JLabel(label),g);
        g.gridx=1; g.weightx=1; p.add(c,g);
    }
    private void full(JPanel p, GridBagConstraints g, int row, String text) { fullComp(p,g,row,new JLabel(text)); }
    private void fullComp(JPanel p, GridBagConstraints g, int row, Component c) {
        g.gridx=0; g.gridy=row; g.gridwidth=2; g.weightx=1; p.add(c,g); g.gridwidth=1;
    }
    private int nonNegative(String t, String name) {
        try { int v=Integer.parseInt(t.trim()); if (v<0) throw new Exception(); return v; }
        catch (Exception e) { throw new IllegalArgumentException(name+" must be a whole number >= 0."); }
    }
    private int positive(String t, String name) {
        int v=nonNegative(t,name); if (v<1) throw new IllegalArgumentException(name+" must be >= 1."); return v;
    }

    // ------------------------------------------------------------------
    // Structured Text source
    // ------------------------------------------------------------------

    private SourceInfo parseSource(File file) {
        SourceInfo info = new SourceInfo();
        info.file = file;

        StringBuilder b = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = r.readLine()) != null) {
                b.append(line).append('\n');
            }
        }
        catch (Exception e) {
            warnings.add("Could not read source: " + e);
            return info;
        }

        info.text = b.toString();

        Pattern pouPattern = Pattern.compile(
            "(?im)^\\s*(PROGRAM|FUNCTION_BLOCK|FUNCTION|METHOD|ACTION)\\s+" +
            "([A-Za-z_][A-Za-z0-9_]*)"
        );

        Matcher pouMatcher = pouPattern.matcher(info.text);
        while (pouMatcher.find()) {
            String type = pouMatcher.group(1).toUpperCase(Locale.ROOT);
            String name = pouMatcher.group(2);
            Pou pou = new Pou(type, name);
            pou.body = extractPouBody(info.text, type, name, pouMatcher.start());
            pou.features.addAll(extractSourceFeatures(pou.body));
            info.pous.add(pou);
            info.names.add(name);
        }

        Set<String> ignored = new HashSet<>(Arrays.asList(
            "IF", "ELSIF", "WHILE", "FOR", "CASE", "PROGRAM",
            "FUNCTION", "FUNCTION_BLOCK", "VAR", "TASK", "RESOURCE"
        ));

        Matcher callMatcher = Pattern.compile(
            "\\b([A-Za-z_][A-Za-z0-9_]*)\\s*\\("
        ).matcher(info.text);

        while (callMatcher.find()) {
            String name = callMatcher.group(1);
            if (!ignored.contains(name.toUpperCase(Locale.ROOT))) {
                info.calls.add(name);
            }
        }

        Matcher taskMatcher = Pattern.compile(
            "(?im)^\\s*TASK\\s+([A-Za-z_][A-Za-z0-9_]*)\\s*" +
            "\\(([^)]*)\\)"
        ).matcher(info.text);

        while (taskMatcher.find()) {
            TaskInfo task = new TaskInfo();
            task.name = taskMatcher.group(1);
            task.parameters = taskMatcher.group(2).trim();
            task.interval = extractNamedParameter(task.parameters, "INTERVAL");
            task.priority = extractNamedParameter(task.parameters, "PRIORITY");
            info.tasks.add(task);
        }

        Matcher bindingMatcher = Pattern.compile(
            "(?im)^\\s*PROGRAM\\s+([A-Za-z_][A-Za-z0-9_]*)\\s+WITH\\s+" +
            "([A-Za-z_][A-Za-z0-9_]*)\\s*:\\s*([A-Za-z_][A-Za-z0-9_]*)"
        ).matcher(info.text);

        while (bindingMatcher.find()) {
            ProgramBinding binding = new ProgramBinding();
            binding.instance = bindingMatcher.group(1);
            binding.task = bindingMatcher.group(2);
            binding.programType = bindingMatcher.group(3);
            info.bindings.add(binding);
        }

        return info;
    }

    private String extractPouBody(
        String sourceText,
        String type,
        String name,
        int declarationStart
    ) {
        String endKeyword =
            "PROGRAM".equals(type) ? "END_PROGRAM" :
            "FUNCTION_BLOCK".equals(type) ? "END_FUNCTION_BLOCK" :
            "METHOD".equals(type) ? "END_METHOD" :
            "ACTION".equals(type) ? "END_ACTION" :
            "END_FUNCTION";

        String upper = sourceText.toUpperCase(Locale.ROOT);
        int end = upper.indexOf(endKeyword, declarationStart);
        if (end < 0) {
            end = Math.min(sourceText.length(), declarationStart + 12000);
        }
        else {
            end += endKeyword.length();
        }

        return sourceText.substring(declarationStart, end);
    }

    private Set<String> extractSourceFeatures(String body) {
        Set<String> features = new LinkedHashSet<>();
        String upper = body.toUpperCase(Locale.ROOT);

        String[] calls = {
            "SQRT", "LN", "LOG", "SIN", "COS", "TAN", "EXP", "ABS",
            "MIN", "MAX", "LIMIT", "SEL", "MUX", "TON", "TOF", "TP"
        };

        for (String call : calls) {
            if (Pattern.compile("\\b" + Pattern.quote(call) + "\\s*\\(")
                .matcher(upper).find()) {
                features.add("CALL_" + call);
            }
        }

        if (upper.contains("*")) features.add("MUL");
        if (upper.contains("/")) features.add("DIV");
        if (upper.contains("+")) features.add("ADD");
        if (upper.contains("-")) features.add("SUB");
        if (Pattern.compile("\\bIF\\b").matcher(upper).find()) features.add("BRANCH");
        if (Pattern.compile("\\bFOR\\b|\\bWHILE\\b|\\bREPEAT\\b")
            .matcher(upper).find()) features.add("LOOP");
        if (upper.contains("1.0")) features.add("CONST_1_0");
        if (upper.contains("0.0")) features.add("CONST_0_0");

        return features;
    }

    private String extractNamedParameter(String parameters, String name) {
        Matcher matcher = Pattern.compile(
            "(?i)\\b" + Pattern.quote(name) + "\\s*:=\\s*([^,]+)"
        ).matcher(parameters);

        return matcher.find() ? matcher.group(1).trim() : "";
    }

    private File findBestPairedSource(File repositoryRoot, Toolchain toolchain) {
        if (repositoryRoot == null || !repositoryRoot.isDirectory()) return null;

        final String programBase = stripExtension(currentProgram.getName());
        List<ScoredFile> candidates = new ArrayList<>();

        try (Stream<Path> paths = Files.walk(repositoryRoot.toPath(), 10)) {
            paths.filter(Files::isRegularFile).forEach(path -> {
                String fileName = path.getFileName().toString();
                String lower = fileName.toLowerCase(Locale.ROOT);

                if (!(lower.endsWith(".st") || lower.endsWith(".txt"))) return;
                if (!stripExtension(fileName).equalsIgnoreCase(programBase)) return;

                String normalized = path.toString().replace('\\', '/').toLowerCase(Locale.ROOT);
                int score = 100;

                if (normalized.contains("/source/plc_programs/")) score += 50;
                if (normalized.contains("/source/")) score += 15;

                if (toolchain == Toolchain.CODESYS && normalized.contains("codesys")) score += 25;
                if (toolchain == Toolchain.GEB && normalized.contains("/geb/")) score += 25;
                if (toolchain == Toolchain.OPENPLC2 && normalized.contains("openplcv2")) score += 25;
                if (toolchain == Toolchain.OPENPLC3 && normalized.contains("openplcv3")) score += 25;

                score -= Math.min(30, path.getNameCount());
                candidates.add(new ScoredFile(path.toFile(), score));
            });
        }
        catch (Exception e) {
            warnings.add("Could not search for paired source: " + e);
        }

        if (candidates.isEmpty()) return null;
        Collections.sort(candidates, (a, b) -> Integer.compare(b.score, a.score));
        return candidates.get(0).file;
    }

    private MetadataMatch findMetadataMatch(File repositoryRoot, Toolchain toolchain) {
        MetadataMatch result = new MetadataMatch();
        if (repositoryRoot == null || !repositoryRoot.isDirectory()) return result;

        final String programName = currentProgram.getName();
        final String programBase = stripExtension(programName);
        List<File> csvFiles = new ArrayList<>();

        try (Stream<Path> paths = Files.walk(repositoryRoot.toPath(), 8)) {
            paths.filter(Files::isRegularFile).forEach(path -> {
                String lower = path.getFileName().toString().toLowerCase(Locale.ROOT);
                if ((lower.endsWith(".csv") && lower.contains("metadata")) ||
                    lower.equals("codesys.csv") || lower.equals("geb.csv") ||
                    lower.equals("openplc_v2.csv") || lower.equals("openplc_v3.csv")) {
                    csvFiles.add(path.toFile());
                }
            });
        }
        catch (Exception e) {
            warnings.add("Could not search metadata files: " + e);
            return result;
        }

        for (File csvFile : csvFiles) {
            try (BufferedReader reader = new BufferedReader(new FileReader(csvFile))) {
                String headerLine = reader.readLine();
                if (headerLine == null) continue;

                List<String> headers = parseCsvLine(headerLine);
                String line;

                while ((line = reader.readLine()) != null) {
                    List<String> values = parseCsvLine(line);
                    if (values.isEmpty()) continue;

                    String first = values.get(0).trim();
                    if (!(first.equalsIgnoreCase(programName) ||
                        stripExtension(first).equalsIgnoreCase(programBase))) {
                        continue;
                    }

                    result.file = csvFile;
                    result.rowText = line;
                    for (int index = 0; index < Math.min(headers.size(), values.size()); index++) {
                        result.values.put(headers.get(index).trim(), values.get(index).trim());
                    }
                    return result;
                }
            }
            catch (Exception e) {
                warnings.add("Could not read metadata file " + csvFile + ": " + e);
            }
        }

        return result;
    }

    private List<String> parseCsvLine(String line) {
        List<String> values = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean quoted = false;

        for (int index = 0; index < line.length(); index++) {
            char ch = line.charAt(index);
            if (ch == '"') {
                if (quoted && index + 1 < line.length() && line.charAt(index + 1) == '"') {
                    current.append('"');
                    index++;
                }
                else {
                    quoted = !quoted;
                }
            }
            else if (ch == ',' && !quoted) {
                values.add(current.toString());
                current.setLength(0);
            }
            else {
                current.append(ch);
            }
        }

        values.add(current.toString());
        return values;
    }

    private String stripExtension(String name) {
        if (name == null) return "";
        int dot = name.lastIndexOf('.');
        return dot <= 0 ? name : name.substring(0, dot);
    }

    // ------------------------------------------------------------------
    // Marker scanning and detection
    // ------------------------------------------------------------------

    private List<MarkerHit> scanMarkers() {
        LinkedHashSet<String> names=new LinkedHashSet<>(Arrays.asList(
            "CODESYS","CoDeSys","PLC_PRG","MainTask","IoConfig_Globals","IMPLICIT_FUNCTION_POINTERS",
            "REAL32__LN","REAL32__SQRT","dt_PR_","dt_FN_","dt_FB_","PROGRAM0_body__","__PROGRAM0__",
            "config_run__","config_init__","glueVars","updateBuffersIn","updateBuffersOut","OpenPLC"));
        names.addAll(source.names);
        for (String n:source.calls) if (n.length()>=3) names.add(n);
        for (TaskInfo task:source.tasks) if (!task.name.isEmpty()) names.add(task.name);
        for (ProgramBinding binding:source.bindings) {
            if (!binding.instance.isEmpty()) names.add(binding.instance);
            if (!binding.programType.isEmpty()) names.add(binding.programType);
        }
        List<MarkerHit> all=new ArrayList<>();
        for (String n:names) {
            if (monitor.isCancelled()) break;
            all.addAll(findBytes(n,n.getBytes(StandardCharsets.US_ASCII),"ASCII"));
            all.addAll(findBytes(n,n.getBytes(StandardCharsets.UTF_16LE),"UTF-16LE"));
        }
        LinkedHashMap<String,MarkerHit> unique=new LinkedHashMap<>();
        for (MarkerHit h:all) unique.put(addr(h.address)+"|"+h.marker+"|"+h.encoding,h);
        List<MarkerHit> result=new ArrayList<>(unique.values());
        Collections.sort(result,(a,b)->a.address.compareTo(b.address));
        return result;
    }

    private List<MarkerHit> findBytes(String marker, byte[] pattern, String encoding) {
        List<MarkerHit> hits=new ArrayList<>(); Memory memory=currentProgram.getMemory();
        for (MemoryBlock block:memory.getBlocks()) {
            if (monitor.isCancelled() || !block.isInitialized()) continue;
            long off=0, size=block.getSize(); int overlap=Math.max(0,pattern.length-1);
            while (off<size && !monitor.isCancelled()) {
                if (settings.maxMarkerHits!=0 && hits.size()>=settings.maxMarkerHits) { truncations.add("Marker "+marker+" reached hit limit."); return hits; }
                int want=(int)Math.min(CHUNK+overlap,size-off); byte[] buf=new byte[want]; int read;
                try { read=memory.getBytes(block.getStart().add(off),buf,0,want); }
                catch (Exception e) { warnings.add("Could not scan block "+block.getName()+": "+e); break; }
                if (read<pattern.length) break;
                for (int i=0;i<=read-pattern.length;i++) {
                    boolean ok=true; for (int j=0;j<pattern.length;j++) if (buf[i+j]!=pattern[j]) { ok=false; break; }
                    if (ok) hits.add(new MarkerHit(marker,encoding,block.getStart().add(off+i),block.getName()));
                }
                if (read<want) break; off+=CHUNK;
            }
        }
        return hits;
    }

    private Detection detect(List<MarkerHit> hits) {
        Detection d=new Detection();
        String path=safe(currentProgram.getExecutablePath()).toLowerCase(Locale.ROOT);
        String name=safe(currentProgram.getName()).toLowerCase(Locale.ROOT);
        String format=safe(currentProgram.getExecutableFormat()).toLowerCase(Locale.ROOT);
        String language=currentProgram.getLanguageID().toString().toLowerCase(Locale.ROOT);

        if (name.endsWith(".app") || path.endsWith(".app")) d.add(Toolchain.CODESYS,8,".app filename");
        if (path.contains("codesys")) d.add(Toolchain.CODESYS,10,"path contains Codesys");
        if (path.contains("geb")) d.add(Toolchain.GEB,10,"path contains GEB");
        if (path.contains("openplcv2") || path.contains("openplc_v2") || path.contains("openplc-v2")) d.add(Toolchain.OPENPLC2,14,"path identifies OpenPLC v2");
        if (path.contains("openplcv3") || path.contains("openplc_v3") || path.contains("openplc-v3")) d.add(Toolchain.OPENPLC3,14,"path identifies OpenPLC v3");
        if (format.contains("elf")) { d.add(Toolchain.GEB,2,"ELF format"); d.add(Toolchain.OPENPLC,2,"ELF format"); }
        if (name.endsWith(".exe") || path.endsWith(".exe")) d.add(Toolchain.OPENPLC,3,".exe filename");
        if ((format.contains("raw") || format.contains("binary")) && language.startsWith("arm:le:32")) d.add(Toolchain.CODESYS,4,"raw ARM32 little-endian import");

        Map<String,Integer> counts=new HashMap<>();
        for (MarkerHit h:hits) counts.put(h.marker,counts.getOrDefault(h.marker,0)+1);
        markerScore(d,counts,"CODESYS",Toolchain.CODESYS,14);
        markerScore(d,counts,"CoDeSys",Toolchain.CODESYS,14);
        markerScore(d,counts,"PLC_PRG",Toolchain.CODESYS,8);
        markerScore(d,counts,"MainTask",Toolchain.CODESYS,4);
        markerScore(d,counts,"IMPLICIT_FUNCTION_POINTERS",Toolchain.CODESYS,6);
        markerScore(d,counts,"dt_PR_",Toolchain.GEB,14);
        markerScore(d,counts,"dt_FN_",Toolchain.GEB,8);
        markerScore(d,counts,"dt_FB_",Toolchain.GEB,8);
        markerScore(d,counts,"PROGRAM0_body__",Toolchain.OPENPLC,16);
        markerScore(d,counts,"__PROGRAM0__",Toolchain.OPENPLC,10);
        markerScore(d,counts,"config_run__",Toolchain.OPENPLC,5);
        markerScore(d,counts,"OpenPLC",Toolchain.OPENPLC,12);

        SymbolIterator symbols=currentProgram.getSymbolTable().getAllSymbols(true);
        int checked=0;
        while (symbols.hasNext() && !monitor.isCancelled() && checked<200000) {
            Symbol s=symbols.next(); checked++; String n=s.getName(); if (n==null) continue;
            if (n.startsWith("dt_PR_")) d.add(Toolchain.GEB,10,"symbol "+n);
            else if (n.startsWith("dt_FN_")) d.add(Toolchain.GEB,6,"symbol "+n);
            else if (n.startsWith("dt_FB_")) d.add(Toolchain.GEB,6,"symbol "+n);
            if (n.equalsIgnoreCase("PROGRAM0_body__")) d.add(Toolchain.OPENPLC,16,"symbol PROGRAM0_body__");
            if (n.toUpperCase(Locale.ROOT).startsWith("__PROGRAM0__")) d.add(Toolchain.OPENPLC,8,"symbol "+n);
            if (n.equalsIgnoreCase("PLC_PRG")) d.add(Toolchain.CODESYS,10,"symbol PLC_PRG");
        }
        d.choose();
        if (d.toolchain==Toolchain.OPENPLC) {
            if (d.score(Toolchain.OPENPLC2)>d.score(Toolchain.OPENPLC3)) d.toolchain=Toolchain.OPENPLC2;
            else if (d.score(Toolchain.OPENPLC3)>d.score(Toolchain.OPENPLC2)) d.toolchain=Toolchain.OPENPLC3;
        }
        return d;
    }

    private void markerScore(Detection d, Map<String,Integer> counts, String marker, Toolchain t, int points) {
        Integer count=counts.get(marker); if (count!=null && count>0) d.add(t,points,"marker '"+marker+"' ("+count+" hit(s))");
    }

    private void applyOverride() {
        String o=settings.override;
        if (o.equals("Auto-detect")) return;
        if (o.equals("CODESYS v3")) detection.toolchain=Toolchain.CODESYS;
        else if (o.equals("GEB")) detection.toolchain=Toolchain.GEB;
        else if (o.equals("OpenPLC v2")) detection.toolchain=Toolchain.OPENPLC2;
        else if (o.equals("OpenPLC v3")) detection.toolchain=Toolchain.OPENPLC3;
        else if (o.equals("OpenPLC family")) detection.toolchain=Toolchain.OPENPLC;
        else detection.toolchain=Toolchain.UNKNOWN;
        detection.override=o;
    }

    // ------------------------------------------------------------------
    // CODESYS ARM function discovery
    // ------------------------------------------------------------------

    private List<CodesysCandidate> scanCodesysCandidates() {
        List<CodesysCandidate> result = new ArrayList<>();
        if (!isArm32LE()) {
            warnings.add("CODESYS prologue scan requires ARM32 little-endian language.");
            return result;
        }

        Set<String> seen = new HashSet<>();
        Memory memory = currentProgram.getMemory();

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || monitor.isCancelled()) continue;

            long off = 0;
            long size = block.getSize();

            while (off < size && !monitor.isCancelled()) {
                if (settings.maxCandidates != 0 &&
                    result.size() >= settings.maxCandidates) {
                    truncations.add("CODESYS candidate scan reached the configured limit.");
                    break;
                }

                int want = (int)Math.min(CHUNK + 8, size - off);
                byte[] buffer = new byte[want];
                int read;

                try {
                    read = memory.getBytes(block.getStart().add(off), buffer, 0, want);
                }
                catch (Exception e) {
                    warnings.add(
                        "Could not scan CODESYS candidates in " +
                        block.getName() + ": " + e
                    );
                    break;
                }

                if (read < 8) break;

                for (int index = 0; index <= read - 8; index++) {
                    Address address = block.getStart().add(off + index);
                    if ((address.getOffset() & 3L) != 0) continue;

                    int first = leInt(buffer, index);
                    int second = leInt(buffer, index + 4);
                    if (!codesysPrologue(first, second)) continue;

                    String key = addr(address);
                    if (!seen.add(key)) continue;

                    int frame = (second >>> 12) & 0xf;
                    Function at = getFunctionAt(address);
                    Function containing = getFunctionContaining(address);

                    CodesysCandidate candidate = new CodesysCandidate(
                        address,
                        block.getName(),
                        frame,
                        at != null,
                        containing != null && at == null
                    );

                    scoreCodesysCandidate(candidate, block);
                    result.add(candidate);

                    if (settings.maxCandidates != 0 &&
                        result.size() >= settings.maxCandidates) {
                        break;
                    }
                }

                if (read < want) break;
                off += CHUNK;
            }
        }

        Collections.sort(result, (a, b) -> a.address.compareTo(b.address));
        return result;
    }

    private void scoreCodesysCandidate(CodesysCandidate candidate, MemoryBlock block) {
        int score = 45;
        candidate.reasons.add("Exact CODESYS-style ARM stack-frame prologue");

        if ((candidate.address.getOffset() & 3L) == 0) {
            score += 5;
            candidate.reasons.add("Four-byte ARM alignment");
        }

        if (candidate.existing) {
            score += 15;
            candidate.reasons.add("Already recognized as a function");
        }

        if (candidate.inside) {
            score -= 45;
            candidate.reasons.add("Falls inside an existing function");
        }

        if (currentProgram.getListing().getDataContaining(candidate.address) != null) {
            score -= 50;
            candidate.reasons.add("Conflicts with defined data");
        }

        if (block.isExecute()) {
            score += 5;
            candidate.reasons.add("Located in executable memory");
        }
        else if (detection != null && detection.toolchain == Toolchain.CODESYS) {
            score += 3;
            candidate.reasons.add("Raw CODESYS imports may lack execute flags");
        }

        PseudoDisassembler pseudo = new PseudoDisassembler(currentProgram);
        int valid = 0;
        Address cursor = candidate.address;

        for (int index = 0; index < 12; index++) {
            try {
                PseudoInstruction instruction = pseudo.disassemble(cursor);
                if (instruction == null || instruction.getLength() <= 0) break;
                valid++;
                cursor = cursor.add(instruction.getLength());
            }
            catch (Exception e) {
                break;
            }
        }

        candidate.validInitialInstructions = valid;
        if (valid >= 10) {
            score += 15;
            candidate.reasons.add("At least ten valid initial ARM instructions");
        }
        else if (valid >= 6) {
            score += 8;
            candidate.reasons.add("At least six valid initial ARM instructions");
        }
        else {
            score -= 20;
            candidate.reasons.add("Weak instruction decoding after prologue");
        }

        ReturnEvidence returnEvidence = findArmReturnEvidence(candidate.address, block);
        candidate.returnAddress = returnEvidence.address;
        candidate.returnRestoresFrame = returnEvidence.restoresFrame;

        if (returnEvidence.address != null) {
            score += 20;
            candidate.reasons.add(
                "Recognizable ARM return at " + addr(returnEvidence.address)
            );

            if (returnEvidence.restoresFrame) {
                score += 8;
                candidate.reasons.add("Return restores the selected frame register");
            }
        }
        else {
            score -= 15;
            candidate.reasons.add("No clear ARM return within the configured span");
        }

        candidate.confidence = Math.max(0, Math.min(100, score));
    }

    private ReturnEvidence findArmReturnEvidence(Address start, MemoryBlock block) {
        ReturnEvidence evidence = new ReturnEvidence();
        long limit = Math.min(settings.maxSpan, block.getEnd().subtract(start) + 1);

        for (long offset = 8; offset + 4 <= limit; offset += 4) {
            Address address;
            int word;

            try {
                address = start.add(offset);
                word = currentProgram.getMemory().getInt(address, false);
            }
            catch (Exception e) {
                break;
            }

            boolean ldmReturn = (word & 0x0fff8000) == 0x08bd8000;
            boolean bxLr = (word & 0x0fffffff) == 0x012fff1e;
            boolean movPcLr = (word & 0x0fffffff) == 0x01a0f00e;

            if (ldmReturn || bxLr || movPcLr) {
                evidence.address = address;
                if (ldmReturn) {
                    int registerList = word & 0xffff;
                    evidence.restoresFrame =
                        (registerList & (1 << 10)) != 0 ||
                        (registerList & (1 << 11)) != 0 ||
                        (registerList & (1 << 12)) != 0;
                }
                return evidence;
            }
        }

        return evidence;
    }

    private int leInt(byte[] b, int i) {
        return (b[i] & 0xff) |
            ((b[i + 1] & 0xff) << 8) |
            ((b[i + 2] & 0xff) << 16) |
            ((b[i + 3] & 0xff) << 24);
    }

    private boolean codesysPrologue(int first, int second) {
        boolean push =
            (first & 0x0fff0000) == 0x092d0000 &&
            (first & 0x00004000) != 0;
        boolean mov =
            (second & 0x0fff0fff) == 0x01a0000d;
        int rd = (second >>> 12) & 0xf;

        return push && mov && (rd == 10 || rd == 11 || rd == 12);
    }

    private void recoverCodesys(List<CodesysCandidate> candidates) {
        if (!isArm32LE()) {
            warnings.add(
                "CODESYS recovery skipped: language is not ARM32 little-endian."
            );
            return;
        }

        Listing listing = currentProgram.getListing();
        Memory memory = currentProgram.getMemory();
        int created = 0;

        for (int index = 0;
            index < candidates.size() && !monitor.isCancelled();
            index++) {

            CodesysCandidate candidate = candidates.get(index);
            Address start = candidate.address;

            if (candidate.confidence < settings.minConfidence) {
                candidate.status = "below_confidence_threshold";
                continue;
            }

            if (getFunctionAt(start) != null) {
                candidate.status = "existing_function";
                continue;
            }

            Function containing = getFunctionContaining(start);
            if (containing != null) {
                candidate.status = "inside_existing_function:" + containing.getName();
                continue;
            }

            if (listing.getDataContaining(start) != null) {
                candidate.status = "defined_data_conflict";
                continue;
            }

            MemoryBlock block = memory.getBlock(start);
            if (block == null) {
                candidate.status = "no_memory_block";
                continue;
            }

            Address end = block.getEnd();

            try {
                Address max = start.add(settings.maxSpan - 1L);
                if (max.compareTo(end) < 0) end = max;
            }
            catch (Exception ignored) {
            }

            if (candidate.returnAddress != null &&
                candidate.returnAddress.compareTo(end) < 0) {
                try {
                    end = candidate.returnAddress.add(3);
                }
                catch (Exception ignored) {
                }
            }
            else if (index + 1 < candidates.size()) {
                Address next = candidates.get(index + 1).address;
                MemoryBlock nextBlock = memory.getBlock(next);

                if (nextBlock != null &&
                    nextBlock.equals(block) &&
                    next.compareTo(start) > 0) {
                    try {
                        Address before = next.subtract(1);
                        if (before.compareTo(end) < 0) end = before;
                    }
                    catch (Exception ignored) {
                    }
                }
            }

            DisassembleCommand command =
                new DisassembleCommand(start, new AddressSet(start, end), true);
            command.enableCodeAnalysis(false);

            boolean ok = command.applyTo(currentProgram, monitor);
            if (!ok && listing.getInstructionAt(start) == null) {
                candidate.status =
                    "disassembly_failed:" + safe(command.getStatusMsg());
                continue;
            }

            Function function = createFunction(start, null);
            if (function != null) {
                candidate.status = "created";
                created++;
                changes.add(
                    "Created CODESYS function at " + addr(start) +
                    " (confidence " + candidate.confidence + "%)"
                );

                if (settings.createBookmarks) {
                    addBookmark(
                        start,
                        "PLC-AUTO/RecoveredFunction",
                        "Recovered CODESYS function; confidence " +
                        candidate.confidence + "%. " +
                        join(candidate.reasons, "; ")
                    );
                }
            }
            else {
                candidate.status = "function_creation_failed";
            }
        }

        println("High-confidence CODESYS functions created: " + created);
    }

    private boolean isArm32LE() {
        String id =
            currentProgram.getLanguageID().toString().toLowerCase(Locale.ROOT);
        return id.startsWith("arm:") && id.contains(":le:32:");
    }

    private void labelMetadata(List<MarkerHit> hits) {
        SymbolTable table = currentProgram.getSymbolTable();

        for (MarkerHit hit : hits) {
            if (monitor.isCancelled()) break;

            Symbol primary = table.getPrimarySymbol(hit.address);
            if (primary != null && primary.getSource() == SourceType.USER_DEFINED) {
                continue;
            }

            String label =
                "PLC_AUTO_META_" +
                safeLabel(hit.marker) +
                "_" +
                addressSuffix(hit.address);

            try {
                if (primary == null ||
                    !primary.getName().startsWith("PLC_AUTO_META_")) {
                    table.createLabel(
                        hit.address,
                        label,
                        SourceType.ANALYSIS
                    );
                    changes.add(
                        "Labeled exact metadata string '" +
                        hit.marker + "' at " + addr(hit.address)
                    );
                }

                if (settings.createBookmarks) {
                    addBookmark(
                        hit.address,
                        "PLC-AUTO/Metadata",
                        "Exact " + hit.encoding +
                        " metadata string: " + hit.marker
                    );
                }
            }
            catch (Exception ignored) {
            }
        }
    }

    // ------------------------------------------------------------------
    // Function analysis and core identification
    // ------------------------------------------------------------------

    private AnalysisModel analyzeProgram() {
        AnalysisModel model=new AnalysisModel();
        FunctionIterator it=currentProgram.getFunctionManager().getFunctions(true); int count=0;
        while (it.hasNext()&&!monitor.isCancelled()) {
            if (settings.maxFunctions!=0 && count>=settings.maxFunctions) { truncations.add("Function inventory reached configured limit."); break; }
            FunctionRecord r=analyzeFunction(it.next()); model.functions.add(r); model.byEntry.put(addr(r.entry),r); count++;
        }
        identifyCore(model); traverseCoreCalls(model); score(model);
        Collections.sort(model.functions,(a,b)->a.score!=b.score?Integer.compare(b.score,a.score):a.entry.compareTo(b.entry));
        return model;
    }

    private FunctionRecord analyzeFunction(Function f) {
        FunctionRecord r=new FunctionRecord(f); r.entry=f.getEntryPoint(); r.name=f.getName(); r.prototype=safePrototype(f);
        r.external=isExternal(f); r.thunk=isThunk(f); r.userNamed="USER_DEFINED".equalsIgnoreCase(symbolSource(f));
        r.xrefs=countReferencesTo(r.entry);
        Listing listing=currentProgram.getListing(); ReferenceManager rm=currentProgram.getReferenceManager();
        InstructionIterator it=listing.getInstructions(f.getBody(),true); Instruction previous=null;
        while (it.hasNext()&&!monitor.isCancelled()) {
            Instruction ins=it.next(); r.instructions++;
            String mnemonic=ins.getMnemonicString().toLowerCase(Locale.ROOT);
            if (semanticMnemonic(mnemonic)) r.semantic.add(addr(ins.getAddress())+" "+ins.toString());
            boolean direct=false;
            for (Reference ref:rm.getReferencesFrom(ins.getAddress())) {
                if (!ref.getReferenceType().isCall()) continue;
                direct=true; Address to=ref.getToAddress(); Function target=to==null?null:getFunctionContaining(to);
                CallEdge edge=new CallEdge(r.name,r.entry,ins.getAddress(),to,target==null?"":target.getName(),ref.getReferenceType().toString());
                r.calls.add(edge); r.callsOut++;
                if (target!=null) { r.callees.add(addr(target.getEntryPoint())); if (isExternal(target)) r.externalCalls++; }
            }
            if (ins.getFlowType().isCall()&&!direct) addIndirect(r,ins,"computed_call");
            if (legacyIndirect(previous,ins) && !hasIndirect(r,ins.getAddress())) addIndirect(r,ins,"legacy_arm_mov_lr_pc_then_mov_pc_register");
            collectDataAccesses(r, ins, rm);
            if (settings.exportFlows) collectFlows(r,ins);
            String normalizedValue = normalize(ins,previous);
            if (settings.exportNormalized) {
                r.normalized.add(new Normalized(ins.getAddress(),ins.toString(),normalizedValue));
            }
            r.normalizedForHash.add(normalizedValue);
            collectFunctionFeatures(r, mnemonic, ins, previous);
            previous=ins;
        }
        r.fingerprint = sha256(join(r.normalizedForHash, "\n"));
        return r;
    }

    private void addIndirect(FunctionRecord r, Instruction ins, String kind) {
        r.indirect.add(new IndirectCall(r.name,r.entry,ins.getAddress(),kind,ins.toString(),context(ins,3,3))); r.indirectCount++;
    }

    private boolean hasIndirect(FunctionRecord r, Address a) {
        for (IndirectCall c:r.indirect) if (c.address.equals(a)) return true; return false;
    }

    private boolean legacyIndirect(Instruction previous, Instruction current) {
        if (previous==null||current==null) return false;
        String p=previous.toString().toLowerCase(Locale.ROOT).replace(" ","");
        String c=current.toString().toLowerCase(Locale.ROOT).replace(" ","");
        return (p.startsWith("movlr,pc")||p.startsWith("cpylr,pc")) && (c.startsWith("movpc,")||c.startsWith("cpypc,"));
    }

    private String context(Instruction center, int before, int after) {
        Listing listing=currentProgram.getListing(); List<Instruction> prior=new ArrayList<>(); Instruction x=center;
        for (int i=0;i<before;i++) { x=listing.getInstructionBefore(x.getAddress()); if (x==null) break; prior.add(x); }
        Collections.reverse(prior); StringBuilder b=new StringBuilder();
        for (Instruction i:prior) b.append(addr(i.getAddress())).append(' ').append(i).append(" | ");
        b.append(addr(center.getAddress())).append(' ').append(center); x=center;
        for (int i=0;i<after;i++) { x=listing.getInstructionAfter(x.getAddress()); if (x==null) break; b.append(" | ").append(addr(x.getAddress())).append(' ').append(x); }
        return b.toString();
    }

    private void collectFlows(FunctionRecord r, Instruction ins) {
        for (Address target:ins.getFlows()) r.flows.add(new FlowEdge(r.name,r.entry,ins.getAddress(),target,ins.getFlowType().toString()));
        Address fall=ins.getFallThrough(); if (fall!=null && ins.getFlowType().hasFallthrough()) r.flows.add(new FlowEdge(r.name,r.entry,ins.getAddress(),fall,"FALL_THROUGH"));
    }

    private boolean semanticMnemonic(String m) {
        return m.startsWith("vadd")||m.startsWith("vsub")||m.startsWith("vmul")||m.startsWith("vdiv")||m.startsWith("vsqrt")||m.startsWith("vcmp")||m.equals("mul")||m.equals("mla")||m.equals("udiv")||m.equals("sdiv");
    }

    private String normalize(Instruction ins, Instruction previous) {
        String m=ins.getMnemonicString().toLowerCase(Locale.ROOT);
        if (ins.getFlowType().isCall() || legacyIndirect(previous,ins)) {
            for (Reference ref:currentProgram.getReferenceManager().getReferencesFrom(ins.getAddress())) {
                if (!ref.getReferenceType().isCall()) continue;
                Function target=ref.getToAddress()==null?null:getFunctionContaining(ref.getToAddress());
                if (target!=null) return m+" call_name:"+safeToken(target.getName());
            }
            return m+" call_indirect";
        }
        StringBuilder b=new StringBuilder(m);
        for (int i=0;i<ins.getNumOperands();i++) {
            int type=ins.getOperandType(i); String token;
            if (OperandType.isRegister(type)) token="reg";
            else if (OperandType.isScalar(type)) token="imm";
            else if (OperandType.isAddress(type)) token="addr";
            else if (OperandType.isIndirect(type)||OperandType.isDynamic(type)) token="mem";
            else token="op";
            b.append(' ').append(token);
        }
        return b.toString();
    }

    private void collectDataAccesses(
        FunctionRecord record,
        Instruction instruction,
        ReferenceManager referenceManager
    ) {
        for (Reference reference :
            referenceManager.getReferencesFrom(instruction.getAddress())) {

            if (reference.getReferenceType().isCall()) continue;
            Address target = reference.getToAddress();
            if (target == null || !target.isMemoryAddress()) continue;

            DataAccess access = new DataAccess();
            access.functionName = record.name;
            access.functionEntry = record.entry;
            access.instructionAddress = instruction.getAddress();
            access.target = target;
            access.referenceType = reference.getReferenceType().toString();
            access.read = reference.getReferenceType().isRead();
            access.write = reference.getReferenceType().isWrite();

            MemoryBlock block = currentProgram.getMemory().getBlock(target);
            access.memoryBlock = block == null ? "" : block.getName();

            Symbol symbol =
                currentProgram.getSymbolTable().getPrimarySymbol(target);
            access.symbol = symbol == null ? "" : symbol.getName(true);

            Data data = currentProgram.getListing().getDefinedDataContaining(target);
            if (data != null) {
                try {
                    access.dataType = data.getDataType().getName();
                    access.representation = data.getDefaultValueRepresentation();
                }
                catch (Exception ignored) {
                }
            }

            record.dataAccesses.add(access);
        }
    }

    private void collectFunctionFeatures(
        FunctionRecord record,
        String mnemonic,
        Instruction instruction,
        Instruction previous
    ) {
        String lower = mnemonic.toLowerCase(Locale.ROOT);

        if (lower.startsWith("vmul") || lower.equals("mul") || lower.equals("mla")) {
            record.features.add("MUL");
        }
        if (lower.startsWith("vdiv") || lower.equals("udiv") || lower.equals("sdiv")) {
            record.features.add("DIV");
        }
        if (lower.startsWith("vadd") || lower.equals("add")) {
            record.features.add("ADD");
        }
        if (lower.startsWith("vsub") || lower.equals("sub")) {
            record.features.add("SUB");
        }
        if (lower.startsWith("vsqrt")) {
            record.features.add("CALL_SQRT");
        }
        if (instruction.getFlowType().isJump() &&
            instruction.getFlowType().hasFallthrough()) {
            record.features.add("BRANCH");
        }
        if (legacyIndirect(previous, instruction) ||
            (instruction.getFlowType().isCall() &&
             instruction.getFlows().length == 0)) {
            record.features.add("INDIRECT_CALL");
        }
    }

    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] result = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder output = new StringBuilder();
            for (byte b : result) {
                output.append(String.format("%02x", b & 0xff));
            }
            return output.toString();
        }
        catch (Exception e) {
            return "";
        }
    }

    private void identifyCore(AnalysisModel model) {
        for (FunctionRecord r:model.functions) {
            String n=r.name, upper=n.toUpperCase(Locale.ROOT);
            if (detection.toolchain==Toolchain.GEB) {
                if (n.matches("(?i)^dt_(PR|FN|FB)_.*")) markCore(model,r,"GEB generated POU naming pattern",95);
                if (n.equalsIgnoreCase("dt_PR_program0_exec")) { markCore(model,r,"GEB main program root",99); model.roots.add(addr(r.entry)); }
            }
            else if (isOpenPlc()) {
                if (n.equalsIgnoreCase("PROGRAM0_body__")) { markCore(model,r,"OpenPLC main program body",99); model.roots.add(addr(r.entry)); }
                else if (upper.startsWith("__PROGRAM0__")||upper.matches("^[A-Z0-9_]+_BODY__$")) markCore(model,r,"OpenPLC generated control-logic name",95);
            }
            else if (detection.toolchain==Toolchain.CODESYS) {
                if (n.equalsIgnoreCase("PLC_PRG")) { markCore(model,r,"CODESYS PLC_PRG root",99); model.roots.add(addr(r.entry)); }
                if (!defaultName(n)&&sourceMatch(n)) markCore(model,r,"Name matches paired ST POU",98);
            }
            if (sourceMatch(n)) markCore(model,r,"Name matches paired ST source",98);
        }
        if (model.roots.isEmpty()) for (String e:model.core) model.roots.add(e);
    }

    private void traverseCoreCalls(AnalysisModel model) {
        if (settings.depth==0||model.roots.isEmpty()) return;
        Deque<Traversal> q=new ArrayDeque<>(); Set<String> visited=new HashSet<>();
        for (String root:model.roots) q.add(new Traversal(root,0));
        while (!q.isEmpty()&&!monitor.isCancelled()) {
            Traversal t=q.removeFirst(); if (!visited.add(t.entry)) continue; FunctionRecord r=model.byEntry.get(t.entry); if (r==null||t.depth>=settings.depth) continue;
            for (String entry:r.callees) {
                FunctionRecord c=model.byEntry.get(entry); if (c==null||c.external||!includeCallee(c)) continue;
                markCore(model,c,"Direct call-chain from PLC root",80); q.addLast(new Traversal(entry,t.depth+1));
            }
        }
    }

    private boolean includeCallee(FunctionRecord r) {
        String n=r.name, upper=n.toUpperCase(Locale.ROOT);
        if (detection.toolchain==Toolchain.GEB) return n.matches("(?i)^dt_(PR|FN|FB)_.*")||sourceMatch(n);
        if (isOpenPlc()) return !openPlcRuntime(n)&&(upper.startsWith("__PROGRAM0__")||upper.matches("^[A-Z0-9_]+_BODY__$")||sourceMatch(n));
        if (detection.toolchain==Toolchain.CODESYS) return (!defaultName(n)&&sourceMatch(n))||r.userNamed;
        return sourceMatch(n)||r.userNamed;
    }

    private boolean openPlcRuntime(String n) {
        String x=n.toLowerCase(Locale.ROOT);
        return x.equals("main")||x.equals("_start")||x.startsWith("config_init__")||x.startsWith("config_run__")||x.contains("updatebuffers")||x.contains("gluevars")||x.contains("openplc")||x.contains("modbus")||x.contains("hardware_layer")||x.startsWith("__libc")||x.startsWith("pthread_");
    }

    private boolean isOpenPlc() { return detection.toolchain==Toolchain.OPENPLC||detection.toolchain==Toolchain.OPENPLC2||detection.toolchain==Toolchain.OPENPLC3; }
    private boolean sourceMatch(String n) { String u=n.toUpperCase(Locale.ROOT); for (String s:source.names) if (u.equals(s.toUpperCase(Locale.ROOT))||u.contains(s.toUpperCase(Locale.ROOT))) return true; return false; }
    private boolean defaultName(String n) { return n==null||n.matches("(?i)^(FUN|SUB)_[0-9A-F]+$")||n.matches("(?i)^THUNK_FUN_[0-9A-F]+$"); }
    private void markCore(AnalysisModel m, FunctionRecord r, String reason) {
        markCore(m, r, reason, 75);
    }

    private void markCore(
        AnalysisModel model,
        FunctionRecord record,
        String reason,
        int confidence
    ) {
        record.core = true;
        record.coreConfidence = Math.max(record.coreConfidence, confidence);
        record.coreReasons.add(reason);
        model.core.add(addr(record.entry));
    }

    private void score(AnalysisModel model) {
        for (FunctionRecord record : model.functions) {
            int value = record.core ? 50 : 0;
            value += Math.min(record.coreConfidence / 5, 20);
            value += Math.min(record.xrefs * 3, 30);
            value += Math.min(record.callsOut, 20);
            value += Math.min(record.externalCalls * 2, 20);
            value += Math.min(record.indirectCount * 4, 20);
            value += Math.min(record.semantic.size() * 5, 25);
            value += Math.min(record.instructions / 20, 25);

            if (record.userNamed) value += 10;
            if (record.thunk) value -= 10;
            record.score = Math.max(0, value);
        }
    }

    private void applyHighConfidenceAnnotations(
        AnalysisModel model,
        List<SourceMatch> sourceMatches,
        List<LiteralRecord> literals,
        List<CodesysCandidate> candidates
    ) {
        for (FunctionRecord record : model.functions) {
            if (record.core && record.coreConfidence >= settings.minConfidence) {
                String message =
                    MANAGED_PREFIX + " Probable PLC control function. " +
                    "Toolchain=" + detection.toolchain.label +
                    "; confidence=" + record.coreConfidence + "%; reasons=" +
                    join(record.coreReasons, "; ");

                setManagedPlateComment(record.entry, message);

                if (settings.createBookmarks) {
                    addBookmark(
                        record.entry,
                        "PLC-AUTO/Core",
                        message
                    );
                }
            }

            for (IndirectCall call : record.indirect) {
                int confidence =
                    "legacy_arm_mov_lr_pc_then_mov_pc_register".equals(call.kind)
                        ? 95
                        : 80;

                if (confidence < settings.minConfidence) continue;

                String message =
                    MANAGED_PREFIX +
                    " Probable indirect PLC runtime/helper call; confidence=" +
                    confidence + "%. Verify against source and surrounding assembly.";

                setManagedEolComment(call.address, message);

                if (settings.createBookmarks) {
                    addBookmark(
                        call.address,
                        "PLC-AUTO/IndirectCall",
                        message
                    );
                }
            }
        }

        for (SourceMatch match : sourceMatches) {
            if (match.confidence < settings.minConfidence ||
                match.function == null ||
                !match.uniqueHighConfidence) {
                continue;
            }

            String message =
                MANAGED_PREFIX + " Probable source mapping: " +
                match.pou.type + " " + match.pou.name +
                "; confidence=" + match.confidence +
                "%; evidence=" + join(match.reasons, "; ");

            setManagedPlateComment(match.function.entry, message);

            if (settings.createBookmarks) {
                addBookmark(
                    match.function.entry,
                    "PLC-AUTO/SourceMatch",
                    message
                );
            }
        }

        for (LiteralRecord literal : literals) {
            if (literal.confidence < settings.minConfidence) continue;
            if (settings.createBookmarks) {
                addBookmark(
                    literal.address,
                    "PLC-AUTO/LiteralPool",
                    literal.description + "; confidence=" +
                    literal.confidence + "%"
                );
            }
        }

        for (CodesysCandidate candidate : candidates) {
            if (candidate.confidence >= settings.minConfidence) continue;
            if (candidate.confidence < Math.max(70, settings.minConfidence - 15)) continue;

            if (settings.createBookmarks) {
                addBookmark(
                    candidate.address,
                    "PLC-AUTO/ReviewFunction",
                    "Possible CODESYS function candidate; confidence=" +
                    candidate.confidence + "%. " +
                    join(candidate.reasons, "; ")
                );
            }
        }
    }

    private void addBookmark(Address address, String category, String comment) {
        try {
            currentProgram.getBookmarkManager().setBookmark(
                address,
                BOOKMARK_TYPE,
                category,
                comment
            );
        }
        catch (Exception e) {
            warnings.add(
                "Could not create bookmark at " + addr(address) + ": " + e
            );
        }
    }

    private void setManagedPlateComment(Address address, String message) {
        try {
            String existing = getPlateComment(address);
            setPlateComment(address, mergeManagedComment(existing, message));
            changes.add("Updated managed plate comment at " + addr(address));
        }
        catch (Exception e) {
            warnings.add(
                "Could not set plate comment at " + addr(address) + ": " + e
            );
        }
    }

    private void setManagedEolComment(Address address, String message) {
        try {
            String existing = getEOLComment(address);
            setEOLComment(address, mergeManagedComment(existing, message));
            changes.add("Updated managed EOL comment at " + addr(address));
        }
        catch (Exception e) {
            warnings.add(
                "Could not set EOL comment at " + addr(address) + ": " + e
            );
        }
    }

    private String mergeManagedComment(String existing, String message) {
        List<String> retained = new ArrayList<>();

        if (existing != null && !existing.trim().isEmpty()) {
            for (String line : existing.split("\\r?\\n")) {
                if (!line.startsWith(MANAGED_PREFIX)) {
                    retained.add(line);
                }
            }
        }

        retained.add(message);
        return join(retained, "\n");
    }

    private Preflight runPreflight(List<CodesysCandidate> candidates) {
        Preflight result = new Preflight();
        result.language = currentProgram.getLanguageID().toString();
        result.format = safe(currentProgram.getExecutableFormat());
        result.imageBase = addr(currentProgram.getImageBase());

        if (detection.toolchain == Toolchain.CODESYS) {
            result.add(
                isArm32LE(),
                "CODESYS import uses ARM32 little-endian",
                "Reimport as Generic ARM/Thumb v7 little endian (ARM:LE:32:v7).",
                true
            );

            String languageLower = result.language.toLowerCase(Locale.ROOT);
            result.add(
                !languageLower.contains("v7t") && !languageLower.contains("v8t"),
                "ARM mode is the default rather than Thumb mode",
                "Select the ARM-default language variant, not the variant ending in T.",
                true
            );

            result.add(
                currentProgram.getImageBase().getOffset() == 0,
                "Raw CODESYS image base is zero",
                "Image base zero is recommended for file-relative CODESYS analysis.",
                false
            );

            int highConfidence = 0;
            for (CodesysCandidate candidate : candidates) {
                if (candidate.confidence >= settings.minConfidence) highConfidence++;
            }

            result.highConfidenceCandidates = highConfidence;
            result.add(
                highConfidence > 0,
                "At least one high-confidence CODESYS function candidate exists",
                "Verify processor language and file offset mapping.",
                true
            );

            result.add(
                verifyDmbDecode(),
                "ARM memory-barrier instructions decode correctly when present",
                "A decoder older than ARMv7 can produce bad-data decompilation.",
                false
            );
        }
        else {
            String formatLower = result.format.toLowerCase(Locale.ROOT);
            result.add(
                !(formatLower.contains("raw") || formatLower.contains("binary")),
                "Non-CODESYS program uses a structured executable import",
                "GEB and OpenPLC files should generally be imported through their normal ELF/PE loader.",
                true
            );

            int symbolCount = 0;
            SymbolIterator symbols =
                currentProgram.getSymbolTable().getAllSymbols(true);
            while (symbols.hasNext() && symbolCount < 100000) {
                symbols.next();
                symbolCount++;
            }

            result.symbolCount = symbolCount;
            result.add(
                symbolCount > 0,
                "Ghidra recovered symbols or generated labels",
                "Allow normal Ghidra auto-analysis to finish before running this script.",
                false
            );
        }

        result.automationAllowed =
            result.fatalFailures == 0 &&
            (
                "high".equals(detection.confidence()) ||
                !detection.override.isEmpty()
            );

        result.overallStatus =
            result.fatalFailures == 0
                ? (result.automationAllowed ? "PASS" : "REPORT-ONLY")
                : "FAIL";

        return result;
    }

    private boolean verifyDmbDecode() {
        if (!isArm32LE()) return false;

        byte[] dmb = new byte[] {
            (byte)0x5f, (byte)0xf0, (byte)0x7f, (byte)0xf5
        };

        List<MarkerHit> hits = findBytes("DMB_ENCODING", dmb, "ARM_WORD");
        if (hits.isEmpty()) return true;

        try {
            PseudoInstruction instruction =
                new PseudoDisassembler(currentProgram)
                    .disassemble(hits.get(0).address);

            return instruction != null &&
                instruction.getMnemonicString()
                    .toLowerCase(Locale.ROOT)
                    .startsWith("dmb");
        }
        catch (Exception e) {
            return false;
        }
    }

    private List<SourceMatch> buildSourceMatches(AnalysisModel model) {
        List<SourceMatch> matches = new ArrayList<>();
        if (source.file == null) return matches;

        boolean hasLnMetadata = hasMarker("REAL32__LN");
        boolean hasSqrtMetadata = hasMarker("REAL32__SQRT");

        for (Pou pou : source.pous) {
            List<SourceMatch> perPou = new ArrayList<>();

            for (FunctionRecord function : model.functions) {
                if (function.external || function.thunk) continue;

                SourceMatch match = new SourceMatch();
                match.pou = pou;
                match.function = function;
                int score = 0;

                String upperName = function.name.toUpperCase(Locale.ROOT);
                String sourceName = pou.name.toUpperCase(Locale.ROOT);

                if (upperName.equals(sourceName)) {
                    score += 80;
                    match.reasons.add("Exact function-name match");
                }
                else if (upperName.contains(sourceName)) {
                    score += 65;
                    match.reasons.add("Generated function name contains source POU name");
                }

                for (String expected : expectedNames(pou)) {
                    String normalizedExpected =
                        expected.replace("*", "").toUpperCase(Locale.ROOT);
                    if (!normalizedExpected.isEmpty() &&
                        upperName.contains(normalizedExpected)) {
                        score += 75;
                        match.reasons.add(
                            "Matches expected compiler-generated name " + expected
                        );
                        break;
                    }
                }

                int featureMatches = 0;
                int matchableFeatures = 0;

                for (String feature : pou.features) {
                    if (feature.startsWith("CONST_")) {
                        continue;
                    }

                    matchableFeatures++;

                    if ("CALL_LN".equals(feature) &&
                        function.features.contains("INDIRECT_CALL") &&
                        hasLnMetadata) {

                        featureMatches++;
                        score += 22;
                        match.reasons.add(
                            "LN source call corresponds to an unresolved indirect call and LN metadata"
                        );
                    }
                    else if ("CALL_SQRT".equals(feature) &&
                        function.features.contains("CALL_SQRT")) {

                        featureMatches++;
                        score += 18;
                        match.reasons.add("SQRT source call matches a recovered square-root instruction");
                    }
                    else if (function.features.contains(feature)) {
                        featureMatches++;

                        if ("MUL".equals(feature) ||
                            "DIV".equals(feature) ||
                            "ADD".equals(feature) ||
                            "SUB".equals(feature)) {
                            score += 10;
                        }
                        else {
                            score += 8;
                        }
                    }
                }

                if (featureMatches > 0) {
                    match.reasons.add(
                        featureMatches + " source operation feature(s) matched"
                    );
                }

                if (matchableFeatures >= 3 &&
                    featureMatches == matchableFeatures) {

                    score += 22;
                    match.reasons.add(
                        "All matchable source operations were recovered in the function"
                    );
                }
                else if (matchableFeatures >= 4 &&
                    featureMatches * 4 >= matchableFeatures * 3) {

                    score += 12;
                    match.reasons.add(
                        "At least 75% of matchable source operations were recovered"
                    );
                }

                if (pou.features.contains("CONST_1_0") &&
                    functionReferencesFloat(function.function, 1.0f)) {
                    score += 12;
                    match.reasons.add("References floating-point constant 1.0");
                }

                if (pou.features.contains("CONST_0_0") &&
                    functionReferencesFloat(function.function, 0.0f)) {
                    score += 8;
                    match.reasons.add("References floating-point constant 0.0");
                }

                if (function.instructions > 0 && function.instructions < 160) {
                    score += 4;
                }

                match.confidence = Math.max(0, Math.min(100, score));
                if (match.confidence >= 35) {
                    perPou.add(match);
                }
            }

            Collections.sort(
                perPou,
                (left, right) -> Integer.compare(right.confidence, left.confidence)
            );

            if (!perPou.isEmpty()) {
                SourceMatch best = perPou.get(0);
                int second =
                    perPou.size() > 1 ? perPou.get(1).confidence : 0;
                best.uniqueHighConfidence =
                    best.confidence >= settings.minConfidence &&
                    best.confidence - second >= 12;

                matches.addAll(
                    perPou.subList(0, Math.min(5, perPou.size()))
                );
            }
        }

        return matches;
    }

    private boolean hasMarker(String name) {
        if (detection == null) return false;
        // Marker evidence is carried by detection; exact marker strings are also
        // searched in the binary during source mapping through metadata labels.
        return findBytes(
            name,
            name.getBytes(StandardCharsets.US_ASCII),
            "ASCII"
        ).size() > 0;
    }

    private void applySourceMatchesToModel(
        AnalysisModel model,
        List<SourceMatch> matches
    ) {
        for (SourceMatch match : matches) {
            if (!match.uniqueHighConfidence ||
                match.function == null ||
                match.confidence < settings.minConfidence) {
                continue;
            }

            markCore(
                model,
                match.function,
                "Unique high-confidence source match: " +
                match.pou.type + " " + match.pou.name,
                match.confidence
            );
        }

        score(model);
        Collections.sort(
            model.functions,
            (left, right) ->
                left.score != right.score
                    ? Integer.compare(right.score, left.score)
                    : left.entry.compareTo(right.entry)
        );
    }

    private boolean functionReferencesFloat(Function function, float expected) {
        int expectedBits = Float.floatToIntBits(expected);
        ReferenceManager references = currentProgram.getReferenceManager();
        InstructionIterator instructions =
            currentProgram.getListing()
                .getInstructions(function.getBody(), true);

        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            for (Reference reference :
                references.getReferencesFrom(instruction.getAddress())) {

                Address target = reference.getToAddress();
                if (target == null || !target.isMemoryAddress()) continue;

                try {
                    int bits =
                        currentProgram.getMemory().getInt(target, false);
                    if (bits == expectedBits) return true;
                }
                catch (Exception ignored) {
                }
            }
        }

        return false;
    }

    private List<LiteralRecord> findLiteralPoolCandidates(AnalysisModel model) {
        Map<String, LiteralRecord> unique = new LinkedHashMap<>();
        ReferenceManager references = currentProgram.getReferenceManager();

        for (FunctionRecord record : model.functions) {
            if (record.external) continue;

            InstructionIterator instructions =
                currentProgram.getListing()
                    .getInstructions(record.function.getBody(), true);

            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                String mnemonic =
                    instruction.getMnemonicString().toLowerCase(Locale.ROOT);

                for (Reference reference :
                    references.getReferencesFrom(instruction.getAddress())) {

                    Address target = reference.getToAddress();
                    if (target == null || !target.isMemoryAddress()) continue;
                    if (record.function.getBody().contains(target)) continue;

                    long distance;
                    try {
                        distance = target.subtract(record.function.getBody().getMaxAddress());
                    }
                    catch (Exception e) {
                        continue;
                    }

                    if (distance < 0 || distance > 512) continue;

                    LiteralRecord literal =
                        unique.computeIfAbsent(
                            addr(target),
                            key -> new LiteralRecord()
                        );

                    literal.address = target;
                    literal.referencingFunctions.add(record.name);
                    literal.referenceSites.add(addr(instruction.getAddress()));
                    literal.mnemonics.add(mnemonic);

                    try {
                        int word =
                            currentProgram.getMemory().getInt(target, false);
                        literal.rawHex =
                            String.format("0x%08X", word);
                        float floatValue =
                            Float.intBitsToFloat(word);
                        literal.floatValue = floatValue;

                        if (Float.isFinite(floatValue) &&
                            isCommonFloat(floatValue) &&
                            (mnemonic.startsWith("vldr") ||
                             mnemonic.startsWith("ldr"))) {
                            literal.confidence = 95;
                            literal.description =
                                "Probable literal-pool float " + floatValue;
                        }
                        else {
                            literal.confidence = Math.max(literal.confidence, 75);
                            literal.description =
                                "Probable ARM literal-pool word " + literal.rawHex;
                        }
                    }
                    catch (Exception e) {
                        literal.description = "Probable literal-pool address";
                        literal.confidence = Math.max(literal.confidence, 70);
                    }
                }
            }
        }

        return new ArrayList<>(unique.values());
    }

    private boolean isCommonFloat(float value) {
        float[] common = {
            0.0f, 1.0f, -1.0f, 0.5f, 2.0f, 10.0f,
            (float)Math.PI, (float)Math.E
        };

        for (float candidate : common) {
            if (Float.floatToIntBits(value) ==
                Float.floatToIntBits(candidate)) {
                return true;
            }
        }

        return false;
    }

    private List<VariableRecord> buildVariableMatrix(AnalysisModel model) {
        Map<String, VariableRecord> variables = new TreeMap<>();

        for (FunctionRecord function : model.functions) {
            for (DataAccess access : function.dataAccesses) {
                VariableRecord variable =
                    variables.computeIfAbsent(
                        addr(access.target),
                        key -> new VariableRecord()
                    );

                variable.address = access.target;
                variable.symbol =
                    variable.symbol.isEmpty()
                        ? access.symbol
                        : variable.symbol;
                variable.memoryBlock =
                    variable.memoryBlock.isEmpty()
                        ? access.memoryBlock
                        : variable.memoryBlock;
                variable.dataType =
                    variable.dataType.isEmpty()
                        ? access.dataType
                        : variable.dataType;
                variable.representation =
                    variable.representation.isEmpty()
                        ? access.representation
                        : variable.representation;

                if (access.read) {
                    variable.readers.add(function.name);
                    if (function.core) variable.coreReaders.add(function.name);
                }
                if (access.write) {
                    variable.writers.add(function.name);
                    if (function.core) variable.coreWriters.add(function.name);
                }

                variable.referenceTypes.add(access.referenceType);
                variable.referenceCount++;
            }
        }

        for (VariableRecord variable : variables.values()) {
            if (!variable.coreReaders.isEmpty() &&
                variable.coreWriters.isEmpty() &&
                !variable.writers.isEmpty()) {
                variable.role = "probable_input_or_runtime_supplied";
                variable.confidence = 80;
            }
            else if (!variable.coreWriters.isEmpty() &&
                variable.coreReaders.isEmpty() &&
                !variable.readers.isEmpty()) {
                variable.role = "probable_output_or_runtime_consumed";
                variable.confidence = 80;
            }
            else if (!variable.coreReaders.isEmpty() &&
                !variable.coreWriters.isEmpty()) {
                variable.role = "probable_internal_state";
                variable.confidence = 85;
            }
            else if (!variable.coreReaders.isEmpty() &&
                variable.writers.isEmpty()) {
                variable.role = "probable_constant_or_configuration";
                variable.confidence = 75;
            }
            else {
                variable.role = "unclassified_data";
                variable.confidence = 50;
            }
        }

        return new ArrayList<>(variables.values());
    }

    private List<FingerprintGroup> buildFingerprintGroups(AnalysisModel model) {
        Map<String, FingerprintGroup> groups = new LinkedHashMap<>();

        for (FunctionRecord function : model.functions) {
            if (function.fingerprint == null ||
                function.fingerprint.isEmpty() ||
                function.instructions < 3) {
                continue;
            }

            FingerprintGroup group =
                groups.computeIfAbsent(
                    function.fingerprint,
                    key -> new FingerprintGroup()
                );

            group.fingerprint = function.fingerprint;
            group.functions.add(function);
        }

        List<FingerprintGroup> result = new ArrayList<>();
        for (FingerprintGroup group : groups.values()) {
            if (group.functions.size() > 1) {
                result.add(group);
            }
        }

        Collections.sort(
            result,
            (left, right) ->
                Integer.compare(right.functions.size(), left.functions.size())
        );

        return result;
    }

    // ------------------------------------------------------------------
    // Reports
    // ------------------------------------------------------------------

    private void writeReports(
        File out,
        List<MarkerHit> markers,
        List<CodesysCandidate> candidates,
        AnalysisModel model,
        Preflight preflight,
        List<SourceMatch> sourceMatches,
        List<LiteralRecord> literals,
        List<VariableRecord> variables,
        List<FingerprintGroup> fingerprintGroups
    ) throws IOException {
        write(new File(out, "README.md"), readmeText());
        write(new File(out, "preflight.md"), preflightMarkdown(preflight));
        write(new File(out, "plc_analysis_summary.md"), summaryText(model));
        write(new File(out, "toolchain_detection.csv"), detectionCsv());
        write(new File(out, "metadata_strings.csv"), markersCsv(markers));
        write(new File(out, "function_inventory.csv"), functionsCsv(model));
        write(new File(out, "core_functions.md"), coreMarkdown(model));
        write(new File(out, "call_edges.csv"), callsCsv(model));
        write(new File(out, "indirect_calls.csv"), indirectCsv(model));
        write(new File(out, "semantic_hints.csv"), semanticCsv(model));
        write(new File(out, "variable_access.csv"), variablesCsv(variables));
        write(new File(out, "literal_pools.csv"), literalsCsv(literals));
        write(
            new File(out, "function_fingerprints.csv"),
            fingerprintsCsv(model)
        );
        write(
            new File(out, "duplicate_function_groups.md"),
            duplicateGroupsMarkdown(fingerprintGroups)
        );

        if (settings.exportNormalized) {
            write(
                new File(out, "normalized_instructions.csv"),
                normalizedCsv(model)
            );
        }

        if (settings.exportFlows) {
            write(
                new File(out, "control_flow_edges.csv"),
                flowsCsv(model)
            );
        }

        if (!candidates.isEmpty() ||
            detection.toolchain == Toolchain.CODESYS) {
            write(
                new File(out, "codesys_function_candidates.csv"),
                candidatesCsv(candidates)
            );
        }

        if (source.file != null) {
            write(
                new File(out, "source_crosswalk.md"),
                sourceCrosswalk(model, markers)
            );
            write(
                new File(out, "source_function_candidates.csv"),
                sourceMatchesCsv(sourceMatches)
            );
            write(
                new File(out, "source_tasks.md"),
                sourceTasksMarkdown()
            );
        }

        if (metadataMatch.file != null) {
            write(
                new File(out, "metadata_match.md"),
                metadataMatchMarkdown()
            );
        }

        exportCompleteProgramAssembly(
            out,
            model,
            candidates
        );

        write(
            new File(out, "report.html"),
            htmlReport(
                model,
                preflight,
                sourceMatches,
                variables,
                literals
            )
        );

        write(new File(out, "codex_prompt.md"), codexPrompt());
        write(
            new File(out, "ANALYSIS_CHANGES.md"),
            listReport("Analysis-only Ghidra project changes", changes)
        );
        write(
            new File(out, "ANALYSIS_WARNINGS.md"),
            warningsReport()
        );
    }

    private String readmeText() {
        return "# PLC Program Plus Analysis Export\n\n"+
            "Generated by `AnalyzePLCProgramPlusV2.java` version `"+VERSION+"`.\n\n"+
            "This bundle combines Ghidra analysis with cautious platform-specific heuristics for CODESYS v3, GEB, and OpenPLC v2/v3.\n\n"+
            "## Recommended reading order\n\n1. `preflight.md`\n2. `plc_analysis_summary.md`\n3. `ANALYSIS_WARNINGS.md`\n4. `core_functions.md`\n5. `source_crosswalk.md`, when present\n6. `source_function_candidates.csv`, when present\n7. `program_assembly/README.md`\n8. `program_assembly/full_analyzed_assembly.asm`\n9. `program_assembly/candidate_pseudo_disassembly/` for low-confidence CODESYS candidates\n10. `variable_access.csv` and `literal_pools.csv`\n11. `function_inventory.csv`\n12. `metadata_strings.csv`\n13. `call_edges.csv` and `indirect_calls.csv`\n14. Selected folders and `SELECTION_README.md` under `core_function_details/`\n\n"+
            "## Limitations\n\n- CODESYS `.app` remains a proprietary container; prologue recovery is heuristic, not a full loader.\n- GEB/OpenPLC results depend on correct normal import and completed Ghidra auto-analysis.\n- Exact OpenPLC v2/v3 attribution may require dataset path or provenance.\n- Metadata names do not automatically prove code addresses.\n- `full_analyzed_assembly.asm` contains everything Ghidra has actually disassembled; undefined regions are summarized rather than falsely treated as code.\n- Candidate pseudo-disassembly is speculative and must not be treated as a confirmed function boundary.\n- Decompiler output is weaker evidence than raw assembly.\n";
    }

    private String summaryText(AnalysisModel model) {
        StringBuilder b=new StringBuilder();
        b.append("# PLC analysis summary\n\n");
        b.append("- Program: `").append(currentProgram.getName()).append("`\n");
        b.append("- Executable path: `").append(safe(currentProgram.getExecutablePath())).append("`\n");
        b.append("- Executable format: `").append(safe(currentProgram.getExecutableFormat())).append("`\n");
        b.append("- Language: `").append(currentProgram.getLanguageID()).append("`\n");
        b.append("- Compiler: `").append(safe(currentProgram.getCompiler())).append("`\n");
        b.append("- MD5: `").append(safe(currentProgram.getExecutableMD5())).append("`\n");
        b.append("- SHA-256: `").append(safe(currentProgram.getExecutableSHA256())).append("`\n");
        b.append("- Detected toolchain: **").append(detection.toolchain.label).append("**\n");
        b.append("- Automatic confidence threshold: `").append(settings.minConfidence).append("%`\n");
        b.append("- Paired source: `")
            .append(source.file == null ? "not found" : source.file.getAbsolutePath())
            .append("`\n");
        b.append("- Metadata match: `")
            .append(metadataMatch.file == null ? "not found" : metadataMatch.file.getAbsolutePath())
            .append("`\n");
        b.append("- Detection confidence: `").append(detection.confidence()).append("`\n");
        b.append("- Functions analyzed: `").append(model.functions.size()).append("`\n");
        b.append("- Probable core functions: `").append(model.core.size()).append("`\n\n");
        b.append("## Detection evidence\n\n"); for (String e:detection.chosenEvidence()) b.append("- ").append(e).append("\n");
        if (!detection.override.isEmpty()) b.append("- Manual override: `").append(detection.override).append("`\n");
        b.append("\n## Interpretation\n\n");
        if (detection.toolchain==Toolchain.CODESYS) b.append("CODESYS analysis uses embedded metadata plus ARM stack-frame prologue recovery. Runtime relocation/function-pointer targets may remain unresolved.\n");
        else if (detection.toolchain==Toolchain.GEB) b.append("GEB core logic is identified primarily through `dt_PR_*`, `dt_FN_*`, and `dt_FB_*`; `dt_PR_program0_exec` is treated as the main root when present.\n");
        else if (isOpenPlc()) b.append("OpenPLC core logic is identified primarily through `PROGRAM0_body__`, `__PROGRAM0__*`, and generated POU body symbols while excluding common runtime/support functions.\n");
        else b.append("No supported PLC toolchain was identified confidently; use the generic function and call reports for manual triage.\n");
        return b.toString();
    }

    private String detectionCsv() {
        StringBuilder b=new StringBuilder("toolchain,score,evidence\n");
        for (Toolchain t:Toolchain.values()) { if (t==Toolchain.UNKNOWN) continue; b.append(csv(t.label)).append(',').append(detection.score(t)).append(',').append(csv(join(detection.evidence.getOrDefault(t,Collections.emptyList())," | "))).append('\n'); }
        return b.toString();
    }

    private String markersCsv(List<MarkerHit> markers) {
        StringBuilder b=new StringBuilder("address,marker,encoding,memory_block\n");
        for (MarkerHit h:markers) b.append(csv(addr(h.address))).append(',').append(csv(h.marker)).append(',').append(csv(h.encoding)).append(',').append(csv(h.block)).append('\n');
        return b.toString();
    }

    private String functionsCsv(AnalysisModel model) {
        StringBuilder b = new StringBuilder(
            "rank,score,entry,name,prototype,instructions,xrefs_to_entry," +
            "calls_out,external_calls,indirect_calls,external,thunk,user_named," +
            "probable_core,core_confidence,core_reasons,semantic_hint_count," +
            "features,fingerprint\n"
        );

        int rank = 1;
        for (FunctionRecord record : model.functions) {
            b.append(rank++).append(',');
            b.append(record.score).append(',');
            b.append(csv(addr(record.entry))).append(',');
            b.append(csv(record.name)).append(',');
            b.append(csv(record.prototype)).append(',');
            b.append(record.instructions).append(',');
            b.append(record.xrefs).append(',');
            b.append(record.callsOut).append(',');
            b.append(record.externalCalls).append(',');
            b.append(record.indirectCount).append(',');
            b.append(record.external).append(',');
            b.append(record.thunk).append(',');
            b.append(record.userNamed).append(',');
            b.append(record.core).append(',');
            b.append(record.coreConfidence).append(',');
            b.append(csv(join(record.coreReasons, " | "))).append(',');
            b.append(record.semantic.size()).append(',');
            b.append(csv(join(record.features, " | "))).append(',');
            b.append(csv(record.fingerprint)).append('\n');
        }

        return b.toString();
    }

    private String coreMarkdown(AnalysisModel model) {
        StringBuilder b = new StringBuilder(
            "# Probable PLC core functions\n\n" +
            "Automatic project annotations require the configured confidence threshold. " +
            "Lower-confidence rows remain report-only.\n\n" +
            "| Entry | Function | Confidence | Score | Instructions | Calls | Indirect | Reasons |\n" +
            "|---|---|---:|---:|---:|---:|---:|---|\n"
        );

        for (FunctionRecord record : model.functions) {
            if (!record.core) continue;

            b.append("| `").append(addr(record.entry)).append("` | `")
                .append(md(record.name)).append("` | ")
                .append(record.coreConfidence).append("% | ")
                .append(record.score).append(" | ")
                .append(record.instructions).append(" | ")
                .append(record.callsOut).append(" | ")
                .append(record.indirectCount).append(" | ")
                .append(md(join(record.coreReasons, "; ")))
                .append(" |\n");
        }

        if (model.core.isEmpty()) {
            b.append(
                "\nNo core functions were identified automatically. " +
                "Use the source candidates and ranked inventory.\n"
            );
        }

        return b.toString();
    }

    private String callsCsv(AnalysisModel model) {
        StringBuilder b=new StringBuilder("from_function,from_entry,call_site,to_address,to_function,reference_type\n");
        for (FunctionRecord r:model.functions) for (CallEdge e:r.calls) b.append(csv(e.fromName)).append(',').append(csv(addr(e.fromEntry))).append(',').append(csv(addr(e.site))).append(',').append(csv(addr(e.to))).append(',').append(csv(e.toName)).append(',').append(csv(e.type)).append('\n');
        return b.toString();
    }

    private String indirectCsv(AnalysisModel model) {
        StringBuilder b=new StringBuilder("function,function_entry,address,kind,instruction,context\n");
        for (FunctionRecord r:model.functions) for (IndirectCall c:r.indirect) b.append(csv(c.function)).append(',').append(csv(addr(c.entry))).append(',').append(csv(addr(c.address))).append(',').append(csv(c.kind)).append(',').append(csv(c.instruction)).append(',').append(csv(c.context)).append('\n');
        return b.toString();
    }

    private String semanticCsv(AnalysisModel model) {
        StringBuilder b=new StringBuilder("function,function_entry,evidence\n");
        for (FunctionRecord r:model.functions) for (String h:r.semantic) b.append(csv(r.name)).append(',').append(csv(addr(r.entry))).append(',').append(csv(h)).append('\n');
        return b.toString();
    }

    private String normalizedCsv(AnalysisModel model) {
        StringBuilder b=new StringBuilder("function,function_entry,address,raw_instruction,normalized\n");
        for (FunctionRecord r:model.functions) for (Normalized n:r.normalized) b.append(csv(r.name)).append(',').append(csv(addr(r.entry))).append(',').append(csv(addr(n.address))).append(',').append(csv(n.raw)).append(',').append(csv(n.value)).append('\n');
        return b.toString();
    }

    private String flowsCsv(AnalysisModel model) {
        StringBuilder b=new StringBuilder("function,function_entry,from_address,to_address,flow_type\n");
        for (FunctionRecord r:model.functions) for (FlowEdge e:r.flows) b.append(csv(e.function)).append(',').append(csv(addr(e.entry))).append(',').append(csv(addr(e.from))).append(',').append(csv(addr(e.to))).append(',').append(csv(e.type)).append('\n');
        return b.toString();
    }

    private String candidatesCsv(List<CodesysCandidate> list) {
        StringBuilder b = new StringBuilder(
            "address,memory_block,frame_register,confidence," +
            "valid_initial_instructions,return_address,return_restores_frame," +
            "existing_function,inside_existing_function,recovery_status,reasons\n"
        );

        for (CodesysCandidate candidate : list) {
            b.append(csv(addr(candidate.address))).append(',');
            b.append(csv(candidate.block)).append(',');
            b.append(csv("r" + candidate.frame)).append(',');
            b.append(candidate.confidence).append(',');
            b.append(candidate.validInitialInstructions).append(',');
            b.append(csv(addr(candidate.returnAddress))).append(',');
            b.append(candidate.returnRestoresFrame).append(',');
            b.append(candidate.existing).append(',');
            b.append(candidate.inside).append(',');
            b.append(csv(candidate.status)).append(',');
            b.append(csv(join(candidate.reasons, " | "))).append('\n');
        }

        return b.toString();
    }

    private String sourceCrosswalk(AnalysisModel model, List<MarkerHit> markers) {
        StringBuilder b=new StringBuilder("# Structured Text source crosswalk\n\n- Source file: `"+source.file.getAbsolutePath()+"`\n- POU declarations: `"+source.pous.size()+"`\n\n| Source type | Source name | Expected generated names | Matching functions | Metadata occurrences |\n|---|---|---|---|---|\n");
        for (Pou p:source.pous) b.append("| ").append(md(p.type)).append(" | `").append(md(p.name)).append("` | ").append(md(join(expectedNames(p),", "))).append(" | ").append(md(join(functionMatches(model,p.name),", "))).append(" | ").append(md(join(markerMatches(markers,p.name),", "))).append(" |\n");
        b.append("\n## Function-like calls visible in source\n\n"); for (String c:source.calls) b.append("- `").append(md(c)).append("`\n");
        b.append("\nFor CODESYS, a metadata-name occurrence does not by itself identify the function body address.\n");
        return b.toString();
    }

    private List<String> expectedNames(Pou p) {
        List<String> out=new ArrayList<>(); String upper=p.name.toUpperCase(Locale.ROOT);
        if (detection.toolchain==Toolchain.GEB) { if (p.type.equals("PROGRAM")) out.add("dt_PR_"+p.name+"_exec"); else if (p.type.equals("FUNCTION_BLOCK")) out.add("dt_FB_"+p.name+"_*"); else out.add("dt_FN_"+p.name+"_*"); }
        else if (isOpenPlc()) { out.add(upper+"_body__"); out.add("__"+upper+"__*"); if (p.type.equals("PROGRAM")&&p.name.equalsIgnoreCase("program0")) { out.add("PROGRAM0_body__"); out.add("__PROGRAM0__*"); } }
        else out.add(p.name);
        return out;
    }

    private List<String> functionMatches(AnalysisModel model, String name) { List<String> out=new ArrayList<>(); String u=name.toUpperCase(Locale.ROOT); for (FunctionRecord r:model.functions) if (r.name.toUpperCase(Locale.ROOT).contains(u)) out.add(addr(r.entry)+" "+r.name); return out; }
    private List<String> markerMatches(List<MarkerHit> markers, String name) { List<String> out=new ArrayList<>(); for (MarkerHit h:markers) if (h.marker.equalsIgnoreCase(name)) out.add(addr(h.address)+" ("+h.encoding+")"); return out; }

    private String preflightMarkdown(Preflight preflight) {
        StringBuilder b = new StringBuilder();
        b.append("# Import and architecture preflight\n\n");
        b.append("- Overall status: **").append(preflight.overallStatus).append("**\n");
        b.append("- Automation allowed: `").append(preflight.automationAllowed).append("`\n");
        b.append("- Language: `").append(preflight.language).append("`\n");
        b.append("- Format: `").append(preflight.format).append("`\n");
        b.append("- Image base: `").append(preflight.imageBase).append("`\n");
        b.append("- High-confidence CODESYS candidates: `")
            .append(preflight.highConfidenceCandidates).append("`\n\n");

        b.append("| Result | Check | Recommendation |\n");
        b.append("|---|---|---|\n");

        for (PreflightCheck check : preflight.checks) {
            b.append("| ").append(check.passed ? "PASS" : "FAIL").append(" | ")
                .append(md(check.description)).append(" | ")
                .append(md(check.recommendation)).append(" |\n");
        }

        return b.toString();
    }

    private String variablesCsv(List<VariableRecord> variables) {
        StringBuilder b = new StringBuilder(
            "address,symbol,memory_block,data_type,representation,role,confidence," +
            "readers,writers,core_readers,core_writers,reference_types,reference_count\n"
        );

        for (VariableRecord variable : variables) {
            b.append(csv(addr(variable.address))).append(',');
            b.append(csv(variable.symbol)).append(',');
            b.append(csv(variable.memoryBlock)).append(',');
            b.append(csv(variable.dataType)).append(',');
            b.append(csv(variable.representation)).append(',');
            b.append(csv(variable.role)).append(',');
            b.append(variable.confidence).append(',');
            b.append(csv(join(variable.readers, " | "))).append(',');
            b.append(csv(join(variable.writers, " | "))).append(',');
            b.append(csv(join(variable.coreReaders, " | "))).append(',');
            b.append(csv(join(variable.coreWriters, " | "))).append(',');
            b.append(csv(join(variable.referenceTypes, " | "))).append(',');
            b.append(variable.referenceCount).append('\n');
        }

        return b.toString();
    }

    private String literalsCsv(List<LiteralRecord> literals) {
        StringBuilder b = new StringBuilder(
            "address,raw_hex,float_value,confidence,description," +
            "referencing_functions,reference_sites,mnemonics\n"
        );

        for (LiteralRecord literal : literals) {
            b.append(csv(addr(literal.address))).append(',');
            b.append(csv(literal.rawHex)).append(',');
            b.append(csv(String.valueOf(literal.floatValue))).append(',');
            b.append(literal.confidence).append(',');
            b.append(csv(literal.description)).append(',');
            b.append(csv(join(literal.referencingFunctions, " | "))).append(',');
            b.append(csv(join(literal.referenceSites, " | "))).append(',');
            b.append(csv(join(literal.mnemonics, " | "))).append('\n');
        }

        return b.toString();
    }

    private String fingerprintsCsv(AnalysisModel model) {
        StringBuilder b = new StringBuilder(
            "entry,function,instructions,fingerprint,probable_core,features\n"
        );

        for (FunctionRecord record : model.functions) {
            b.append(csv(addr(record.entry))).append(',');
            b.append(csv(record.name)).append(',');
            b.append(record.instructions).append(',');
            b.append(csv(record.fingerprint)).append(',');
            b.append(record.core).append(',');
            b.append(csv(join(record.features, " | "))).append('\n');
        }

        return b.toString();
    }

    private String duplicateGroupsMarkdown(List<FingerprintGroup> groups) {
        StringBuilder b = new StringBuilder();
        b.append("# Duplicate normalized-function groups\n\n");
        b.append(
            "These are exact matches of normalized instruction sequences within " +
            "the currently open binary. They may indicate wrappers, repeated library " +
            "helpers, or compiler-generated duplicates.\n\n"
        );

        if (groups.isEmpty()) {
            b.append("- No duplicate normalized functions were found.\n");
            return b.toString();
        }

        int index = 1;
        for (FingerprintGroup group : groups) {
            b.append("## Group ").append(index++).append("\n\n");
            b.append("- Fingerprint: `").append(group.fingerprint).append("`\n");
            for (FunctionRecord function : group.functions) {
                b.append("- `").append(addr(function.entry)).append("` ")
                    .append(function.name).append("\n");
            }
            b.append("\n");
        }

        return b.toString();
    }

    private String sourceMatchesCsv(List<SourceMatch> matches) {
        StringBuilder b = new StringBuilder(
            "source_type,source_name,function_entry,function_name,confidence," +
            "unique_high_confidence,reasons\n"
        );

        for (SourceMatch match : matches) {
            b.append(csv(match.pou.type)).append(',');
            b.append(csv(match.pou.name)).append(',');
            b.append(csv(match.function == null ? "" : addr(match.function.entry))).append(',');
            b.append(csv(match.function == null ? "" : match.function.name)).append(',');
            b.append(match.confidence).append(',');
            b.append(match.uniqueHighConfidence).append(',');
            b.append(csv(join(match.reasons, " | "))).append('\n');
        }

        return b.toString();
    }

    private String sourceTasksMarkdown() {
        StringBuilder b = new StringBuilder();
        b.append("# Structured Text task and program configuration\n\n");

        if (source.tasks.isEmpty() && source.bindings.isEmpty()) {
            b.append("- No task configuration was recognized.\n");
            return b.toString();
        }

        b.append("## Tasks\n\n");
        b.append("| Name | Interval | Priority | Raw parameters |\n");
        b.append("|---|---|---|---|\n");

        for (TaskInfo task : source.tasks) {
            b.append("| `").append(md(task.name)).append("` | `")
                .append(md(task.interval)).append("` | `")
                .append(md(task.priority)).append("` | `")
                .append(md(task.parameters)).append("` |\n");
        }

        b.append("\n## Program bindings\n\n");
        b.append("| Instance | Task | Program type |\n");
        b.append("|---|---|---|\n");

        for (ProgramBinding binding : source.bindings) {
            b.append("| `").append(md(binding.instance)).append("` | `")
                .append(md(binding.task)).append("` | `")
                .append(md(binding.programType)).append("` |\n");
        }

        return b.toString();
    }

    private String metadataMatchMarkdown() {
        StringBuilder b = new StringBuilder();
        b.append("# PLC-BEAD metadata match\n\n");
        b.append("- Metadata file: `")
            .append(metadataMatch.file.getAbsolutePath())
            .append("`\n\n");

        b.append("| Field | Value |\n");
        b.append("|---|---|\n");
        for (Map.Entry<String, String> entry : metadataMatch.values.entrySet()) {
            b.append("| ").append(md(entry.getKey())).append(" | ")
                .append(md(entry.getValue())).append(" |\n");
        }

        return b.toString();
    }

    private String htmlReport(
        AnalysisModel model,
        Preflight preflight,
        List<SourceMatch> sourceMatches,
        List<VariableRecord> variables,
        List<LiteralRecord> literals
    ) {
        StringBuilder b = new StringBuilder();
        b.append("<!doctype html><html><head><meta charset='utf-8'>");
        b.append("<title>PLC Program Plus Report</title>");
        b.append("<style>");
        b.append("body{font-family:Arial,sans-serif;max-width:1200px;margin:30px auto;padding:0 20px;}");
        b.append("table{border-collapse:collapse;width:100%;margin:12px 0 28px;}");
        b.append("th,td{border:1px solid #ccc;padding:7px;text-align:left;vertical-align:top;}");
        b.append("th{background:#eee;}code{background:#f2f2f2;padding:2px 4px;}");
        b.append(".pass{font-weight:bold}.warn{font-weight:bold}");
        b.append("</style></head><body>");
        b.append("<h1>PLC Program Plus Report</h1>");
        b.append("<p><b>Program:</b> ").append(html(currentProgram.getName())).append("<br>");
        b.append("<b>Toolchain:</b> ").append(html(detection.toolchain.label)).append("<br>");
        b.append("<b>Preflight:</b> ").append(html(preflight.overallStatus)).append("</p>");

        b.append("<h2>Preflight checks</h2><table><tr><th>Result</th><th>Check</th></tr>");
        for (PreflightCheck check : preflight.checks) {
            b.append("<tr><td>").append(check.passed ? "PASS" : "FAIL")
                .append("</td><td>").append(html(check.description)).append("</td></tr>");
        }
        b.append("</table>");

        b.append("<h2>Likely control functions</h2><table>");
        b.append("<tr><th>Address</th><th>Name</th><th>Confidence</th><th>Reasons</th></tr>");
        for (FunctionRecord record : model.functions) {
            if (!record.core) continue;
            b.append("<tr><td><code>").append(html(addr(record.entry))).append("</code></td>");
            b.append("<td>").append(html(record.name)).append("</td>");
            b.append("<td>").append(record.coreConfidence).append("%</td>");
            b.append("<td>").append(html(join(record.coreReasons, "; "))).append("</td></tr>");
        }
        b.append("</table>");

        b.append("<h2>Top source candidates</h2><table>");
        b.append("<tr><th>Source</th><th>Function</th><th>Confidence</th><th>Evidence</th></tr>");
        int shown = 0;
        for (SourceMatch match : sourceMatches) {
            if (shown++ >= 20) break;
            b.append("<tr><td>").append(html(match.pou.type + " " + match.pou.name)).append("</td>");
            b.append("<td>").append(html(match.function == null ? "" : match.function.name)).append("</td>");
            b.append("<td>").append(match.confidence).append("%</td>");
            b.append("<td>").append(html(join(match.reasons, "; "))).append("</td></tr>");
        }
        b.append("</table>");

        b.append("<h2>Data-access summary</h2><p>")
            .append(variables.size()).append(" referenced data addresses; ")
            .append(literals.size()).append(" probable literal-pool entries.</p>");

        b.append("<h2>Warnings</h2><ul>");
        if (warnings.isEmpty()) b.append("<li>None recorded.</li>");
        else for (String warning : warnings) b.append("<li>").append(html(warning)).append("</li>");
        b.append("</ul></body></html>");
        return b.toString();
    }

    private String html(String value) {
        return safe(value)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;");
    }

    // ------------------------------------------------------------------
    // Complete program assembly export
    // ------------------------------------------------------------------

    private void exportCompleteProgramAssembly(
        File out,
        AnalysisModel model,
        List<CodesysCandidate> candidates
    ) throws IOException {
        File root = new File(out, "program_assembly");
        File blocksDirectory = new File(root, "memory_blocks");
        File candidatesDirectory =
            new File(root, "candidate_pseudo_disassembly");

        if (!root.exists() && !root.mkdirs()) {
            warnings.add("Could not create program_assembly directory.");
            return;
        }

        if (!blocksDirectory.exists() && !blocksDirectory.mkdirs()) {
            warnings.add("Could not create program_assembly/memory_blocks.");
            return;
        }

        if (!candidatesDirectory.exists() &&
            !candidatesDirectory.mkdirs()) {
            warnings.add(
                "Could not create candidate_pseudo_disassembly directory."
            );
            return;
        }

        List<UndefinedRegion> undefinedRegions = new ArrayList<>();

        File fullListing =
            new File(root, "full_analyzed_assembly.asm");

        try (BufferedWriter complete =
            new BufferedWriter(new FileWriter(fullListing))) {

            writeAssemblyFileHeader(complete);

            MemoryBlock[] blocks =
                currentProgram.getMemory().getBlocks();

            for (int index = 0;
                index < blocks.length &&
                !monitor.isCancelled();
                index++) {

                MemoryBlock block = blocks[index];

                if (!block.isInitialized()) {
                    continue;
                }

                String blockFileName =
                    String.format(
                        Locale.ROOT,
                        "%03d_%s_%s.asm",
                        index,
                        safeFile(block.getName()),
                        addressSuffix(block.getStart())
                    );

                File blockFile =
                    new File(blocksDirectory, blockFileName);

                try (BufferedWriter blockWriter =
                    new BufferedWriter(new FileWriter(blockFile))) {

                    writeBlockHeader(complete, block, blockFileName);
                    writeBlockHeader(blockWriter, block, blockFileName);

                    exportMemoryBlockListing(
                        block,
                        complete,
                        blockWriter,
                        undefinedRegions
                    );
                }
            }
        }

        write(
            new File(root, "function_map.csv"),
            fullFunctionMapCsv(model)
        );

        write(
            new File(root, "undefined_regions.csv"),
            undefinedRegionsCsv(undefinedRegions)
        );

        exportCandidatePseudoDisassembly(
            candidatesDirectory,
            root,
            candidates
        );

        write(
            new File(root, "README.md"),
            completeAssemblyReadme(undefinedRegions, candidates)
        );
    }

    private void writeAssemblyFileHeader(
        BufferedWriter writer
    ) throws IOException {
        writer.write("; Complete analyzed assembly listing\n");
        writer.write("; Program: " + currentProgram.getName() + "\n");
        writer.write(
            "; Format: " +
            safe(currentProgram.getExecutableFormat()) +
            "\n"
        );
        writer.write(
            "; Language: " +
            currentProgram.getLanguageID() +
            "\n"
        );
        writer.write(
            "; Compiler: " +
            safe(currentProgram.getCompiler()) +
            "\n"
        );
        writer.write(
            "; Image base: " +
            addr(currentProgram.getImageBase()) +
            "\n"
        );
        writer.write(
            "; Generated by AnalyzePLCProgramPlusV2 version " +
            VERSION +
            "\n"
        );
        writer.write(
            "; Only instructions already recognized by Ghidra are " +
            "presented as confirmed assembly.\n"
        );
        writer.write(
            "; Undefined areas are marked as ranges with a short byte " +
            "preview and are not treated as instructions.\n\n"
        );
    }

    private void writeBlockHeader(
        BufferedWriter writer,
        MemoryBlock block,
        String blockFileName
    ) throws IOException {
        writer.write("\n");
        writer.write(
            "; ============================================================\n"
        );
        writer.write("; MEMORY BLOCK: " + block.getName() + "\n");
        writer.write("; File: " + blockFileName + "\n");
        writer.write(
            "; Range: " +
            addr(block.getStart()) +
            " - " +
            addr(block.getEnd()) +
            "\n"
        );
        writer.write("; Size: " + block.getSize() + " bytes\n");
        writer.write(
            "; Permissions: " +
            (block.isRead() ? "R" : "-") +
            (block.isWrite() ? "W" : "-") +
            (block.isExecute() ? "X" : "-") +
            "\n"
        );
        writer.write(
            "; ============================================================\n\n"
        );
    }

    private void exportMemoryBlockListing(
        MemoryBlock block,
        BufferedWriter complete,
        BufferedWriter blockWriter,
        List<UndefinedRegion> undefinedRegions
    ) throws IOException {
        Listing listing = currentProgram.getListing();

        CodeUnitIterator units =
            listing.getCodeUnits(block.getStart(), true);

        Address cursor = block.getStart();

        while (units.hasNext() && !monitor.isCancelled()) {
            CodeUnit unit = units.next();

            if (unit.getMinAddress().compareTo(block.getEnd()) > 0) {
                break;
            }

            if (unit.getMaxAddress().compareTo(block.getStart()) < 0) {
                continue;
            }

            if (cursor != null &&
                cursor.compareTo(unit.getMinAddress()) < 0) {

                Address undefinedEnd =
                    safePrevious(unit.getMinAddress());

                if (undefinedEnd != null &&
                    undefinedEnd.compareTo(cursor) >= 0) {

                    UndefinedRegion region =
                        createUndefinedRegion(
                            block,
                            cursor,
                            undefinedEnd
                        );

                    undefinedRegions.add(region);
                    writeUndefinedRegion(complete, region);
                    writeUndefinedRegion(blockWriter, region);
                }
            }

            if (unit instanceof Instruction) {
                writeInstructionUnit(
                    complete,
                    (Instruction) unit
                );
                writeInstructionUnit(
                    blockWriter,
                    (Instruction) unit
                );
            }
            else if (unit instanceof Data) {
                writeDataUnit(complete, (Data) unit);
                writeDataUnit(blockWriter, (Data) unit);
            }
            else {
                writeGenericCodeUnit(complete, unit);
                writeGenericCodeUnit(blockWriter, unit);
            }

            cursor = safeNext(unit.getMaxAddress());
        }

        if (cursor != null &&
            cursor.compareTo(block.getEnd()) <= 0) {

            UndefinedRegion region =
                createUndefinedRegion(
                    block,
                    cursor,
                    block.getEnd()
                );

            undefinedRegions.add(region);
            writeUndefinedRegion(complete, region);
            writeUndefinedRegion(blockWriter, region);
        }
    }

    private void writeInstructionUnit(
        BufferedWriter writer,
        Instruction instruction
    ) throws IOException {
        Address address = instruction.getAddress();
        Function function = getFunctionAt(address);

        if (function != null) {
            writer.write("\n");
            writer.write(
                "; ------------------------------------------------------------\n"
            );
            writer.write(
                "; FUNCTION " +
                function.getName() +
                " @ " +
                addr(address) +
                "\n"
            );
            writer.write(
                "; Prototype: " +
                safePrototype(function) +
                "\n"
            );
            writer.write(
                "; Body: " +
                addr(function.getBody().getMinAddress()) +
                " - " +
                addr(function.getBody().getMaxAddress()) +
                "\n"
            );
            writer.write(
                "; ------------------------------------------------------------\n"
            );
        }

        Symbol primary =
            currentProgram.getSymbolTable()
                .getPrimarySymbol(address);

        if (primary != null &&
            (function == null ||
             !primary.getName().equals(function.getName()))) {

            writer.write(primary.getName(true) + ":\n");
        }

        writeCommentLines(
            writer,
            getPlateComment(address),
            "; PLATE: "
        );

        writeCommentLines(
            writer,
            getPreComment(address),
            "; PRE: "
        );

        String references = referencesFromText(address);
        String eol = flattenComment(getEOLComment(address));

        writer.write(
            addr(address) +
            "  " +
            pad(bytesHex(instruction), 32) +
            "  " +
            instruction.toString()
        );

        if (!references.isEmpty()) {
            writer.write("  ; refs: " + references);
        }

        if (!eol.isEmpty()) {
            writer.write("  ; " + eol);
        }

        writer.write("\n");

        writeCommentLines(
            writer,
            getPostComment(address),
            "; POST: "
        );
    }

    private void writeDataUnit(
        BufferedWriter writer,
        Data data
    ) throws IOException {
        Address address = data.getAddress();

        Symbol primary =
            currentProgram.getSymbolTable()
                .getPrimarySymbol(address);

        if (primary != null) {
            writer.write(primary.getName(true) + ":\n");
        }

        writeCommentLines(
            writer,
            getPlateComment(address),
            "; PLATE: "
        );

        String representation = "";
        String typeName = "";

        try {
            representation =
                data.getDefaultValueRepresentation();
        }
        catch (Exception ignored) {
        }

        try {
            typeName = data.getDataType().getName();
        }
        catch (Exception ignored) {
        }

        writer.write(
            addr(address) +
            "  " +
            pad(bytesHex(data), 32) +
            "  .data " +
            typeName
        );

        if (!representation.isEmpty()) {
            writer.write(
                "  ; " +
                flattenComment(representation)
            );
        }

        writer.write("\n");
    }

    private void writeGenericCodeUnit(
        BufferedWriter writer,
        CodeUnit unit
    ) throws IOException {
        writer.write(
            addr(unit.getMinAddress()) +
            "  " +
            pad(bytesHex(unit), 32) +
            "  ; " +
            unit.toString() +
            "\n"
        );
    }

    private UndefinedRegion createUndefinedRegion(
        MemoryBlock block,
        Address start,
        Address end
    ) {
        UndefinedRegion region = new UndefinedRegion();

        region.block = block.getName();
        region.start = start;
        region.end = end;

        try {
            region.length = end.subtract(start) + 1L;
        }
        catch (Exception e) {
            region.length = 0;
        }

        region.preview =
            memoryPreview(
                start,
                end,
                UNDEFINED_PREVIEW_BYTES
            );

        return region;
    }

    private void writeUndefinedRegion(
        BufferedWriter writer,
        UndefinedRegion region
    ) throws IOException {
        writer.write("\n");
        writer.write(
            "; [UNDEFINED] " +
            addr(region.start) +
            " - " +
            addr(region.end) +
            " (" +
            region.length +
            " bytes)\n"
        );

        if (!region.preview.isEmpty()) {
            writer.write(
                "; Byte preview: " +
                region.preview +
                "\n"
            );
        }

        writer.write(
            "; Review candidate pseudo-disassembly before " +
            "treating this range as code.\n\n"
        );
    }

    private String memoryPreview(
        Address start,
        Address end,
        int maximumBytes
    ) {
        long available;

        try {
            available = end.subtract(start) + 1L;
        }
        catch (Exception e) {
            return "";
        }

        int count =
            (int) Math.min(
                Math.max(0L, available),
                (long) maximumBytes
            );

        if (count <= 0) {
            return "";
        }

        byte[] bytes = new byte[count];

        try {
            int read =
                currentProgram.getMemory()
                    .getBytes(
                        start,
                        bytes,
                        0,
                        count
                    );

            StringBuilder output = new StringBuilder();

            for (int index = 0;
                index < read;
                index++) {

                if (index > 0) {
                    output.append(' ');
                }

                output.append(
                    String.format(
                        Locale.ROOT,
                        "%02X",
                        bytes[index] & 0xff
                    )
                );
            }

            if (available > read) {
                output.append(" ...");
            }

            return output.toString();
        }
        catch (Exception e) {
            return "";
        }
    }

    private String referencesFromText(Address address) {
        Reference[] references =
            currentProgram.getReferenceManager()
                .getReferencesFrom(address);

        List<String> values = new ArrayList<>();

        for (Reference reference : references) {
            Address destination = reference.getToAddress();

            if (destination == null) {
                continue;
            }

            Function target =
                getFunctionContaining(destination);

            String targetText =
                target == null
                    ? addr(destination)
                    : target.getName() +
                        "@" +
                        addr(destination);

            values.add(
                reference.getReferenceType() +
                "->" +
                targetText
            );
        }

        return join(values, ", ");
    }

    private void writeCommentLines(
        BufferedWriter writer,
        String comment,
        String prefix
    ) throws IOException {
        if (comment == null || comment.trim().isEmpty()) {
            return;
        }

        for (String line : comment.split("\\r?\\n")) {
            writer.write(prefix + line + "\n");
        }
    }

    private String flattenComment(String value) {
        return safe(value)
            .replace('\r', ' ')
            .replace('\n', ' ')
            .trim();
    }

    private String fullFunctionMapCsv(
        AnalysisModel model
    ) {
        StringBuilder output = new StringBuilder();

        output.append(
            "entry,name,prototype,body_start,body_end,instructions," +
            "xrefs,calls_out,indirect_calls,probable_core," +
            "core_confidence,features,fingerprint\n"
        );

        for (FunctionRecord record : model.functions) {
            output.append(csv(addr(record.entry))).append(',');
            output.append(csv(record.name)).append(',');
            output.append(csv(record.prototype)).append(',');
            output.append(
                csv(
                    addr(
                        record.function.getBody()
                            .getMinAddress()
                    )
                )
            ).append(',');
            output.append(
                csv(
                    addr(
                        record.function.getBody()
                            .getMaxAddress()
                    )
                )
            ).append(',');
            output.append(record.instructions).append(',');
            output.append(record.xrefs).append(',');
            output.append(record.callsOut).append(',');
            output.append(record.indirectCount).append(',');
            output.append(record.core).append(',');
            output.append(record.coreConfidence).append(',');
            output.append(
                csv(join(record.features, " | "))
            ).append(',');
            output.append(csv(record.fingerprint)).append('\n');
        }

        return output.toString();
    }

    private String undefinedRegionsCsv(
        List<UndefinedRegion> regions
    ) {
        StringBuilder output = new StringBuilder();

        output.append(
            "memory_block,start,end,length,byte_preview\n"
        );

        for (UndefinedRegion region : regions) {
            output.append(csv(region.block)).append(',');
            output.append(csv(addr(region.start))).append(',');
            output.append(csv(addr(region.end))).append(',');
            output.append(region.length).append(',');
            output.append(csv(region.preview)).append('\n');
        }

        return output.toString();
    }

    private void exportCandidatePseudoDisassembly(
        File candidatesDirectory,
        File root,
        List<CodesysCandidate> candidates
    ) throws IOException {
        StringBuilder index = new StringBuilder();

        index.append(
            "address,confidence,status,existing_function," +
            "return_address,file,reasons\n"
        );

        File combined =
            new File(
                root,
                "all_candidate_pseudo_disassembly.asm"
            );

        try (BufferedWriter combinedWriter =
            new BufferedWriter(new FileWriter(combined))) {

            combinedWriter.write(
                "; Non-destructive pseudo-disassembly for every " +
                "CODESYS candidate.\n"
            );
            combinedWriter.write(
                "; These regions may not be real functions. Verify " +
                "boundaries manually.\n\n"
            );

            for (int candidateNumber = 0;
                candidateNumber < candidates.size() &&
                !monitor.isCancelled();
                candidateNumber++) {

                CodesysCandidate candidate =
                    candidates.get(candidateNumber);

                String fileName =
                    String.format(
                        Locale.ROOT,
                        "%04d_conf_%03d_%s.asm",
                        candidateNumber + 1,
                        candidate.confidence,
                        addressSuffix(candidate.address)
                    );

                File candidateFile =
                    new File(candidatesDirectory, fileName);

                String pseudo =
                    candidatePseudoDisassembly(candidate);

                write(candidateFile, pseudo);
                combinedWriter.write(pseudo);
                combinedWriter.write("\n\n");

                index.append(
                    csv(addr(candidate.address))
                ).append(',');
                index.append(candidate.confidence).append(',');
                index.append(csv(candidate.status)).append(',');
                index.append(candidate.existing).append(',');
                index.append(
                    csv(addr(candidate.returnAddress))
                ).append(',');
                index.append(
                    csv(
                        "candidate_pseudo_disassembly/" +
                        fileName
                    )
                ).append(',');
                index.append(
                    csv(join(candidate.reasons, " | "))
                ).append('\n');
            }
        }

        write(
            new File(root, "candidate_index.csv"),
            index.toString()
        );
    }

    private String candidatePseudoDisassembly(
        CodesysCandidate candidate
    ) {
        StringBuilder output = new StringBuilder();

        output.append(
            "; ============================================================\n"
        );
        output.append("; CODESYS FUNCTION CANDIDATE\n");
        output.append(
            "; Address: " +
            addr(candidate.address) +
            "\n"
        );
        output.append(
            "; Confidence: " +
            candidate.confidence +
            "%\n"
        );
        output.append(
            "; Recovery status: " +
            candidate.status +
            "\n"
        );
        output.append(
            "; Existing function: " +
            candidate.existing +
            "\n"
        );
        output.append(
            "; Recognized return: " +
            addr(candidate.returnAddress) +
            "\n"
        );
        output.append(
            "; Reasons: " +
            join(candidate.reasons, "; ") +
            "\n"
        );
        output.append(
            "; This is speculative pseudo-disassembly and may cross " +
            "into data or adjacent code.\n"
        );
        output.append(
            "; ============================================================\n\n"
        );

        PseudoDisassembler pseudo =
            new PseudoDisassembler(currentProgram);

        pseudo.setMaxInstructions(
            PSEUDO_ASSEMBLY_MAX_INSTRUCTIONS
        );

        Address cursor = candidate.address;
        Address maximumAddress = null;

        try {
            maximumAddress =
                candidate.address.add(
                    PSEUDO_ASSEMBLY_MAX_BYTES
                );
        }
        catch (Exception ignored) {
        }

        int instructionCount = 0;

        while (cursor != null &&
            instructionCount <
                PSEUDO_ASSEMBLY_MAX_INSTRUCTIONS &&
            !monitor.isCancelled()) {

            if (maximumAddress != null &&
                cursor.compareTo(maximumAddress) > 0) {
                output.append(
                    "\n; Stopped at pseudo-disassembly byte limit.\n"
                );
                break;
            }

            Data definedData =
                currentProgram.getListing()
                    .getDefinedDataContaining(cursor);

            if (definedData != null &&
                cursor.equals(definedData.getMinAddress())) {

                output.append(
                    "\n; Stopped at defined data " +
                    addr(cursor) +
                    " (" +
                    definedData.getDataType().getName() +
                    ").\n"
                );
                break;
            }

            PseudoInstruction instruction;

            try {
                instruction = pseudo.disassemble(cursor);
            }
            catch (Exception e) {
                instruction = null;
            }

            if (instruction == null ||
                instruction.getLength() <= 0) {

                output.append(
                    "\n; Pseudo-disassembly failed at " +
                    addr(cursor) +
                    ".\n"
                );
                break;
            }

            output.append(
                addr(instruction.getAddress())
            ).append("  ");
            output.append(
                pad(bytesHex(instruction), 32)
            ).append("  ");
            output.append(
                instruction.toString()
            ).append('\n');

            instructionCount++;

            if (candidate.returnAddress != null &&
                instruction.getAddress()
                    .compareTo(candidate.returnAddress) >= 0) {

                output.append(
                    "\n; Stopped after the candidate's recognized return.\n"
                );
                break;
            }

            try {
                cursor =
                    instruction.getAddress()
                        .add(instruction.getLength());
            }
            catch (Exception e) {
                cursor = null;
            }
        }

        if (instructionCount >=
            PSEUDO_ASSEMBLY_MAX_INSTRUCTIONS) {

            output.append(
                "\n; Stopped at pseudo-disassembly instruction limit.\n"
            );
        }

        return output.toString();
    }

    private String completeAssemblyReadme(
        List<UndefinedRegion> undefinedRegions,
        List<CodesysCandidate> candidates
    ) {
        return "# Complete program assembly export\n\n" +
            "This directory gives Codex and human reviewers access to the " +
            "entire analyzed program, not only functions classified as PLC " +
            "core logic.\n\n" +
            "## Files\n\n" +
            "- `full_analyzed_assembly.asm` — monolithic listing of every " +
            "instruction and defined data item recognized by Ghidra.\n" +
            "- `memory_blocks/` — the same analyzed listing separated by " +
            "memory block for easier targeted reading.\n" +
            "- `function_map.csv` — every function known to Ghidra with " +
            "boundaries, scores, features, and fingerprints.\n" +
            "- `undefined_regions.csv` — gaps not currently interpreted as " +
            "instructions or defined data.\n" +
            "- `candidate_index.csv` — every CODESYS prologue candidate, " +
            "including low-confidence and rejected candidates.\n" +
            "- `all_candidate_pseudo_disassembly.asm` — combined speculative " +
            "disassembly of all candidates.\n" +
            "- `candidate_pseudo_disassembly/` — one speculative assembly " +
            "file per candidate.\n\n" +
            "## How to use this with Codex\n\n" +
            "Start with `function_map.csv` and `candidate_index.csv`. Search " +
            "`full_analyzed_assembly.asm` for important addresses, constants, " +
            "calls, and metadata references. For a low-confidence function, " +
            "open its file in `candidate_pseudo_disassembly/` and compare it " +
            "against nearby confirmed functions and Structured Text source.\n\n" +
            "## Important distinction\n\n" +
            "`full_analyzed_assembly.asm` contains confirmed Ghidra listing " +
            "items. Candidate pseudo-disassembly is non-destructive and " +
            "speculative: it may cross data, literal pools, or another " +
            "function. It is supplied to help propose addresses for manual " +
            "review, not to assert that every candidate is a real function.\n\n" +
            "Undefined regions recorded: `" +
            undefinedRegions.size() +
            "`.\n\n" +
            "CODESYS candidates exported: `" +
            candidates.size() +
            "`.\n";
    }

    private String bytesHex(CodeUnit unit) {
        int length = unit.getLength();

        if (length <= 0) {
            return "";
        }

        byte[] bytes = new byte[length];

        try {
            int read =
                currentProgram.getMemory()
                    .getBytes(
                        unit.getMinAddress(),
                        bytes,
                        0,
                        length
                    );

            StringBuilder output = new StringBuilder();

            for (int index = 0;
                index < read;
                index++) {

                if (index > 0) {
                    output.append(' ');
                }

                output.append(
                    String.format(
                        Locale.ROOT,
                        "%02X",
                        bytes[index] & 0xff
                    )
                );
            }

            return output.toString();
        }
        catch (Exception e) {
            return "";
        }
    }

    private Address safeNext(Address address) {
        try {
            return address.next();
        }
        catch (Exception e) {
            return null;
        }
    }

    private Address safePrevious(Address address) {
        try {
            return address.previous();
        }
        catch (Exception e) {
            return null;
        }
    }

    private String codexPrompt() {
        return "Read AGENTS.md first, then analyze this PLC Ghidra export.\n\n" +
            "Start with preflight.md, plc_analysis_summary.md, ANALYSIS_WARNINGS.md, " +
            "core_functions.md, source_crosswalk.md if present, function_inventory.csv, " +
            "and source_function_candidates.csv if present.\n\n" +
            "Then read program_assembly/README.md. Use " +
            "program_assembly/full_analyzed_assembly.asm as the complete listing of " +
            "everything Ghidra actually disassembled. Use the per-memory-block files " +
            "when the monolithic listing is too large. Review " +
            "program_assembly/candidate_pseudo_disassembly/ and candidate_index.csv " +
            "to investigate low-confidence CODESYS function entries that were not " +
            "created as functions. These candidate files are speculative and may run " +
            "into data or adjacent code.\n\n" +
            "Use variable_access.csv, literal_pools.csv, metadata_strings.csv, " +
            "call_edges.csv, and indirect_calls.csv as supporting evidence. Identify " +
            "possible missing function boundaries and explain which addresses should " +
            "be reviewed manually in Ghidra. Separate probable PLC control logic from " +
            "runtime/support code, compare candidates against Structured Text source, " +
            "and treat unresolved indirect calls as provisional. Raw assembly is " +
            "stronger evidence than decompiled C. Do not modify or patch binaries.\n";
    }

    private String warningsReport() {
        StringBuilder b=new StringBuilder("# Analysis warnings and truncation notes\n\n## Warnings\n\n");
        if (warnings.isEmpty()) b.append("- None recorded.\n"); else for (String x:warnings) b.append("- ").append(x).append('\n');
        b.append("\n## Truncation notes\n\n"); if (truncations.isEmpty()) b.append("- None recorded.\n"); else for (String x:truncations) b.append("- ").append(x).append('\n');
        return b.toString();
    }

    private String listReport(String title, List<String> items) { StringBuilder b=new StringBuilder("# "+title+"\n\n"); if (items.isEmpty()) b.append("- None.\n"); else for (String x:items) b.append("- ").append(x).append('\n'); return b.toString(); }

    // ------------------------------------------------------------------
    // Per-core-function details
    // ------------------------------------------------------------------

    private void exportCoreDetails(
        File out,
        AnalysisModel model,
        List<SourceMatch> sourceMatches
    ) throws IOException {
        File root = new File(out, "core_function_details");

        if (!root.exists() && !root.mkdirs()) {
            warnings.add("Could not create core_function_details.");
            return;
        }

        List<DetailSelection> selections =
            selectFunctionsForDetailedExport(model, sourceMatches);

        write(
            new File(root, "SELECTION_README.md"),
            detailSelectionReadme(selections)
        );

        if (selections.isEmpty()) {
            warnings.add(
                "No functions qualified for detailed export. " +
                "Review function_inventory.csv and source_function_candidates.csv."
            );
            return;
        }

        DecompInterface decompiler = new DecompInterface();

        try {
            DecompileOptions options = new DecompileOptions();

            try {
                options.grabFromProgram(currentProgram);
            }
            catch (Exception ignored) {
            }

            decompiler.setOptions(options);
            decompiler.openProgram(currentProgram);

            for (DetailSelection selection : selections) {
                if (monitor.isCancelled()) {
                    break;
                }

                FunctionRecord record = selection.function;
                File directory = new File(
                    root,
                    safeFile(addr(record.entry) + "_" + record.name)
                );

                if (!directory.exists() && !directory.mkdirs()) {
                    warnings.add(
                        "Could not create detail folder for " + record.name
                    );
                    continue;
                }

                write(
                    new File(directory, "selection.md"),
                    detailSelectionMarkdown(selection)
                );
                write(
                    new File(directory, "metadata.md"),
                    functionMetadata(record)
                );
                write(
                    new File(directory, "decompile.c"),
                    decompile(record.function, decompiler)
                );
                write(
                    new File(directory, "assembly.asm"),
                    assembly(record.function)
                );
                write(
                    new File(directory, "normalized.txt"),
                    normalizedText(record)
                );
                write(
                    new File(directory, "calls.md"),
                    callsText(record)
                );
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

    private List<DetailSelection> selectFunctionsForDetailedExport(
        AnalysisModel model,
        List<SourceMatch> sourceMatches
    ) {
        LinkedHashMap<String, DetailSelection> selected =
            new LinkedHashMap<>();

        // Confirmed or strongly classified control functions always qualify.
        for (FunctionRecord record : model.functions) {
            if (!record.core || record.external) {
                continue;
            }

            DetailSelection selection = new DetailSelection();
            selection.function = record;
            selection.category = "probable_core";
            selection.confidence = Math.max(record.coreConfidence, 75);
            selection.reasons.addAll(record.coreReasons);

            selected.put(addr(record.entry), selection);
        }

        // Detailed exports are report-only and do not alter Ghidra. Therefore,
        // a lower threshold is appropriate than the annotation/function-creation
        // threshold. Each POU contributes its best candidate.
        Map<String, SourceMatch> bestByPou =
            new LinkedHashMap<>();

        for (SourceMatch match : sourceMatches) {
            if (match.function == null ||
                match.function.external ||
                match.function.thunk) {
                continue;
            }

            String key =
                match.pou.type + ":" +
                match.pou.name.toUpperCase(Locale.ROOT);

            SourceMatch current = bestByPou.get(key);
            if (current == null ||
                match.confidence > current.confidence) {
                bestByPou.put(key, match);
            }
        }

        int reportThreshold =
            Math.max(45, settings.minConfidence - 30);

        for (SourceMatch match : bestByPou.values()) {
            if (match.confidence < reportThreshold) {
                continue;
            }

            String entry = addr(match.function.entry);
            DetailSelection existing = selected.get(entry);

            if (existing == null) {
                DetailSelection selection = new DetailSelection();
                selection.function = match.function;
                selection.category =
                    match.uniqueHighConfidence
                        ? "high_confidence_source_match"
                        : "report_only_source_candidate";
                selection.confidence = match.confidence;
                selection.reasons.add(
                    "Best binary candidate for source " +
                    match.pou.type + " " + match.pou.name
                );
                selection.reasons.addAll(match.reasons);
                selected.put(entry, selection);
            }
            else {
                existing.confidence =
                    Math.max(existing.confidence, match.confidence);
                existing.reasons.add(
                    "Also matched source " +
                    match.pou.type + " " + match.pou.name
                );
            }
        }

        // Deep Report intentionally includes more report-only candidates.
        if ("Deep Report".equals(settings.profile)) {
            int added = 0;

            for (SourceMatch match : sourceMatches) {
                if (added >= 20) {
                    break;
                }

                if (match.function == null ||
                    match.function.external ||
                    match.confidence < 35) {
                    continue;
                }

                String entry = addr(match.function.entry);
                if (selected.containsKey(entry)) {
                    continue;
                }

                DetailSelection selection = new DetailSelection();
                selection.function = match.function;
                selection.category = "deep_report_source_candidate";
                selection.confidence = match.confidence;
                selection.reasons.add(
                    "Additional Deep Report source candidate for " +
                    match.pou.type + " " + match.pou.name
                );
                selection.reasons.addAll(match.reasons);
                selected.put(entry, selection);
                added++;
            }
        }

        // Final fallback: never leave the directory empty merely because the
        // compiler stripped names. Prefer functions with semantic operations,
        // indirect calls, or high ranking.
        int fallbackLimit =
            "Deep Report".equals(settings.profile) ? 20 : 8;

        if (selected.isEmpty()) {
            int added = 0;

            for (FunctionRecord record : model.functions) {
                if (added >= fallbackLimit) {
                    break;
                }

                if (record.external ||
                    record.thunk ||
                    record.instructions == 0) {
                    continue;
                }

                boolean interesting =
                    !record.semantic.isEmpty() ||
                    record.indirectCount > 0 ||
                    !record.features.isEmpty();

                if (!interesting && added >= 3) {
                    continue;
                }

                DetailSelection selection = new DetailSelection();
                selection.function = record;
                selection.category = "ranked_fallback_candidate";
                selection.confidence = Math.min(70, Math.max(35, record.score));
                selection.reasons.add(
                    "No confirmed core function was available; selected from ranked function inventory"
                );

                if (!record.features.isEmpty()) {
                    selection.reasons.add(
                        "Recovered features: " +
                        join(record.features, ", ")
                    );
                }

                selected.put(addr(record.entry), selection);
                added++;
            }
        }

        return new ArrayList<>(selected.values());
    }

    private String detailSelectionReadme(
        List<DetailSelection> selections
    ) {
        StringBuilder output = new StringBuilder();

        output.append("# Detailed-function selection\n\n");
        output.append(
            "This directory contains confirmed probable core functions and, " +
            "when needed, explicitly labeled report-only candidates. Exporting " +
            "a candidate does not rename it, annotate it, or assert that it is " +
            "the correct source function.\n\n"
        );

        output.append("| Entry | Function | Category | Confidence | Reasons |\n");
        output.append("|---|---|---|---:|---|\n");

        for (DetailSelection selection : selections) {
            output.append("| `")
                .append(addr(selection.function.entry))
                .append("` | `")
                .append(md(selection.function.name))
                .append("` | ")
                .append(md(selection.category))
                .append(" | ")
                .append(selection.confidence)
                .append("% | ")
                .append(md(join(selection.reasons, "; ")))
                .append(" |\n");
        }

        if (selections.isEmpty()) {
            output.append(
                "\nNo function met even the report-only selection criteria.\n"
            );
        }

        return output.toString();
    }

    private String detailSelectionMarkdown(
        DetailSelection selection
    ) {
        StringBuilder output = new StringBuilder();

        output.append("# Selection basis\n\n");
        output.append("- Category: `")
            .append(selection.category)
            .append("`\n");
        output.append("- Confidence: `")
            .append(selection.confidence)
            .append("%`\n");
        output.append("- Automatically confirmed as core: `")
            .append(selection.function.core)
            .append("`\n\n");

        output.append("## Reasons\n\n");
        for (String reason : selection.reasons) {
            output.append("- ").append(reason).append("\n");
        }

        output.append(
            "\nA report-only candidate must still be verified against assembly, " +
            "source operations, metadata, and call context.\n"
        );

        return output.toString();
    }

    private String functionMetadata(FunctionRecord r) {
        StringBuilder b=new StringBuilder("# Function metadata\n\n");
        b.append("- Name: `").append(r.name).append("`\n- Entry: `").append(addr(r.entry)).append("`\n- Prototype: `").append(r.prototype).append("`\n- Instructions: `").append(r.instructions).append("`\n- Xrefs: `").append(r.xrefs).append("`\n- Calls: `").append(r.callsOut).append("`\n- Indirect calls: `").append(r.indirectCount).append("`\n- Score: `").append(r.score).append("`\n- Core reasons: `").append(join(r.coreReasons,"; ")).append("`\n\n## Semantic hints\n\n");
        if (r.semantic.isEmpty()) b.append("- None.\n"); else for (String h:r.semantic) b.append("- `").append(h).append("`\n");
        return b.toString();
    }

    private String decompile(Function f, DecompInterface decompiler) {
        try {
            DecompileResults results=decompiler.decompileFunction(f,60,monitor);
            if (results==null) return "/* No decompiler result returned. */\n";
            if (!results.decompileCompleted()) return "/* Decompilation did not complete.\n"+results.getErrorMessage()+"\n*/\n";
            DecompiledFunction d=results.getDecompiledFunction(); return d==null?"/* No C output returned. */\n":d.getC();
        }
        catch (Exception e) { return "/* Decompiler error:\n"+e+"\n*/\n"; }
    }

    private String assembly(Function f) {
        StringBuilder b=new StringBuilder("; Function: "+f.getName()+"\n; Entry: "+addr(f.getEntryPoint())+"\n\n");
        InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true); int count=0;
        while (it.hasNext()&&!monitor.isCancelled()) {
            if (count>=settings.maxInstructions) { b.append("\n; Truncated at configured instruction limit.\n"); truncations.add("Assembly for "+f.getName()+" truncated at "+settings.maxInstructions+" instructions."); break; }
            Instruction ins=it.next(); b.append(addr(ins.getAddress())).append("  ").append(pad(bytesHex(ins),28)).append("  ").append(ins).append('\n'); count++;
        }
        return b.toString();
    }

    private String normalizedText(FunctionRecord r) { StringBuilder b=new StringBuilder(); for (Normalized n:r.normalized) b.append(addr(n.address)).append("  ").append(n.value).append('\n'); return b.toString(); }

    private String callsText(FunctionRecord r) {
        StringBuilder b=new StringBuilder("# Direct calls\n\n");
        if (r.calls.isEmpty()) b.append("- None recovered.\n"); else for (CallEdge e:r.calls) b.append("- `").append(addr(e.site)).append("` → `").append(e.toName.isEmpty()?addr(e.to):e.toName).append("`\n");
        b.append("\n# Indirect calls\n\n"); if (r.indirect.isEmpty()) b.append("- None recovered.\n"); else for (IndirectCall c:r.indirect) b.append("- `").append(addr(c.address)).append("` ").append(c.kind).append(": `").append(c.context).append("`\n");
        return b.toString();
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private int countReferencesTo(Address a) { int count=0; try { ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(a); while (it.hasNext()&&!monitor.isCancelled()) { it.next(); count++; } } catch (Exception ignored) {} return count; }
    private boolean isExternal(Function f) { try { return f.isExternal(); } catch (Exception e) { return false; } }
    private boolean isThunk(Function f) { try { return f.isThunk(); } catch (Exception e) { return false; } }
    private String symbolSource(Function f) { try { return f.getSymbol()==null?"":f.getSymbol().getSource().toString(); } catch (Exception e) { return ""; } }
    private String safePrototype(Function f) { try { return f.getPrototypeString(false,false); } catch (Exception e) { return f.getName()+"()"; } }
    private String bytesHex(Instruction ins) { try { byte[] bytes=ins.getBytes(); StringBuilder b=new StringBuilder(); for (int i=0;i<bytes.length;i++) { if (i>0) b.append(' '); b.append(String.format("%02X",bytes[i]&0xff)); } return b.toString(); } catch (MemoryAccessException e) { return ""; } }
    private String pad(String s,int width) { StringBuilder b=new StringBuilder(s==null?"":s); while (b.length()<width) b.append(' '); return b.toString(); }
    private String addr(Address a) { return a==null?"":"0x"+a.toString().toUpperCase(Locale.ROOT); }
    private String safe(String s) { return s==null?"":s; }
    private String safeFile(String s) { String x=s==null?"unknown":s.replaceAll("[^A-Za-z0-9_.-]+","_").replaceAll("^[._]+","").replaceAll("[._]+$",""); if (x.isEmpty()) x="unknown"; return x.length()>120?x.substring(0,120):x; }
    private String safeLabel(String s) { String x=s==null?"UNKNOWN":s.replaceAll("[^A-Za-z0-9_]+","_"); if (x.isEmpty()) x="UNKNOWN"; if (Character.isDigit(x.charAt(0))) x="_"+x; return x.length()>60?x.substring(0,60):x; }
    private String safeToken(String s) { return s==null?"unknown":s.replaceAll("[^A-Za-z0-9_.$-]+","_"); }
    private String addressSuffix(Address a) { String x=a.toString().replaceAll("[^A-Za-z0-9]",""); return x.length()>12?x.substring(x.length()-12):x; }
    private String csv(String s) { return "\""+safe(s).replace("\"","\"\"")+"\""; }
    private String md(String s) { return safe(s).replace("\\","\\\\").replace("|","\\|").replace("`","\\`").replace('\n',' ').replace('\r',' '); }
    private String join(Iterable<String> values,String delimiter) { StringBuilder b=new StringBuilder(); boolean first=true; for (String v:values) { if (!first) b.append(delimiter); b.append(v); first=false; } return b.toString(); }
    private File uniqueDir(File base,String name) { File f=new File(base,name); int n=2; while (f.exists()) f=new File(base,name+"_"+(n++)); return f; }
    private void write(File f,String s) throws IOException { try (FileWriter w=new FileWriter(f)) { w.write(s); } }

    // ------------------------------------------------------------------
    // Data classes
    // ------------------------------------------------------------------

    private static class Settings {
        String profile;
        String override;
        String repositoryRoot;
        String outputDirectory;

        boolean applyChanges;
        boolean recoverCodesys;
        boolean forceCodesysScan;
        boolean labelMetadata;
        boolean createBookmarks;
        boolean annotateCore;
        boolean annotateIndirect;
        boolean runAnalysis;
        boolean autoPairSource;
        boolean exportDetails;
        boolean exportNormalized;
        boolean exportFlows;

        int minConfidence;
        int maxCandidates;
        int maxSpan;
        int depth;
        int maxFunctions;
        int maxInstructions;
        int maxMarkerHits;
    }

    private enum Toolchain {
        CODESYS("CODESYS v3"),
        GEB("GEB"),
        OPENPLC2("OpenPLC v2"),
        OPENPLC3("OpenPLC v3"),
        OPENPLC("OpenPLC family"),
        UNKNOWN("Unknown");

        final String label;
        Toolchain(String label) {
            this.label = label;
        }
    }

    private static class Detection {
        final Map<Toolchain, Integer> scores = new LinkedHashMap<>();
        final Map<Toolchain, List<String>> evidence = new LinkedHashMap<>();
        Toolchain toolchain = Toolchain.UNKNOWN;
        String override = "";

        void add(Toolchain toolchain, int points, String reason) {
            scores.put(toolchain, score(toolchain) + points);
            evidence.computeIfAbsent(toolchain, key -> new ArrayList<>());
            if (!evidence.get(toolchain).contains(reason)) {
                evidence.get(toolchain).add(reason);
            }
        }

        int score(Toolchain toolchain) {
            return scores.getOrDefault(toolchain, 0);
        }

        void choose() {
            int best = 0;
            for (Toolchain candidate : Toolchain.values()) {
                if (candidate != Toolchain.UNKNOWN && score(candidate) > best) {
                    best = score(candidate);
                    toolchain = candidate;
                }
            }
        }

        String confidence() {
            if (!override.isEmpty()) return "manual override";
            int value = score(toolchain);
            return value >= 20 ? "high" :
                value >= 10 ? "medium" :
                value > 0 ? "low" : "unknown";
        }

        List<String> chosenEvidence() {
            return evidence.getOrDefault(toolchain, Collections.emptyList());
        }
    }

    private static class SourceInfo {
        File file;
        String text = "";
        final List<Pou> pous = new ArrayList<>();
        final Set<String> names = new LinkedHashSet<>();
        final Set<String> calls = new LinkedHashSet<>();
        final List<TaskInfo> tasks = new ArrayList<>();
        final List<ProgramBinding> bindings = new ArrayList<>();
    }

    private static class Pou {
        final String type;
        final String name;
        String body = "";
        final Set<String> features = new LinkedHashSet<>();

        Pou(String type, String name) {
            this.type = type;
            this.name = name;
        }
    }

    private static class TaskInfo {
        String name = "";
        String parameters = "";
        String interval = "";
        String priority = "";
    }

    private static class ProgramBinding {
        String instance = "";
        String task = "";
        String programType = "";
    }

    private static class MetadataMatch {
        File file;
        String rowText = "";
        final Map<String, String> values = new LinkedHashMap<>();
    }

    private static class ScoredFile {
        final File file;
        final int score;

        ScoredFile(File file, int score) {
            this.file = file;
            this.score = score;
        }
    }

    private static class MarkerHit {
        final String marker;
        final String encoding;
        final String block;
        final Address address;

        MarkerHit(
            String marker,
            String encoding,
            Address address,
            String block
        ) {
            this.marker = marker;
            this.encoding = encoding;
            this.address = address;
            this.block = block;
        }
    }

    private static class CodesysCandidate {
        final Address address;
        final String block;
        final int frame;
        final boolean existing;
        final boolean inside;
        final List<String> reasons = new ArrayList<>();

        int confidence;
        int validInitialInstructions;
        Address returnAddress;
        boolean returnRestoresFrame;
        String status = "not_requested";

        CodesysCandidate(
            Address address,
            String block,
            int frame,
            boolean existing,
            boolean inside
        ) {
            this.address = address;
            this.block = block;
            this.frame = frame;
            this.existing = existing;
            this.inside = inside;
        }
    }

    private static class ReturnEvidence {
        Address address;
        boolean restoresFrame;
    }

    private static class AnalysisModel {
        final List<FunctionRecord> functions = new ArrayList<>();
        final Map<String, FunctionRecord> byEntry = new LinkedHashMap<>();
        final Set<String> core = new LinkedHashSet<>();
        final Set<String> roots = new LinkedHashSet<>();
    }

    private static class FunctionRecord {
        final Function function;
        Address entry;
        String name = "";
        String prototype = "";
        String fingerprint = "";

        int instructions;
        int xrefs;
        int callsOut;
        int externalCalls;
        int indirectCount;
        int score;
        int coreConfidence;

        boolean external;
        boolean thunk;
        boolean userNamed;
        boolean core;

        final Set<String> callees = new LinkedHashSet<>();
        final Set<String> coreReasons = new LinkedHashSet<>();
        final Set<String> features = new LinkedHashSet<>();
        final List<String> semantic = new ArrayList<>();
        final List<String> normalizedForHash = new ArrayList<>();
        final List<CallEdge> calls = new ArrayList<>();
        final List<IndirectCall> indirect = new ArrayList<>();
        final List<FlowEdge> flows = new ArrayList<>();
        final List<Normalized> normalized = new ArrayList<>();
        final List<DataAccess> dataAccesses = new ArrayList<>();

        FunctionRecord(Function function) {
            this.function = function;
        }
    }

    private static class DataAccess {
        String functionName = "";
        Address functionEntry;
        Address instructionAddress;
        Address target;
        String referenceType = "";
        String memoryBlock = "";
        String symbol = "";
        String dataType = "";
        String representation = "";
        boolean read;
        boolean write;
    }

    private static class VariableRecord {
        Address address;
        String symbol = "";
        String memoryBlock = "";
        String dataType = "";
        String representation = "";
        String role = "";
        int confidence;
        int referenceCount;

        final Set<String> readers = new LinkedHashSet<>();
        final Set<String> writers = new LinkedHashSet<>();
        final Set<String> coreReaders = new LinkedHashSet<>();
        final Set<String> coreWriters = new LinkedHashSet<>();
        final Set<String> referenceTypes = new LinkedHashSet<>();
    }

    private static class LiteralRecord {
        Address address;
        String rawHex = "";
        float floatValue;
        int confidence;
        String description = "";

        final Set<String> referencingFunctions = new LinkedHashSet<>();
        final Set<String> referenceSites = new LinkedHashSet<>();
        final Set<String> mnemonics = new LinkedHashSet<>();
    }

    private static class SourceMatch {
        Pou pou;
        FunctionRecord function;
        int confidence;
        boolean uniqueHighConfidence;
        final List<String> reasons = new ArrayList<>();
    }

    private static class FingerprintGroup {
        String fingerprint = "";
        final List<FunctionRecord> functions = new ArrayList<>();
    }

    private static class Preflight {
        String language = "";
        String format = "";
        String imageBase = "";
        String overallStatus = "UNKNOWN";
        int highConfidenceCandidates;
        int symbolCount;
        int fatalFailures;
        boolean automationAllowed;
        final List<PreflightCheck> checks = new ArrayList<>();

        void add(
            boolean passed,
            String description,
            String recommendation,
            boolean fatal
        ) {
            PreflightCheck check = new PreflightCheck();
            check.passed = passed;
            check.description = description;
            check.recommendation = passed ? "" : recommendation;
            check.fatal = fatal;
            checks.add(check);
            if (!passed && fatal) fatalFailures++;
        }
    }

    private static class PreflightCheck {
        boolean passed;
        boolean fatal;
        String description = "";
        String recommendation = "";
    }

    private static class CallEdge {
        final String fromName;
        final String toName;
        final String type;
        final Address fromEntry;
        final Address site;
        final Address to;

        CallEdge(
            String fromName,
            Address fromEntry,
            Address site,
            Address to,
            String toName,
            String type
        ) {
            this.fromName = fromName;
            this.fromEntry = fromEntry;
            this.site = site;
            this.to = to;
            this.toName = toName;
            this.type = type;
        }
    }

    private static class IndirectCall {
        final String function;
        final String kind;
        final String instruction;
        final String context;
        final Address entry;
        final Address address;

        IndirectCall(
            String function,
            Address entry,
            Address address,
            String kind,
            String instruction,
            String context
        ) {
            this.function = function;
            this.entry = entry;
            this.address = address;
            this.kind = kind;
            this.instruction = instruction;
            this.context = context;
        }
    }

    private static class FlowEdge {
        final String function;
        final String type;
        final Address entry;
        final Address from;
        final Address to;

        FlowEdge(
            String function,
            Address entry,
            Address from,
            Address to,
            String type
        ) {
            this.function = function;
            this.entry = entry;
            this.from = from;
            this.to = to;
            this.type = type;
        }
    }

    private static class Normalized {
        final Address address;
        final String raw;
        final String value;

        Normalized(Address address, String raw, String value) {
            this.address = address;
            this.raw = raw;
            this.value = value;
        }
    }

    private static class Traversal {
        final String entry;
        final int depth;

        Traversal(String entry, int depth) {
            this.entry = entry;
            this.depth = depth;
        }
    }

    private static class DetailSelection {
        FunctionRecord function;
        String category = "";
        int confidence;
        final List<String> reasons = new ArrayList<>();
    }

    private static class UndefinedRegion {
        String block = "";
        Address start;
        Address end;
        long length;
        String preview = "";
    }

}
