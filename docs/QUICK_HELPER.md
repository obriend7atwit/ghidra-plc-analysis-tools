# RecoverAndDecompilePLC

The quick helper performs broad in-Ghidra recovery with no report directory and no script prompts.

## User responsibilities

For raw binaries, determine the processor, bitness, endianness, instruction mode, and image base.

## Automatic actions

- full Ghidra analysis
- function candidate discovery
- pseudo-disassembler validation
- disassembly and function creation
- repeated call-target recovery
- aligned-gap scanning on suitable raw files
- incremental analysis
- Decompiler Parameter ID
- decompiler validation
- `PLC Recovery/` bookmarks

Open **Window → Functions** and **Window → Bookmarks** after the script finishes.
