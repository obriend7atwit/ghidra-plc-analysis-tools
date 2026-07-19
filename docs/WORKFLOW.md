# End-to-End Workflow

1. Preserve and hash the original file.
2. Identify whether it is ELF, PE, raw binary, proprietary container, archive, source, bytecode, or firmware.
3. Import it using the correct Ghidra loader or raw language.
4. Run `RecoverAndDecompilePLC` for broad recovery or `AnalyzePLCProgramPlusV2` for careful evidence.
5. Check function prologues, returns, calls, literals, stack use, and decompiler consistency.
6. Rename only confirmed functions and document uncertainty.
7. Rerun analysis after manual improvements.
