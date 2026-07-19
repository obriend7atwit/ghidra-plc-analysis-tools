# AnalyzePLCProgramPlusV2

The main tool combines confidence-gated function recovery, PLC toolchain detection, Structured Text matching, bookmarks, data-access analysis, decompiler exports, and structured reporting.

## Recommended workflow

1. Import the PLC file.
2. Allow normal auto-analysis for ELF, PE, or another recognized executable.
3. For raw files, select the correct language and image base.
4. Run the script with **Automatic Safe**.
5. Read `preflight.md`.
6. Review `core_function_details/SELECTION_README.md`.
7. Compare assembly and decompiler output.
8. Rerun after manual renaming or data definition.

## Profiles

- **Automatic Safe:** high-confidence changes only.
- **Report Only:** no project changes.
- **Deep Report:** broader report-only analysis.
- **Custom:** individual feature selection.

## Important reports

- `preflight.md`: import validation.
- `core_functions.md`: likely PLC logic.
- `source_function_candidates.csv`: ranked source matches.
- `variable_access.csv`: memory read/write roles.
- `literal_pools.csv`: likely constants and descriptors.
- `codesys_function_candidates.csv`: recovery scores.
- `core_function_details/`: per-function evidence.
