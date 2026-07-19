#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="${SCRIPT_DIR}/../ghidra_scripts"
TARGET_DIR="${HOME}/ghidra_scripts"
mkdir -p "${TARGET_DIR}"
cp "${SOURCE_DIR}/AnalyzePLCProgramPlusV2.java" "${TARGET_DIR}/AnalyzePLCProgramPlusV2.java"
cp "${SOURCE_DIR}/RecoverAndDecompilePLC.java" "${TARGET_DIR}/RecoverAndDecompilePLC.java"
echo "Installed both scripts to ${TARGET_DIR}"
