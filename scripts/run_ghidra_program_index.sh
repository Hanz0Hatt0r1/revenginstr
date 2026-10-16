#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "Usage: GHIDRA_HOME=/opt/ghidra $0 <project-dir> <project-name> <program-name> <output-path-prefix>" >&2
  exit 2
fi

: "${GHIDRA_HOME:?Set GHIDRA_HOME to the Ghidra installation directory}"
PROJECT_DIR=$1
PROJECT_NAME=$2
PROGRAM_NAME=$3
PREFIX=$4
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"

[[ -x "$ANALYZE" ]] || { echo "error: analyzeHeadless not executable: $ANALYZE" >&2; exit 1; }
mkdir -p "$(dirname -- "$PREFIX")"
PREFIX="$(cd -- "$(dirname -- "$PREFIX")" && pwd)/$(basename -- "$PREFIX")"
TMP_SCRIPT_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_SCRIPT_DIR"' EXIT
cp "$ROOT/ghidra/ExportGhidraProgramIndex.java" "$TMP_SCRIPT_DIR/ExportGhidraProgramIndex.java"

"$ANALYZE" \
  "$PROJECT_DIR" "$PROJECT_NAME" \
  -process "$PROGRAM_NAME" \
  -readOnly \
  -noanalysis \
  -scriptPath "$TMP_SCRIPT_DIR" \
  -postScript ExportGhidraProgramIndex.java "$PREFIX"
