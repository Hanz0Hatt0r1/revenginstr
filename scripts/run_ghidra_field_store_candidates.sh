#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_field_store_candidates.sh \
    <project-dir> <project-name> <program-name> \
    <function-name-fragment[;...]> <field-offset> <output.tsv>

The Ghidra project must already contain an analyzed program. Quote the
semicolon-separated function-name fragments so the shell passes one argument.
EOF
}

if [[ $# -ne 6 ]]; then
  usage >&2
  exit 2
fi

: "${GHIDRA_HOME:?Set GHIDRA_HOME to the Ghidra installation directory}"
PROJECT_DIR=$1
PROJECT_NAME=$2
PROGRAM_NAME=$3
FUNCTION_NAME_FRAGMENTS=$4
FIELD_OFFSET=$5
OUTPUT=$6
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"

[[ -x "$ANALYZE" ]] || { echo "error: analyzeHeadless not executable: $ANALYZE" >&2; exit 1; }
mkdir -p "$(dirname -- "$OUTPUT")"
TMP_SCRIPT_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_SCRIPT_DIR"' EXIT
cp "$ROOT/ghidra/ExportGhidraFieldStoreCandidates.java" "$TMP_SCRIPT_DIR/ExportGhidraFieldStoreCandidates.java"

"$ANALYZE" \
  "$PROJECT_DIR" "$PROJECT_NAME" \
  -recursive \
  -process "$PROGRAM_NAME" \
  -readOnly \
  -noanalysis \
  -scriptPath "$TMP_SCRIPT_DIR" \
  -postScript ExportGhidraFieldStoreCandidates.java \
  "$FUNCTION_NAME_FRAGMENTS" "$FIELD_OFFSET" "$OUTPUT"
