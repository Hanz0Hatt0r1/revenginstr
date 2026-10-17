#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_parameter_store_field.sh \
    <project-dir> <project-name> <program-name> <function-address-or-name> <stores.tsv> \
    [--load-output <loads.tsv>]

The Ghidra project must already contain an analyzed program.
EOF
}

if [[ $# -eq 7 ]]; then
  [[ "$6" == "--load-output" ]] || { usage >&2; exit 2; }
elif [[ $# -ne 5 ]]; then
  usage >&2
  exit 2
fi

: "${GHIDRA_HOME:?Set GHIDRA_HOME to the Ghidra installation directory}"
PROJECT_DIR=$1
PROJECT_NAME=$2
PROGRAM_NAME=$3
FUNCTION=$4
OUTPUT=$5
POST_SCRIPT_ARGS=("$FUNCTION" "$OUTPUT")
if [[ $# -eq 7 ]]; then
  LOAD_OUTPUT=$7
  mkdir -p "$(dirname -- "$LOAD_OUTPUT")"
  POST_SCRIPT_ARGS+=("--load-output" "$LOAD_OUTPUT")
fi
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"

[[ -x "$ANALYZE" ]] || { echo "error: analyzeHeadless not executable: $ANALYZE" >&2; exit 1; }
mkdir -p "$(dirname -- "$OUTPUT")"
TMP_SCRIPT_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_SCRIPT_DIR"' EXIT
cp "$ROOT/ghidra/ExportGhidraParameterStoreField.java" "$TMP_SCRIPT_DIR/ExportGhidraParameterStoreField.java"

"$ANALYZE" \
  "$PROJECT_DIR" "$PROJECT_NAME" \
  -recursive \
  -process "$PROGRAM_NAME" \
  -readOnly \
  -noanalysis \
  -scriptPath "$TMP_SCRIPT_DIR" \
  -postScript ExportGhidraParameterStoreField.java "${POST_SCRIPT_ARGS[@]}"
