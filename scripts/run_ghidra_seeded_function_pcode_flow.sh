#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_seeded_function_pcode_flow.sh \
    <project-dir> <project-name> <program-name> <function-address> <output.tsv> \
    --writable-project-copy

This runner creates the requested function entry if it is not already defined,
then exports its High-P-code flow. It writes to the Ghidra project; use a
disposable writable copy and pass the final acknowledgement flag explicitly.
EOF
}

if [[ $# -ne 6 || "$6" != "--writable-project-copy" ]]; then
  usage >&2
  exit 2
fi

: "${GHIDRA_HOME:?Set GHIDRA_HOME to the Ghidra installation directory}"
PROJECT_DIR=$1
PROJECT_NAME=$2
PROGRAM_NAME=$3
FUNCTION=$4
OUTPUT=$5
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"

[[ -x "$ANALYZE" ]] || { echo "error: analyzeHeadless not executable: $ANALYZE" >&2; exit 1; }
mkdir -p "$(dirname -- "$OUTPUT")"
TMP_SCRIPT_DIR=$(mktemp -d)
TMP_LOG_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_SCRIPT_DIR" "$TMP_LOG_DIR"' EXIT
cp "$ROOT/ghidra/SeedFunctionAtAddress.java" "$ROOT/ghidra/ExportFunctionPcodeFlow.java" "$TMP_SCRIPT_DIR/"

RUN_LOG="$TMP_LOG_DIR/analyze.log"
if ! "$ANALYZE" \
  "$PROJECT_DIR" "$PROJECT_NAME" \
  -process "$PROGRAM_NAME" \
  -noanalysis \
  -scriptPath "$TMP_SCRIPT_DIR" \
  -preScript SeedFunctionAtAddress.java "$FUNCTION" \
  -postScript ExportFunctionPcodeFlow.java "$FUNCTION" "$OUTPUT" \
  2>&1 | tee "$RUN_LOG"; then
  exit 1
fi

if ! grep -Fq "GHIDRA_SEEDED_FUNCTION_ENTRY=$FUNCTION" "$RUN_LOG"; then
  echo "error: Ghidra did not confirm the exact function entry" >&2
  exit 1
fi
if ! grep -Fq "GHIDRA_FUNCTION_PCODE_FLOW_FORMAT=REVENGINSTR.GhidraFunctionPcodeFlow/1" "$RUN_LOG"; then
  echo "error: Ghidra did not report successful P-code flow export completion" >&2
  exit 1
fi
if [[ ! -s "$OUTPUT" ]] || [[ "$(head -n 1 "$OUTPUT")" != $'function_entry\top_address\top_time\topcode\toutput\tinputs\tcallee_entry\tcallee_name' ]]; then
  echo "error: Ghidra P-code flow output is missing or malformed: $OUTPUT" >&2
  exit 1
fi
