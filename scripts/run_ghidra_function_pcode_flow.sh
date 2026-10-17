#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_function_pcode_flow.sh \
    <project-dir> <project-name> <program-name> <function-address-or-name> <output.tsv>

The Ghidra project must already contain an analyzed program. The runner uses
-recursive -readOnly -noanalysis and an isolated temporary script path.
EOF
}

if [[ $# -ne 5 ]]; then
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
cp "$ROOT/ghidra/ExportFunctionPcodeFlow.java" "$TMP_SCRIPT_DIR/ExportFunctionPcodeFlow.java"

RUN_LOG="$TMP_LOG_DIR/analyze.log"
if ! "$ANALYZE" \
  "$PROJECT_DIR" "$PROJECT_NAME" \
  -recursive \
  -process "$PROGRAM_NAME" \
  -readOnly \
  -noanalysis \
  -scriptPath "$TMP_SCRIPT_DIR" \
  -postScript ExportFunctionPcodeFlow.java "$FUNCTION" "$OUTPUT" \
  2>&1 | tee "$RUN_LOG"; then
  exit 1
fi
if ! grep -Fq 'GHIDRA_FUNCTION_PCODE_FLOW_FORMAT=REVENGINSTR.GhidraFunctionPcodeFlow/1' "$RUN_LOG"; then
  echo "error: Ghidra did not report successful function P-code flow export completion" >&2
  exit 1
fi
