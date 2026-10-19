#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_pcode_flow_batch.sh \
    <project-dir> <project-name> <program-name> <function-list.txt> \
    <flow.tsv> <callind.jsonl> <acquisition.jsonl> [max-functions] [max-total-seconds]

The input list contains one exact function entry per line; blank lines and
comments beginning with # are ignored. The analyzed project is opened read-only.
EOF
}

if [[ $# -lt 7 || $# -gt 9 ]]; then
  usage >&2
  exit 2
fi

: "${GHIDRA_HOME:?Set GHIDRA_HOME to the Ghidra installation directory}"
PROJECT_DIR=$1
PROJECT_NAME=$2
PROGRAM_NAME=$3
FUNCTION_LIST=$4
FLOW_OUTPUT=$5
EVIDENCE_OUTPUT=$6
ACQUISITION_OUTPUT=$7
MAX_FUNCTIONS=${8:-1000}
MAX_TOTAL_SECONDS=${9:-3600}
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"

[[ -x "$ANALYZE" ]] || { echo "error: analyzeHeadless not executable: $ANALYZE" >&2; exit 1; }
[[ -f "$FUNCTION_LIST" ]] || { echo "error: function list not found: $FUNCTION_LIST" >&2; exit 1; }
mkdir -p "$(dirname -- "$FLOW_OUTPUT")" "$(dirname -- "$EVIDENCE_OUTPUT")" "$(dirname -- "$ACQUISITION_OUTPUT")"
TMP_SCRIPT_DIR=$(mktemp -d)
TMP_LOG_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_SCRIPT_DIR" "$TMP_LOG_DIR"' EXIT
cp "$ROOT/ghidra/ExportProgramPcodeFlowBatch.java" "$TMP_SCRIPT_DIR/ExportProgramPcodeFlowBatch.java"

RUN_LOG="$TMP_LOG_DIR/analyze.log"
if ! "$ANALYZE" \
  "$PROJECT_DIR" "$PROJECT_NAME" \
  -recursive \
  -process "$PROGRAM_NAME" \
  -readOnly \
  -noanalysis \
  -scriptPath "$TMP_SCRIPT_DIR" \
  -postScript ExportProgramPcodeFlowBatch.java \
    "$FUNCTION_LIST" "$FLOW_OUTPUT" "$EVIDENCE_OUTPUT" "$ACQUISITION_OUTPUT" "$MAX_FUNCTIONS" \
    "$MAX_TOTAL_SECONDS" \
  2>&1 | tee "$RUN_LOG"; then
  exit 1
fi
if ! grep -Fq 'GHIDRA_PROGRAM_PCODE_FLOW_FORMAT=REVENGINSTR.GhidraPcodeFlowAcquisition/1' "$RUN_LOG"; then
  echo "error: Ghidra did not report successful batch P-code flow completion" >&2
  exit 1
fi
