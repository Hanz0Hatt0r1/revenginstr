#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 6 ]]; then
  echo "usage: GHIDRA_HOME=/opt/ghidra $0 <project-dir> <project-name> <program-name> <trace.jsonl> <plan.tsv> <receiver-types.tsv>" >&2
  exit 2
fi

: "${GHIDRA_HOME:?Set GHIDRA_HOME to the Ghidra installation directory}"
PROJECT_DIR=$1
PROJECT_NAME=$2
PROGRAM_NAME=$3
TRACE=$4
PLAN=$5
OUTPUT=$6
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"
[[ -x "$ANALYZE" ]] || { echo "error: analyzeHeadless not executable: $ANALYZE" >&2; exit 1; }

PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}" \
  python3 -m revenginstr.receiver.plan "$TRACE" "$PLAN" --program "$PROGRAM_NAME"

TMP_SCRIPT_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_SCRIPT_DIR"' EXIT
cp "$ROOT/ghidra/ExportIndirectCallReceiverTypes.java" "$TMP_SCRIPT_DIR/ExportIndirectCallReceiverTypes.java"

"$ANALYZE" \
  "$PROJECT_DIR" "$PROJECT_NAME" \
  -process "$PROGRAM_NAME" \
  -readOnly \
  -noanalysis \
  -scriptPath "$TMP_SCRIPT_DIR" \
  -postScript ExportIndirectCallReceiverTypes.java "$PLAN" "$OUTPUT"
