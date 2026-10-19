#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "Usage: GHIDRA_HOME=/opt/ghidra $0 <project-dir> <project-name> <program-name> <plan.tsv> <output.jsonl>" >&2
  echo "Plan columns: plan_id, requested_entry, resolution" >&2
  exit 2
fi

: "${GHIDRA_HOME:?Set GHIDRA_HOME to the Ghidra installation directory}"
PROJECT_DIR=$1
PROJECT_NAME=$2
PROGRAM_NAME=$3
PLAN=$4
OUTPUT=$5
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"

[[ -x "$ANALYZE" ]] || { echo "error: analyzeHeadless not executable: $ANALYZE" >&2; exit 1; }
[[ -f "$PLAN" ]] || { echo "error: plan not found: $PLAN" >&2; exit 1; }
mkdir -p "$(dirname -- "$OUTPUT")"
TMP_SCRIPT_DIR=$(mktemp -d)
LOG_FILE=$(mktemp)
trap 'rm -rf -- "$TMP_SCRIPT_DIR"; rm -f -- "$LOG_FILE"' EXIT
cp "$ROOT/ghidra/ExportGhidraDecompilerParameters.java" "$TMP_SCRIPT_DIR/ExportGhidraDecompilerParameters.java"

if ! "$ANALYZE" \
  "$PROJECT_DIR" "$PROJECT_NAME" \
  -recursive \
  -process "$PROGRAM_NAME" \
  -readOnly \
  -noanalysis \
  -scriptPath "$TMP_SCRIPT_DIR" \
  -postScript ExportGhidraDecompilerParameters.java "$PLAN" "$OUTPUT" \
  2>&1 | tee "$LOG_FILE"; then
  exit 1
fi
grep -Fq 'GHIDRA_DECOMPILER_PARAMETERS_FORMAT=REVENGINSTR.GhidraDecompilerParameters/1' "$LOG_FILE" || {
  echo "error: Ghidra decompiler parameter exporter did not emit its completion marker" >&2
  exit 1
}
