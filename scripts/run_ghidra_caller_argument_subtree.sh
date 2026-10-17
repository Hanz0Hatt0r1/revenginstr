#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 7 ]]; then
  [[ "$6" == "--parameter-root-output" ]] || { echo "Expected --parameter-root-output" >&2; exit 2; }
elif [[ $# -ne 5 ]]; then
  echo "Usage: GHIDRA_HOME=/opt/ghidra $0 <project-dir> <project-name> <program-name> <plan.tsv> <output.tsv> [--parameter-root-output <roots.tsv>]" >&2
  echo "Plan columns: plan_id, callee_entry, parameter_index" >&2
  exit 2
fi

: "${GHIDRA_HOME:?Set GHIDRA_HOME to the Ghidra installation directory}"
PROJECT_DIR=$1
PROJECT_NAME=$2
PROGRAM_NAME=$3
PLAN=$4
OUTPUT=$5
POST_SCRIPT_ARGS=("$PLAN" "$OUTPUT")
if [[ $# -eq 7 ]]; then
  PARAMETER_ROOT_OUTPUT=$7
  mkdir -p "$(dirname -- "$PARAMETER_ROOT_OUTPUT")"
  POST_SCRIPT_ARGS+=("--parameter-root-output" "$PARAMETER_ROOT_OUTPUT")
fi
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"

[[ -x "$ANALYZE" ]] || { echo "error: analyzeHeadless not executable: $ANALYZE" >&2; exit 1; }
[[ -f "$PLAN" ]] || { echo "error: plan not found: $PLAN" >&2; exit 1; }
mkdir -p "$(dirname -- "$OUTPUT")"
TMP_SCRIPT_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_SCRIPT_DIR"' EXIT
cp "$ROOT/ghidra/ExportGhidraCallerArgumentSubtree.java" "$TMP_SCRIPT_DIR/ExportGhidraCallerArgumentSubtree.java"

"$ANALYZE" \
  "$PROJECT_DIR" "$PROJECT_NAME" \
  -recursive \
  -process "$PROGRAM_NAME" \
  -readOnly \
  -noanalysis \
  -scriptPath "$TMP_SCRIPT_DIR" \
  -postScript ExportGhidraCallerArgumentSubtree.java "${POST_SCRIPT_ARGS[@]}"
