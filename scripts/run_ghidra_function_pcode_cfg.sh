#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 6 ]]; then
  echo "Usage: GHIDRA_HOME=/opt/ghidra $0 <project-dir> <project-name> <program-name> <output.jsonl> <program-id> <function-entry> [entry ...] [--memory-metadata|--physical-memory-metadata]" >&2
  exit 2
fi

: "${GHIDRA_HOME:?Set GHIDRA_HOME to the Ghidra installation directory}"
PROJECT_DIR=$1
PROJECT_NAME=$2
PROGRAM_NAME=$3
OUTPUT=$4
shift 4
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"

[[ -x "$ANALYZE" ]] || { echo "error: analyzeHeadless not executable: $ANALYZE" >&2; exit 1; }
mkdir -p "$(dirname -- "$OUTPUT")"
TMP_SCRIPT_DIR=$(mktemp -d)
TMP_LOG_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_SCRIPT_DIR" "$TMP_LOG_DIR"' EXIT
cp "$ROOT/ghidra/ExportFunctionPcodeCFG.java" "$TMP_SCRIPT_DIR/ExportFunctionPcodeCFG.java"

RUN_LOG="$TMP_LOG_DIR/analyze.log"
if ! "$ANALYZE" \
  "$PROJECT_DIR" "$PROJECT_NAME" \
  -recursive \
  -process "$PROGRAM_NAME" \
  -readOnly \
  -noanalysis \
  -scriptPath "$TMP_SCRIPT_DIR" \
  -postScript ExportFunctionPcodeCFG.java "$OUTPUT" "$@" \
  2>&1 | tee "$RUN_LOG"; then
  exit 1
fi
if ! grep -Eq 'GHIDRA_FUNCTION_PCODE_CFG_FORMAT=REVENGINSTR\.GhidraFunctionPcodeCFG/[123]([^0-9]|$)' "$RUN_LOG"; then
  echo "error: Ghidra did not report successful function CFG export completion" >&2
  exit 1
fi
