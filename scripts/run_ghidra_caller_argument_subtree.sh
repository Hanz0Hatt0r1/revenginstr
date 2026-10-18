#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 5 ]]; then
  echo "Usage: GHIDRA_HOME=/opt/ghidra $0 <project-dir> <project-name> <program-name>" >&2
  echo "  <plan.tsv> <output.tsv> [--parameter-root-output <roots.tsv>]" >&2
  echo "  [--parameter-offset-root-output <offset-roots.tsv>]" >&2
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
shift 5
HAS_PARAMETER_ROOT_OUTPUT=0
HAS_PARAMETER_OFFSET_ROOT_OUTPUT=0
while [[ $# -gt 0 ]]; do
  [[ $# -ge 2 ]] || { echo "Missing path after $1" >&2; exit 2; }
  case "$1" in
    --parameter-root-output|--parameter-offset-root-output)
      if [[ "$1" == "--parameter-root-output" ]]; then
        [[ $HAS_PARAMETER_ROOT_OUTPUT -eq 0 ]] || { echo "Duplicate option: $1" >&2; exit 2; }
        HAS_PARAMETER_ROOT_OUTPUT=1
      else
        [[ $HAS_PARAMETER_OFFSET_ROOT_OUTPUT -eq 0 ]] || { echo "Duplicate option: $1" >&2; exit 2; }
        HAS_PARAMETER_OFFSET_ROOT_OUTPUT=1
      fi
      mkdir -p "$(dirname -- "$2")"
      POST_SCRIPT_ARGS+=("$1" "$2")
      shift 2
      ;;
    *) echo "Unsupported option: $1" >&2; exit 2 ;;
  esac
done
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"

[[ -x "$ANALYZE" ]] || { echo "error: analyzeHeadless not executable: $ANALYZE" >&2; exit 1; }
[[ -f "$PLAN" ]] || { echo "error: plan not found: $PLAN" >&2; exit 1; }
mkdir -p "$(dirname -- "$OUTPUT")"
TMP_SCRIPT_DIR=$(mktemp -d)
TMP_LOG_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_SCRIPT_DIR" "$TMP_LOG_DIR"' EXIT
cp "$ROOT/ghidra/ExportGhidraCallerArgumentSubtree.java" "$TMP_SCRIPT_DIR/ExportGhidraCallerArgumentSubtree.java"

RUN_LOG="$TMP_LOG_DIR/analyze.log"
PARAMETER_OFFSET_ROOT_MARKER='CALLER_ARGUMENT_PARAMETER_OFFSET_ROOT_FORMAT=REVENGINSTR.GhidraCallerArgumentParameterRoot/2'
if ! "$ANALYZE" \
  "$PROJECT_DIR" "$PROJECT_NAME" \
  -recursive \
  -process "$PROGRAM_NAME" \
  -readOnly \
  -noanalysis \
  -scriptPath "$TMP_SCRIPT_DIR" \
  -postScript ExportGhidraCallerArgumentSubtree.java "${POST_SCRIPT_ARGS[@]}" \
  2>&1 | tee "$RUN_LOG"; then
  exit 1
fi

if ! grep -Fq 'CALLER_ARGUMENT_SUBTREE_FORMAT=REVENGINSTR.GhidraCallerArgumentSubtree/1' "$RUN_LOG"; then
  echo "error: Ghidra did not report successful caller-argument export completion" >&2
  exit 1
fi
if [[ $HAS_PARAMETER_ROOT_OUTPUT -eq 1 ]]; then
  if ! grep -Fq 'CALLER_ARGUMENT_PARAMETER_ROOT_FORMAT=REVENGINSTR.GhidraCallerArgumentParameterRoot/1' "$RUN_LOG"; then
    echo "error: Ghidra did not report successful caller-parameter-root export completion" >&2
    exit 1
  fi
fi
if [[ $HAS_PARAMETER_OFFSET_ROOT_OUTPUT -eq 1 ]]; then
  if ! grep -Fq "$PARAMETER_OFFSET_ROOT_MARKER" "$RUN_LOG"; then
    echo "error: Ghidra did not report successful caller-parameter-offset-root export completion" >&2
    exit 1
  fi
fi
