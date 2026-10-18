#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_parameter_id.sh \
    <project-dir> <project-name> <program-name> <function-entry> [function-entry ...]

This updates recovered function signatures in the selected Ghidra project.
Run it on a disposable project copy when the original analysis must be preserved.
EOF
}

if [[ $# -lt 4 ]]; then
  usage >&2
  exit 2
fi

: "${GHIDRA_HOME:?Set GHIDRA_HOME to the Ghidra installation directory}"
PROJECT_DIR=$1
PROJECT_NAME=$2
PROGRAM_NAME=$3
shift 3
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"

[[ -x "$ANALYZE" ]] || { echo "error: analyzeHeadless not executable: $ANALYZE" >&2; exit 1; }
TMP_SCRIPT_DIR=$(mktemp -d)
TMP_LOG_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_SCRIPT_DIR" "$TMP_LOG_DIR"' EXIT
cp "$ROOT/ghidra/preparation/ApplyDecompilerParameterId.java" "$TMP_SCRIPT_DIR/ApplyDecompilerParameterId.java"

RUN_LOG="$TMP_LOG_DIR/analyze.log"
if ! "$ANALYZE" \
  "$PROJECT_DIR" "$PROJECT_NAME" \
  -recursive \
  -process "$PROGRAM_NAME" \
  -noanalysis \
  -scriptPath "$TMP_SCRIPT_DIR" \
  -postScript ApplyDecompilerParameterId.java "$@" \
  2>&1 | tee "$RUN_LOG"; then
  exit 1
fi

if ! grep -Fq 'GHIDRA_PARAMETER_ID_COMPLETE=true' "$RUN_LOG"; then
  echo "error: Ghidra did not report successful Parameter ID completion" >&2
  exit 1
fi
