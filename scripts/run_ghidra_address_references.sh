#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 5 ]]; then
  echo "Usage: GHIDRA_HOME=/opt/ghidra $0 <project-dir> <project-name> <program-name> <output.jsonl> <address> [address ...]" >&2
  exit 2
fi

GHIDRA_HOME=$(printenv GHIDRA_HOME || true)
if [[ -z "$GHIDRA_HOME" ]]; then
  echo "error: set GHIDRA_HOME to the Ghidra installation directory" >&2
  exit 2
fi
PROJECT_DIR=$1
PROJECT_NAME=$2
PROGRAM_NAME=$3
OUTPUT=$4
shift 4
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"

[[ -x "$ANALYZE" ]] || { echo "error: analyzeHeadless not executable: $ANALYZE" >&2; exit 1; }
mkdir -p "$(dirname -- "$OUTPUT")"
OUTPUT="$(cd -- "$(dirname -- "$OUTPUT")" && pwd)/$(basename -- "$OUTPUT")"
TMP_SCRIPT_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_SCRIPT_DIR"' EXIT
cp "$ROOT/ghidra/ExportGhidraAddressReferences.java" "$TMP_SCRIPT_DIR/ExportGhidraAddressReferences.java"

"$ANALYZE" \
  "$PROJECT_DIR" "$PROJECT_NAME" \
  -process "$PROGRAM_NAME" \
  -readOnly \
  -noanalysis \
  -scriptPath "$TMP_SCRIPT_DIR" \
  -postScript ExportGhidraAddressReferences.java "$OUTPUT" "$@"
