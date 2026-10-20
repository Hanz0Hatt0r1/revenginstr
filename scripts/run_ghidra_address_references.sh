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
EXPECTED_ROWS=$#
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"

[[ -x "$ANALYZE" ]] || { echo "error: analyzeHeadless not executable: $ANALYZE" >&2; exit 1; }
mkdir -p "$(dirname -- "$OUTPUT")"
OUTPUT="$(cd -- "$(dirname -- "$OUTPUT")" && pwd)/$(basename -- "$OUTPUT")"
TMP_SCRIPT_DIR=$(mktemp -d)
TMP_LOG_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_SCRIPT_DIR" "$TMP_LOG_DIR"' EXIT
cp "$ROOT/ghidra/ExportGhidraAddressReferences.java" "$TMP_SCRIPT_DIR/ExportGhidraAddressReferences.java"

RUN_LOG="$TMP_LOG_DIR/analyze.log"
if ! "$ANALYZE" \
  "$PROJECT_DIR" "$PROJECT_NAME" \
  -process "$PROGRAM_NAME" \
  -readOnly \
  -noanalysis \
  -scriptPath "$TMP_SCRIPT_DIR" \
  -postScript ExportGhidraAddressReferences.java "$OUTPUT" "$@" \
  2>&1 | tee "$RUN_LOG"; then
  exit 1
fi
if ! grep -Fq 'GHIDRA_ADDRESS_REFERENCES_FORMAT=REVENGINSTR.GhidraAddressReferences/1' "$RUN_LOG"; then
  echo "error: Ghidra did not report successful address-reference export completion" >&2
  exit 1
fi
if ! grep -Fq "GHIDRA_ADDRESS_REFERENCES_ROWS=$EXPECTED_ROWS" "$RUN_LOG"; then
  echo "error: Ghidra address-reference row count did not match requested targets" >&2
  exit 1
fi
if [[ ! -s "$OUTPUT" ]] || [[ "$(wc -l < "$OUTPUT")" -ne "$EXPECTED_ROWS" ]]; then
  echo "error: Ghidra address-reference output is missing or incomplete: $OUTPUT" >&2
  exit 1
fi
