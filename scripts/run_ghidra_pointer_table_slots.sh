#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 7 || $(( ($# - 5) % 2 )) -ne 0 ]]; then
  echo "usage: $0 <project-dir> <project-name> <program> <output.jsonl> <program-id> <table-address> <slot-count> [table-address slot-count ...]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${GHIDRA_HOME:=/opt/ghidra}"
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"
[[ -x "$ANALYZE" ]] || { echo "missing analyzeHeadless: $ANALYZE" >&2; exit 2; }

TMP_SCRIPT_DIR=$(mktemp -d)
TMP_LOG_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_SCRIPT_DIR" "$TMP_LOG_DIR"' EXIT
cp "$ROOT/ghidra/ExportGhidraPointerTableSlots.java" "$TMP_SCRIPT_DIR/ExportGhidraPointerTableSlots.java"

RUN_LOG="$TMP_LOG_DIR/analyze.log"
if ! "$ANALYZE" "$1" "$2" \
  -process "$3" \
  -readOnly \
  -noanalysis \
  -scriptPath "$TMP_SCRIPT_DIR" \
  -postScript ExportGhidraPointerTableSlots.java "${@:4}" \
  2>&1 | tee "$RUN_LOG"; then
  exit 1
fi
if ! grep -Fq 'POINTER_TABLE_SLOTS_FORMAT=REVENGINSTR.GhidraPointerTableSlots/1' "$RUN_LOG"; then
  echo "error: Ghidra did not report successful pointer-table export completion" >&2
  exit 1
fi
