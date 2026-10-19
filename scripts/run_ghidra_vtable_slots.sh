#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 || $# -gt 5 ]]; then
  echo "usage: $0 <project-dir> <project-name> <program> <output.tsv.gz> [max-slot-offset]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${GHIDRA_HOME:=/opt/ghidra}"
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"
[[ -x "$ANALYZE" ]] || { echo "missing analyzeHeadless: $ANALYZE" >&2; exit 2; }

TMP_SCRIPT_DIR=$(mktemp -d)
TMP_LOG_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_SCRIPT_DIR" "$TMP_LOG_DIR"' EXIT
cp "$ROOT/ghidra/ExportArm32ItaniumVtableSlots.java" "$TMP_SCRIPT_DIR/ExportArm32ItaniumVtableSlots.java"

args=(
  "$1" "$2"
  -process "$3"
  -recursive
  -readOnly
  -noanalysis
  -scriptPath "$TMP_SCRIPT_DIR"
  -postScript ExportArm32ItaniumVtableSlots.java "$4"
)
if [[ $# == 5 ]]; then
  args+=("$5")
fi

RUN_LOG="$TMP_LOG_DIR/analyze.log"
if ! "$ANALYZE" "${args[@]}" 2>&1 | tee "$RUN_LOG"; then
  exit 1
fi
if ! grep -Fq 'VTABLE_SLOT_FORMAT=REVENGINSTR.GhidraArm32ItaniumVtableSlots/1' "$RUN_LOG"; then
  echo "error: Ghidra did not report successful vtable export completion" >&2
  exit 1
fi
