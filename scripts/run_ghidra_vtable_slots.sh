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

args=(
  "$1" "$2"
  -process "$3"
  -recursive
  -readOnly
  -noanalysis
  -scriptPath "$ROOT/ghidra"
  -postScript ExportArm32ItaniumVtableSlots.java "$4"
)
if [[ $# == 5 ]]; then
  args+=("$5")
fi

"$ANALYZE" "${args[@]}"
