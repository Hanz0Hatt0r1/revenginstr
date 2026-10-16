#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_scalar_uses.sh     <project-dir> <project-name> <program-name> <output.jsonl> <scalar-hex>

The Ghidra project must already contain an analyzed program.
EOF
}

if [[ $# -ne 5 ]]; then
  usage >&2
  exit 2
fi

: "${GHIDRA_HOME:?Set GHIDRA_HOME to the Ghidra installation directory}"
PROJECT_DIR=$1
PROJECT_NAME=$2
PROGRAM_NAME=$3
OUTPUT=$4
SCALAR=$5
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"

[[ -x "$ANALYZE" ]] || { echo "error: analyzeHeadless not executable: $ANALYZE" >&2; exit 1; }
mkdir -p "$(dirname -- "$OUTPUT")"
TMP_SCRIPT_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_SCRIPT_DIR"' EXIT
cp "$ROOT/ghidra/ExportGhidraScalarUses.java" "$TMP_SCRIPT_DIR/ExportGhidraScalarUses.java"

"$ANALYZE"   "$PROJECT_DIR" "$PROJECT_NAME"   -recursive   -process "$PROGRAM_NAME"   -readOnly   -noanalysis   -scriptPath "$TMP_SCRIPT_DIR"   -postScript ExportGhidraScalarUses.java "$OUTPUT" "$SCALAR"
