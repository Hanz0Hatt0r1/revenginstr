#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_pcode_export.sh \
    <project-dir> <project-name> <program-name> <output.jsonl> [max-functions] [name-contains]

The Ghidra project must already contain an analyzed program. The runner uses
-readOnly -noanalysis and an isolated temporary script path so unrelated Ghidra
scripts are not compiled.
EOF
}

if [[ $# -lt 4 || $# -gt 6 ]]; then
  usage >&2
  exit 2
fi

: "${GHIDRA_HOME:?Set GHIDRA_HOME to the Ghidra installation directory}"
PROJECT_DIR=$1
PROJECT_NAME=$2
PROGRAM_NAME=$3
OUTPUT=$4
MAX_FUNCTIONS=${5:-0}
NAME_FILTER=${6:-}
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"

[[ -x "$ANALYZE" ]] || { echo "error: analyzeHeadless not executable: $ANALYZE" >&2; exit 1; }
mkdir -p "$(dirname -- "$OUTPUT")"
TMP_SCRIPT_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_SCRIPT_DIR"' EXIT
cp "$ROOT/ghidra/PortablePcodeCorpusExporter.java" "$TMP_SCRIPT_DIR/PortablePcodeCorpusExporter.java"

ARGS=("$OUTPUT" "$MAX_FUNCTIONS")
if [[ -n "$NAME_FILTER" ]]; then
  ARGS+=("$NAME_FILTER")
fi

"$ANALYZE" \
  "$PROJECT_DIR" "$PROJECT_NAME" \
  -process "$PROGRAM_NAME" \
  -readOnly \
  -noanalysis \
  -scriptPath "$TMP_SCRIPT_DIR" \
  -postScript PortablePcodeCorpusExporter.java "${ARGS[@]}"
