#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_parameter_store_field.sh \
    <project-dir> <project-name> <program-name> <function-address-or-name> <stores.tsv> \
    [--load-output <loads.tsv>] \
    [--memory-access-output <stores.jsonl> --program-id <opaque-id>]

The Ghidra project must already contain an analyzed program.
EOF
}

if [[ $# -lt 5 ]]; then
  usage >&2
  exit 2
fi

: "${GHIDRA_HOME:?Set GHIDRA_HOME to the Ghidra installation directory}"
PROJECT_DIR=$1
PROJECT_NAME=$2
PROGRAM_NAME=$3
FUNCTION=$4
OUTPUT=$5
POST_SCRIPT_ARGS=("$FUNCTION" "$OUTPUT")
shift 5
while (($#)); do
  case "$1" in
    --load-output|--memory-access-output|--program-id)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      if [[ "$1" != "--program-id" ]]; then
        mkdir -p "$(dirname -- "$2")"
      fi
      POST_SCRIPT_ARGS+=("$1" "$2")
      shift 2
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"

[[ -x "$ANALYZE" ]] || { echo "error: analyzeHeadless not executable: $ANALYZE" >&2; exit 1; }
mkdir -p "$(dirname -- "$OUTPUT")"
TMP_SCRIPT_DIR=$(mktemp -d)
TMP_LOG_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_SCRIPT_DIR" "$TMP_LOG_DIR"' EXIT
cp "$ROOT/ghidra/ExportGhidraParameterStoreField.java" "$TMP_SCRIPT_DIR/ExportGhidraParameterStoreField.java"

RUN_LOG="$TMP_LOG_DIR/analyze.log"
if ! "$ANALYZE" \
  "$PROJECT_DIR" "$PROJECT_NAME" \
  -recursive \
  -process "$PROGRAM_NAME" \
  -readOnly \
  -noanalysis \
  -scriptPath "$TMP_SCRIPT_DIR" \
  -postScript ExportGhidraParameterStoreField.java "${POST_SCRIPT_ARGS[@]}" \
  2>&1 | tee "$RUN_LOG"; then
  exit 1
fi
if ! grep -Fq 'GHIDRA_PARAMETER_STORE_FIELD_FORMAT=REVENGINSTR.GhidraParameterStoreField/1' "$RUN_LOG"; then
  echo "error: Ghidra did not report successful parameter-store export completion" >&2
  exit 1
fi
