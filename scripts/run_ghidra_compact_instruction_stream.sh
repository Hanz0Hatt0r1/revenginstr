#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_compact_instruction_stream.sh \
    <project-dir> <project-name> <program-name> <output.jsonl[.gz]>

The Ghidra project must already contain the selected analyzed program.
REVENGINSTR_GHIDRA_HEADLESS_TIMEOUT_SECONDS defaults to 1800.
EOF
}

if [[ $# -ne 4 ]]; then usage >&2; exit 2; fi
: "${GHIDRA_HOME:?Set GHIDRA_HOME to the Ghidra installation directory}"
PROJECT_DIR=$1
PROJECT_NAME=$2
PROGRAM_NAME=$3
OUTPUT=$4
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"
TIMEOUT_SECONDS=${REVENGINSTR_GHIDRA_HEADLESS_TIMEOUT_SECONDS:-1800}

if [[ ! "$TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
  echo "error: REVENGINSTR_GHIDRA_HEADLESS_TIMEOUT_SECONDS must be a positive integer" >&2
  exit 2
fi
[[ -x "$ANALYZE" ]] || { echo "error: analyzeHeadless not executable: $ANALYZE" >&2; exit 1; }
if [[ -d "$PROJECT_DIR" ]]; then PROJECT_DIR=$(cd -- "$PROJECT_DIR" && pwd); fi
mkdir -p -- "$(dirname -- "$OUTPUT")"
OUTPUT="$(cd -- "$(dirname -- "$OUTPUT")" && pwd)/$(basename -- "$OUTPUT")"

TMP_SCRIPT_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_SCRIPT_DIR"' EXIT
cp -- "$ROOT/ghidra/ExportGhidraCompactInstructionStream.java" \
  "$TMP_SCRIPT_DIR/ExportGhidraCompactInstructionStream.java"
HEADLESS_CMD=(
  "$ANALYZE" "$PROJECT_DIR" "$PROJECT_NAME"
  -process "$PROGRAM_NAME" -readOnly -noanalysis
  -scriptPath "$TMP_SCRIPT_DIR"
  -postScript ExportGhidraCompactInstructionStream.java "$OUTPUT"
)

if command -v timeout >/dev/null 2>&1; then
  set +e
  timeout --signal=TERM --kill-after=10s "${TIMEOUT_SECONDS}s" "${HEADLESS_CMD[@]}"
  status=$?
  set -e
  if [[ $status -ne 0 ]]; then
    if [[ $status -eq 124 || $status -eq 137 ]]; then
      echo "error: Ghidra headless exceeded ${TIMEOUT_SECONDS}s" >&2
    fi
    exit "$status"
  fi
else
  "${HEADLESS_CMD[@]}"
fi

python3 - "$OUTPUT" "$PROGRAM_NAME" <<'PY'
import gzip
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
opener = gzip.open if path.suffix == ".gz" else open
with opener(path, "rt", encoding="utf-8") as stream:
    first = next((line for line in stream if line.strip()), None)
if first is None:
    raise SystemExit("error: compact instruction stream is empty")
header = json.loads(first)
if header.get("format") != "REVENGINSTR.GhidraCompactInstructionStream/1":
    raise SystemExit("error: unexpected compact instruction stream format")
if header.get("kind") != "header" or header.get("program") != sys.argv[2]:
    raise SystemExit("error: compact instruction stream program/header drift")
print("compact instruction stream header: PASS")
PY
