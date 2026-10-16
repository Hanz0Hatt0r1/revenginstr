#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_instruction_slices.sh \
    <project-dir> <project-name> <program-name> <output.jsonl> \
    <address[:hex-length]> [address[:hex-length] ...]

The Ghidra project must already contain the selected analyzed program.
REVENGINSTR_GHIDRA_HEADLESS_TIMEOUT_SECONDS defaults to 300.
EOF
}

if [[ $# -lt 5 ]]; then usage >&2; exit 2; fi
: "${GHIDRA_HOME:?Set GHIDRA_HOME to the Ghidra installation directory}"
PROJECT_DIR=$1
PROJECT_NAME=$2
PROGRAM_NAME=$3
OUTPUT=$4
shift 4
TARGETS=("$@")
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"
TIMEOUT_SECONDS=${REVENGINSTR_GHIDRA_HEADLESS_TIMEOUT_SECONDS:-300}

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
cp -- "$ROOT/ghidra/ExportGhidraInstructionSlices.java" \
  "$TMP_SCRIPT_DIR/ExportGhidraInstructionSlices.java"
HEADLESS_CMD=(
  "$ANALYZE" "$PROJECT_DIR" "$PROJECT_NAME"
  -recursive -process "$PROGRAM_NAME" -readOnly -noanalysis
  -scriptPath "$TMP_SCRIPT_DIR"
  -postScript ExportGhidraInstructionSlices.java "$OUTPUT" "${TARGETS[@]}"
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

python3 - "$OUTPUT" "$PROGRAM_NAME" "${TARGETS[@]}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
program = sys.argv[2]
targets = sys.argv[3:]
rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
if len(rows) != len(targets):
    raise SystemExit(f"error: expected {len(targets)} slice rows, got {len(rows)}")
for index, (row, token) in enumerate(zip(rows, targets), 1):
    if row.get("format") != "REVENGINSTR.GhidraInstructionSlice/1":
        raise SystemExit(f"error: row {index} has unexpected format")
    if row.get("program") != program or row.get("requested") != token.split(":", 1)[0]:
        raise SystemExit(f"error: row {index} program/request drift")
    if not isinstance(row.get("exact_instruction_at_start"), bool):
        raise SystemExit(f"error: row {index} has no exact-instruction status")
    instructions = row.get("instructions")
    if not isinstance(instructions, list) or row.get("instruction_count") != len(instructions):
        raise SystemExit(f"error: row {index} instruction count mismatch")
print(f"instruction slice export contract: PASS ({len(rows)} slices)")
PY
