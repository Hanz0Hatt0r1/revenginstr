#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "Usage: GHIDRA_HOME=/opt/ghidra $0 <project-dir> <project-name> <program-name> <output.json>" >&2
  exit 2
fi
: "${GHIDRA_HOME:?Set GHIDRA_HOME to the Ghidra installation directory}"

PROJECT_DIR=$1
PROJECT_NAME=$2
PROGRAM_NAME=$3
OUTPUT=$4
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"
[[ -x "$ANALYZE" ]] || { echo "error: analyzeHeadless not executable: $ANALYZE" >&2; exit 1; }
if [[ ! -d "$PROJECT_DIR" ]]; then
  echo "error: Ghidra project directory not found: $PROJECT_DIR" >&2
  exit 2
fi
PROJECT_DIR=$(cd -- "$PROJECT_DIR" && pwd)
mkdir -p -- "$(dirname -- "$OUTPUT")"
OUTPUT="$(cd -- "$(dirname -- "$OUTPUT")" && pwd)/$(basename -- "$OUTPUT")"

SCRIPT_DIR=$(mktemp -d)
trap 'rm -rf -- "$SCRIPT_DIR"' EXIT
cp -- "$ROOT/ghidra/ExportGhidraLanguageUserops.java" "$SCRIPT_DIR/"

"$ANALYZE" "$PROJECT_DIR" "$PROJECT_NAME" \
  -process "$PROGRAM_NAME" -readOnly -noanalysis \
  -scriptPath "$SCRIPT_DIR" \
  -postScript ExportGhidraLanguageUserops.java "$OUTPUT"

[[ -s "$OUTPUT" ]] || { echo "error: exporter produced no output: $OUTPUT" >&2; exit 1; }
python3 - "$OUTPUT" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
row = json.loads(path.read_text(encoding="utf-8"))
if row.get("format") != "REVENGINSTR.GhidraLanguageUserops/1":
    raise SystemExit("error: unexpected Ghidra language userop format")
if row.get("userop_count") != len(row.get("userops", [])):
    raise SystemExit("error: Ghidra language userop count mismatch")
if any(item.get("index") != index for index, item in enumerate(row["userops"])):
    raise SystemExit("error: Ghidra language userop indices are not contiguous")
print(f"Ghidra language userop contract: PASS ({row['userop_count']} names)")
PY
