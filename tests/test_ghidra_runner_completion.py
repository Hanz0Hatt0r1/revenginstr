from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
RUNNERS = (
    (
        "run_ghidra_parameter_store_field.sh",
        ["project-dir", "project", "program", "00401000", "stores.tsv"],
        "GHIDRA_PARAMETER_STORE_FIELD_FORMAT=REVENGINSTR.GhidraParameterStoreField/1",
    ),
    (
        "run_ghidra_function_pcode_cfg.sh",
        ["project-dir", "project", "program", "cfg.jsonl", "consumer:run", "00401000"],
        "GHIDRA_FUNCTION_PCODE_CFG_FORMAT=REVENGINSTR.GhidraFunctionPcodeCFG/3",
    ),
)


@pytest.mark.parametrize(("runner", "arguments", "marker"), RUNNERS)
def test_ghidra_runners_reject_zero_exit_without_success_marker(
    tmp_path: Path, runner: str, arguments: list[str], marker: str,
) -> None:
    fake_ghidra = tmp_path / "ghidra"
    support = fake_ghidra / "support"
    support.mkdir(parents=True)
    analyzer = support / "analyzeHeadless"
    analyzer.write_text("#!/usr/bin/env bash\nprintf 'ERROR REPORT SCRIPT ERROR\\n'\nexit 0\n", encoding="utf-8")
    analyzer.chmod(0o755)
    output = subprocess.run(
        ["bash", str(ROOT / "scripts" / runner), *arguments],
        cwd=ROOT,
        env={**os.environ, "GHIDRA_HOME": str(fake_ghidra)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert output.returncode != 0
    assert "did not report successful" in output.stderr
    assert marker not in output.stdout


@pytest.mark.parametrize(("runner", "arguments", "marker"), RUNNERS)
def test_ghidra_runners_accept_their_exporter_completion_marker(
    tmp_path: Path, runner: str, arguments: list[str], marker: str,
) -> None:
    fake_ghidra = tmp_path / "ghidra"
    support = fake_ghidra / "support"
    support.mkdir(parents=True)
    analyzer = support / "analyzeHeadless"
    analyzer.write_text(
        "#!/usr/bin/env bash\n"
        "while (($#)); do\n"
        "  if [[ \"$1\" == \"-scriptPath\" ]]; then\n"
        "    python3 -c 'import shutil,sys; shutil.rmtree(sys.argv[1])' \"$2\"\n"
        "    break\n"
        "  fi\n"
        "  shift\n"
        "done\n"
        f"printf '%s\\n' 'INFO Export.java> {marker} (GhidraScript)'\n"
        "exit 0\n",
        encoding="utf-8",
    )
    analyzer.chmod(0o755)
    output = subprocess.run(
        ["bash", str(ROOT / "scripts" / runner), *arguments],
        cwd=ROOT,
        env={**os.environ, "GHIDRA_HOME": str(fake_ghidra)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert output.returncode == 0, output.stderr
    assert marker in output.stdout
