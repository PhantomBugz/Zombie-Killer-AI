"""Exercise the Windows CI launcher without changing persistent account state."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "scripts" / "ci_windows_owner.py"


@pytest.mark.skipif(os.name != "nt", reason="Windows token ownership is Windows-only")
def test_owner_launcher_runs_child_after_user_owned_probe(tmp_path: Path) -> None:
    environment = os.environ.copy()
    environment["TEMP"] = str(tmp_path)
    environment["TMP"] = str(tmp_path)
    result = subprocess.run(
        [sys.executable, str(LAUNCHER), "--", sys.executable, "-c", "print('child-ran')"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "child-ran"


@pytest.mark.skipif(os.name != "nt", reason="Windows token ownership is Windows-only")
def test_owner_launcher_preserves_child_exit_code(tmp_path: Path) -> None:
    environment = os.environ.copy()
    environment["TEMP"] = str(tmp_path)
    environment["TMP"] = str(tmp_path)
    result = subprocess.run(
        [sys.executable, str(LAUNCHER), "--", sys.executable, "-c", "raise SystemExit(7)"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 7, result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows token ownership is Windows-only")
@pytest.mark.parametrize("exit_code", [0, 7])
def test_powershell_custom_shell_uses_ps1_and_returns_child_status(
    tmp_path: Path, exit_code: int
) -> None:
    if shutil.which("pwsh") is None:
        pytest.skip("PowerShell Core is required for the hosted shell contract")
    script = tmp_path / "generated.ps1"
    script.write_text(f"Write-Output 'child-ran'; exit {exit_code}\n", encoding="utf-8")
    environment = os.environ.copy()
    environment["TEMP"] = str(tmp_path)
    environment["TMP"] = str(tmp_path)
    quoted_script = str(script).replace("'", "''")
    command = (
        f"python -I scripts/ci_windows_owner.py -- pwsh -NoProfile -File '{quoted_script}'; "
        "exit $LASTEXITCODE"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == exit_code, result.stderr
    assert result.stdout.strip() == "child-ran"
