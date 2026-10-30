"""Exercise the Windows CI launcher without changing persistent account state."""

from __future__ import annotations

import os
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
