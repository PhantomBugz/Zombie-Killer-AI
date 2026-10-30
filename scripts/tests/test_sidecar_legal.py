from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


@pytest.fixture(scope="module")
def collector() -> ModuleType:
    script = Path(__file__).parents[1] / "collect-sidecar-legal.py"
    spec = importlib.util.spec_from_file_location("collect_sidecar_legal", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def distribution(root: Path, name: str, *, requires: tuple[str, ...] = ()) -> None:
    metadata = root / f"{name}-1.0.dist-info"
    metadata.mkdir(parents=True)
    (metadata / "METADATA").write_text(
        f"Metadata-Version: 2.4\nName: {name}\nVersion: 1.0\nLicense-Expression: MIT\n"
        + "".join(f"Requires-Dist: {dependency}\n" for dependency in requires),
        encoding="utf-8",
    )
    (metadata / "LICENSE").write_bytes(f"Copyright {name}\nfixture license\n".encode())
    (metadata / "RECORD").write_text(
        f"{metadata.name}/METADATA,,\n{metadata.name}/LICENSE,,\n", encoding="utf-8"
    )


def test_runtime_licenses_exclude_inactive_extras_and_unrelated_dev_tools(
    collector: Any, tmp_path: Path
) -> None:
    site = tmp_path / "site"
    distribution(site, "engine", requires=("runtime",))
    distribution(site, "runtime", requires=("leaf", 'devtool; extra == "test"'))
    distribution(site, "leaf")
    distribution(site, "devtool")
    distribution(site, "unrelated")
    python_license = tmp_path / "python-license.txt"
    python_license.write_bytes(b"actual interpreter license\n")
    output = tmp_path / "engine-build"
    output.mkdir()

    collector.collect_runtime_legal(
        output,
        distributions=importlib.metadata.distributions(path=[str(site)]),
        root_names=("engine",),
        tool_names=(),
        python_license=python_license,
    )

    manifest = json.loads((output / "LEGAL" / "MANIFEST.json").read_text(encoding="utf-8"))
    assert {entry["name"] for entry in manifest["distributions"]} == {"engine", "runtime", "leaf"}
    assert (output / "LEGAL" / "CPython" / "LICENSE.txt").read_bytes() == (
        b"actual interpreter license\n"
    )
    for entry in manifest["files"]:
        payload = (output / "LEGAL" / entry["path"]).read_bytes()
        assert entry["sha256"] == hashlib.sha256(payload).hexdigest()
    assert not any("devtool" in entry["path"] for entry in manifest["files"])


def test_missing_runtime_license_fails_before_legal_inventory_is_written(
    collector: Any, tmp_path: Path
) -> None:
    site = tmp_path / "site"
    distribution(site, "engine", requires=("runtime",))
    distribution(site, "runtime")
    (site / "runtime-1.0.dist-info" / "LICENSE").unlink()
    python_license = tmp_path / "python-license.txt"
    python_license.write_bytes(b"interpreter license\n")
    output = tmp_path / "engine-build"
    output.mkdir()

    with pytest.raises(RuntimeError, match="runtime.*license"):
        collector.collect_runtime_legal(
            output,
            distributions=importlib.metadata.distributions(path=[str(site)]),
            root_names=("engine",),
            tool_names=(),
            python_license=python_license,
        )
    assert not (output / "LEGAL" / "MANIFEST.json").exists()


def test_bootloader_terms_do_not_pull_build_tool_dependencies_into_runtime_inventory(
    collector: Any, tmp_path: Path
) -> None:
    site = tmp_path / "site"
    distribution(site, "engine")
    distribution(site, "pyinstaller", requires=("buildtool",))
    distribution(site, "buildtool")
    python_license = tmp_path / "python-license.txt"
    python_license.write_bytes(b"interpreter license\n")
    output = tmp_path / "engine-build"
    output.mkdir()

    manifest = collector.collect_runtime_legal(
        output,
        distributions=importlib.metadata.distributions(path=[str(site)]),
        root_names=("engine",),
        python_license=python_license,
    )

    assert {entry["name"] for entry in manifest["distributions"]} == {"engine", "pyinstaller"}
    assert not any("buildtool" in entry["path"] for entry in manifest["files"])


def test_missing_interpreter_terms_prevents_sidecar_legal_sealing(
    collector: Any, tmp_path: Path
) -> None:
    site = tmp_path / "site"
    distribution(site, "engine")
    output = tmp_path / "engine-build"
    output.mkdir()

    with pytest.raises(RuntimeError, match="CPython.*license"):
        collector.collect_runtime_legal(
            output,
            distributions=importlib.metadata.distributions(path=[str(site)]),
            root_names=("engine",),
            tool_names=(),
            python_license=tmp_path / "missing",
        )
    assert not (output / "LEGAL").exists()


def test_isolated_collector_preserves_actual_installed_runtime_terms(tmp_path: Path) -> None:
    script = Path(__file__).parents[1] / "collect-sidecar-legal.py"

    completed = subprocess.run(
        [sys.executable, "-I", str(script), "--output", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    manifest = json.loads((tmp_path / "LEGAL" / "MANIFEST.json").read_text(encoding="utf-8"))
    names = {entry["name"] for entry in manifest["distributions"]}
    assert {"psutil", "pydantic", "typer", "pyinstaller"} <= names
    assert not {"pytest", "ruff", "mypy", "hatchling"} & names
    assert any("typer/_click/LICENSE.txt" in entry["path"] for entry in manifest["files"])
    assert any("COPYING.txt" in entry["path"] for entry in manifest["files"])
    for entry in manifest["files"]:
        assert (tmp_path / "LEGAL" / entry["path"]).is_file()
