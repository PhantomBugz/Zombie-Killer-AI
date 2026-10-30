"""Collect installed runtime legal files before the sidecar manifest is sealed."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import sys
import sysconfig
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def interpreter_license() -> Path:
    for candidate in (
        Path(sys.base_prefix) / "LICENSE.txt",
        Path(sys.base_prefix) / "LICENSE",
        Path(sysconfig.get_path("stdlib")) / "LICENSE.txt",
        Path(sysconfig.get_path("stdlib")) / "LICENSE",
    ):
        if candidate.is_file():
            return candidate
    raise RuntimeError("CPython license text is missing from the installed interpreter")


def license_payloads(distribution: importlib.metadata.Distribution) -> list[tuple[str, bytes]]:
    payloads: list[tuple[str, bytes]] = []
    for entry in distribution.files or ():
        path = PurePosixPath(str(entry).replace("\\", "/"))
        stem = path.name.upper()
        if not stem.startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "AUTHORS")):
            continue
        if path.suffix.lower() not in {"", ".txt", ".md", ".rst", ".markdown-it"}:
            continue
        if path.is_absolute() or any(component in {"..", "."} for component in path.parts):
            raise RuntimeError("installed runtime license has an unsafe relative path")
        source = Path(str(distribution.locate_file(entry)))
        if not source.is_file():
            raise RuntimeError(f"{distribution.metadata['Name']} runtime license file is missing")
        payloads.append((path.as_posix(), source.read_bytes()))
    if not payloads:
        raise RuntimeError(f"{distribution.metadata['Name']} runtime license text is missing")
    return sorted(payloads)


def collect_runtime_legal(
    output: Path,
    *,
    distributions: Iterable[importlib.metadata.Distribution] | None = None,
    root_names: tuple[str, ...] = ("zombie-killer-engine",),
    tool_names: tuple[str, ...] = ("pyinstaller",),
    python_license: Path | None = None,
) -> dict[str, Any]:
    python_terms = python_license if python_license is not None else interpreter_license()
    if not python_terms.is_file():
        raise RuntimeError("CPython license text is missing from the installed interpreter")
    installed: dict[str, importlib.metadata.Distribution] = {
        canonicalize_name(distribution.metadata["Name"]): distribution
        for distribution in (
            distributions if distributions is not None else importlib.metadata.distributions()
        )
    }
    selected: set[str] = set()
    pending: list[tuple[str, frozenset[str]]] = [
        (canonicalize_name(name), frozenset[str]()) for name in root_names
    ]
    visited: set[tuple[str, frozenset[str]]] = set()
    environment = {key: str(value) for key, value in default_environment().items()}
    while pending:
        name, extras = pending.pop()
        if (name, extras) in visited:
            continue
        visited.add((name, extras))
        if name not in installed:
            raise RuntimeError(f"runtime distribution is missing: {name}")
        selected.add(name)
        for raw in installed[name].requires or ():
            requirement = Requirement(raw)
            if requirement.marker is not None and not any(
                requirement.marker.evaluate({**environment, "extra": extra})
                for extra in extras | {""}
            ):
                continue
            pending.append((canonicalize_name(requirement.name), frozenset(requirement.extras)))
    tools = {canonicalize_name(name) for name in tool_names}
    selected.update(tools)

    files: list[tuple[str, bytes]] = [("CPython/LICENSE.txt", python_terms.read_bytes())]
    components: list[dict[str, Any]] = []
    for name in sorted(selected):
        if name not in installed:
            raise RuntimeError(f"bootloader distribution is missing: {name}")
        distribution = installed[name]
        for relative, payload in license_payloads(distribution):
            files.append((f"distributions/{name}/{relative}", payload))
        components.append(
            {
                "name": name,
                "version": distribution.version,
                "scope": "bootloader_terms" if name in tools else "runtime_dependency_graph",
                "declared_license": distribution.metadata.json.get(
                    "license_expression", distribution.metadata.json.get("license", "NOASSERTION")
                ),
            }
        )
    manifest: dict[str, Any] = {
        "format": "zombie-killer-sidecar-legal-v1",
        "python": platform.python_version(),
        "platform": platform.system().lower(),
        "distributions": components,
        "files": [
            {"path": relative, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
            for relative, payload in sorted(files)
        ],
        "scope": (
            "Installed engine runtime dependency closure, bootloader terms, and interpreter terms."
        ),
        "review_required": [
            "This dependency graph does not prove which optional modules PyInstaller included.",
            "Review platform libraries (OpenSSL, SQLite, and CRTs) against actual binaries.",
            "Desktop JavaScript, Rust, assets, and system prerequisites have separate legal scope.",
        ],
    }
    legal = output / "LEGAL"
    legal.mkdir()
    for relative, payload in files:
        destination = legal / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    (legal / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    manifest = collect_runtime_legal(arguments.output)
    print(f"Collected {len(manifest['files'])} sidecar legal files for build inventory.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
