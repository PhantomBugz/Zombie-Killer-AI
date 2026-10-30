from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "package-native-artifact.py"


def fixture_build(root: Path, target_platform: str) -> Path:
    release = root / "target" / "release"
    release.mkdir(parents=True)
    executable = "zombie-killer.exe" if target_platform == "windows" else "zombie-killer"
    (release / executable).write_bytes(b"native executable")
    (release / executable).chmod(0o755)
    (release / ".cargo-lock").touch()
    engine = root / "resources" / "engine"
    engine.mkdir(parents=True)
    engine_exe = (
        "zombie-killer-engine.exe" if target_platform == "windows" else "zombie-killer-engine"
    )
    (engine / engine_exe).write_bytes(b"engine executable")
    (engine / engine_exe).chmod(0o755)
    (engine / ".gitkeep").touch()
    entries: list[dict[str, str | int]] = []
    for name in (".gitkeep", engine_exe):
        payload = (engine / name).read_bytes()
        entries.append(
            {
                "path": name,
                "type": "file",
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    manifest = {
        "format": "pyinstaller-onedir",
        "platform": target_platform,
        "architecture": "x86_64",
        "entries": entries,
    }
    (engine / "BUILD-MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
    legal = root / "legal"
    (legal / "LICENSES").mkdir(parents=True)
    (legal / "LICENSES" / "bundled").mkdir()
    for name in (
        "LICENSE",
        "NOTICE",
        "THIRD_PARTY_NOTICES.md",
        "TRADEMARKS.md",
        "LICENSES/CC-BY-4.0.txt",
        "LICENSES/OFL-1.1.txt",
        "LICENSES/bundled/NOTICE.txt",
    ):
        (legal / name).write_bytes(b"fixture legal terms\n")
    return engine


def package(root: Path, output: Path, target_platform: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-I",
            str(SCRIPT),
            "--tauri-root",
            str(root),
            "--output-dir",
            str(output),
            "--platform",
            target_platform,
            "--legal-root",
            str(root / "legal"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("target_platform", ["windows", "linux", "darwin"])
def test_archive_keeps_engine_in_the_native_runtime_resource_directory(
    tmp_path: Path, target_platform: str
) -> None:
    root = tmp_path / "tauri"
    fixture_build(root, target_platform)
    output = tmp_path / "artifacts"

    completed = package(root, output, target_platform)

    assert completed.returncode == 0, completed.stderr
    archive_path = output / f"unsigned-native-{target_platform}-x86_64.tar.gz"
    with tarfile.open(archive_path, "r:gz") as archive:
        names = set(archive.getnames())
        executable = "zombie-killer.exe" if target_platform == "windows" else "zombie-killer"
        assert f"target/release/{executable}" in names
        assert "target/release/.cargo-lock" in names
        assert "target/release/engine/.gitkeep" in names
        manifest_file = archive.extractfile("target/release/engine/BUILD-MANIFEST.json")
        assert manifest_file is not None
        manifest = json.load(manifest_file)
        for entry in manifest["entries"]:
            member = archive.extractfile("target/release/engine/" + entry["path"])
            assert member is not None
            assert hashlib.sha256(member.read()).hexdigest() == entry["sha256"]
        assert "README.txt" in names
    assert archive_path.name in (output / "SHA256SUMS").read_text(encoding="utf-8")


def test_native_archive_carries_project_and_asset_attribution(tmp_path: Path) -> None:
    root = tmp_path / "tauri"
    fixture_build(root, "windows")
    output = tmp_path / "artifacts"

    completed = package(root, output, "windows")

    assert completed.returncode == 0, completed.stderr
    with tarfile.open(output / "unsigned-native-windows-x86_64.tar.gz", "r:gz") as archive:
        for name in (
            "LICENSE",
            "NOTICE",
            "THIRD_PARTY_NOTICES.md",
            "TRADEMARKS.md",
            "LICENSES/CC-BY-4.0.txt",
            "LICENSES/OFL-1.1.txt",
            "LICENSES/bundled/NOTICE.txt",
        ):
            member = archive.extractfile(name)
            assert member is not None
            assert member.read() == b"fixture legal terms\n"


def test_windows_zip_is_explorer_ready_and_matches_the_verified_tar(tmp_path: Path) -> None:
    root = tmp_path / "tauri with spaces"
    fixture_build(root, "windows")
    output = tmp_path / "artifacts"

    completed = package(root, output, "windows")

    assert completed.returncode == 0, completed.stderr
    zip_path = output / "unsigned-native-windows-x86_64.zip"
    assert zip_path.is_file()
    with (
        zipfile.ZipFile(zip_path) as windows_archive,
        tarfile.open(output / "unsigned-native-windows-x86_64.tar.gz", "r:gz") as archive,
    ):
        files = {member.name for member in archive if member.isfile()}
        assert set(windows_archive.namelist()) == files
        for name in files:
            stream = archive.extractfile(name)
            assert stream is not None
            assert windows_archive.read(name) == stream.read()
        launcher = windows_archive.read("Start Zombie Killer.cmd").decode("utf-8")
        assert 'start "" "%~dp0target\\release\\zombie-killer.exe"' in launcher
        assert 'if not exist "%~dp0target\\release\\engine\\BUILD-MANIFEST.json"' in launcher
        instructions = windows_archive.read("README.txt").decode("utf-8")
        assert "Extract All" in instructions
        assert "Start Zombie Killer.cmd" in instructions
        assert "browser demo" in instructions
    checksums = dict(
        (name, digest)
        for digest, name in (
            line.split("  ", 1)
            for line in (output / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
        )
    )
    for name, digest in checksums.items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest
    assert set(checksums) == {
        "unsigned-native-windows-x86_64.tar.gz",
        "unsigned-native-windows-x86_64.zip",
    }


@pytest.mark.parametrize("target_platform", ["linux", "darwin"])
def test_unix_archive_has_no_windows_launcher_or_zip(tmp_path: Path, target_platform: str) -> None:
    root = tmp_path / "tauri"
    fixture_build(root, target_platform)
    output = tmp_path / "artifacts"

    completed = package(root, output, target_platform)

    assert completed.returncode == 0, completed.stderr
    assert not list(output.glob("*.zip"))
    with tarfile.open(output / f"unsigned-native-{target_platform}-x86_64.tar.gz") as archive:
        assert "Start Zombie Killer.cmd" not in archive.getnames()


def test_missing_native_asset_license_prevents_packaging(tmp_path: Path) -> None:
    root = tmp_path / "tauri"
    fixture_build(root, "windows")
    (root / "legal" / "LICENSES" / "OFL-1.1.txt").unlink()
    output = tmp_path / "artifacts"

    completed = package(root, output, "windows")

    assert completed.returncode != 0
    assert "OFL-1.1.txt" in completed.stderr
    assert not list(output.glob("*.tar.gz"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes and symlinks require a Unix host")
def test_archive_preserves_executable_modes_and_relative_links(tmp_path: Path) -> None:
    root = tmp_path / "tauri"
    engine = fixture_build(root, "linux")
    (engine / "engine-link").symlink_to("zombie-killer-engine")
    manifest_path = engine / "BUILD-MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["entries"].append(
        {"path": "engine-link", "type": "symlink", "target": "zombie-killer-engine"}
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    output = tmp_path / "artifacts"

    completed = package(root, output, "linux")

    assert completed.returncode == 0, completed.stderr
    with tarfile.open(output / "unsigned-native-linux-x86_64.tar.gz", "r:gz") as archive:
        assert archive.getmember("target/release/zombie-killer").mode & 0o111 == 0o111
        assert archive.getmember("target/release/engine/zombie-killer-engine").mode & 0o111 == 0o111
        link = archive.getmember("target/release/engine/engine-link")
        assert link.issym()
        assert link.linkname == "zombie-killer-engine"


def test_missing_cargo_marker_cannot_create_an_unrunnable_unix_archive(tmp_path: Path) -> None:
    root = tmp_path / "tauri"
    fixture_build(root, "linux")
    (root / "target" / "release" / ".cargo-lock").unlink()
    output = tmp_path / "artifacts"

    completed = package(root, output, "linux")

    assert completed.returncode != 0
    assert ".cargo-lock" in completed.stderr
    assert not list(output.glob("*.tar.gz"))


def test_incomplete_engine_inventory_is_not_uploaded(tmp_path: Path) -> None:
    root = tmp_path / "tauri"
    engine = fixture_build(root, "windows")
    (engine / ".gitkeep").unlink()
    output = tmp_path / "artifacts"

    completed = package(root, output, "windows")

    assert completed.returncode != 0
    assert "inventory" in completed.stderr
    assert not list(output.glob("*.tar.gz"))
