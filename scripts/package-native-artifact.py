"""Package the unbundled native build without changing its Tauri resource layout."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Any

WINDOWS_LAUNCHER = (
    b"@echo off\r\n"
    b"setlocal\r\n"
    b'if not exist "%~dp0target\\release\\zombie-killer.exe" goto incomplete\r\n'
    b'if not exist "%~dp0target\\release\\engine\\BUILD-MANIFEST.json" goto incomplete\r\n'
    b'start "" "%~dp0target\\release\\zombie-killer.exe"\r\n'
    b"exit /b %errorlevel%\r\n"
    b":incomplete\r\n"
    b"echo Please extract the entire Zombie Killer archive before launching.\r\n"
    b"echo Keep this launcher beside the target folder.\r\n"
    b"pause\r\n"
    b"exit /b 1\r\n"
)


def file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_engine_inventory(engine: Path, manifest: dict[str, Any]) -> None:
    expected = {entry["path"] for entry in manifest["entries"]}
    actual = {
        path.relative_to(engine).as_posix()
        for path in engine.rglob("*")
        if path.is_symlink() or path.is_file()
    }
    if actual != expected | {"BUILD-MANIFEST.json"}:
        raise RuntimeError("engine inventory does not match the package source tree")
    for entry in manifest["entries"]:
        path = engine / entry["path"]
        if entry["type"] == "symlink":
            if not path.is_symlink() or os.readlink(path) != entry["target"]:
                raise RuntimeError("engine inventory symbolic link does not match")
        elif (
            path.is_symlink()
            or path.stat().st_size != entry["size"]
            or file_digest(path) != entry["sha256"]
        ):
            raise RuntimeError("engine inventory file does not match")


def legal_files(legal_root: Path) -> list[Path]:
    required = (
        "LICENSE",
        "NOTICE",
        "THIRD_PARTY_NOTICES.md",
        "TRADEMARKS.md",
        "LICENSES/CC-BY-4.0.txt",
        "LICENSES/OFL-1.1.txt",
    )
    for name in required:
        if not (legal_root / name).is_file():
            raise RuntimeError(f"native artifact legal file is missing: {name}")
    return [legal_root / name for name in required[:4]] + sorted(
        path for path in (legal_root / "LICENSES").rglob("*") if path.is_file()
    )


def windows_zip_from_tar(archive_path: Path) -> Path:
    """Offer Explorer extraction without altering the verified portable layout."""
    zip_path = archive_path.with_suffix("").with_suffix(".zip")
    with (
        tarfile.open(archive_path, "r:gz") as source,
        zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as destination,
    ):
        for member in source:
            if member.isdir():
                continue
            if not member.isfile():
                raise RuntimeError("Windows ZIP requires regular files, not symbolic links")
            stream = source.extractfile(member)
            if stream is None:
                raise RuntimeError("verified native archive file is missing")
            with stream, destination.open(member.name, "w") as output:
                shutil.copyfileobj(stream, output)
    with zipfile.ZipFile(zip_path) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("Windows native ZIP failed its integrity check")
    return zip_path


def package_native(
    tauri_root: Path, output_dir: Path, target_platform: str, legal_root: Path
) -> Path:
    release = tauri_root / "target" / "release"
    native_name = "zombie-killer.exe" if target_platform == "windows" else "zombie-killer"
    native = release / native_name
    marker = release / ".cargo-lock"
    engine = tauri_root / "resources" / "engine"
    if not native.is_file():
        raise RuntimeError(f"native build is missing {native_name}")
    if not marker.is_file():
        raise RuntimeError("native build is missing .cargo-lock required for Unix resource lookup")
    manifest = json.loads((engine / "BUILD-MANIFEST.json").read_text(encoding="utf-8"))
    if manifest["platform"] != target_platform:
        raise RuntimeError("engine inventory platform does not match the native artifact")
    verify_engine_inventory(engine, manifest)
    notices = legal_files(legal_root)

    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / (
        f"unsigned-native-{target_platform}-{manifest['architecture']}.tar.gz"
    )
    launch_instructions = (
        'On Windows, right-click the ZIP and choose "Extract All".\n'
        'Open the extracted folder and double-click "Start Zombie Killer.cmd".\n'
        "This starts the real local desktop app, not the synthetic browser demo.\n"
        "Do not run from inside the archive or move the launcher away from the target folder.\n"
        if target_platform == "windows"
        else "Extract this tar.gz with a tool that preserves symbolic links and Unix permissions.\n"
    )
    instructions = (
        "Unsigned Zombie Killer native verification build\n\n" + launch_instructions + "\n"
        f"Run target/release/{native_name} on the same OS and architecture as this archive.\n"
        "Keep target/release, .cargo-lock, and the complete engine directory together.\n"
        "Tauri uses this Cargo output layout to locate the packaged engine on Unix.\n"
        "Do not move the executable out of target/release or remove hidden files.\n"
        "Install the Tauri system prerequisites for your platform.\n"
        "LICENSE, NOTICE, THIRD_PARTY_NOTICES.md, TRADEMARKS.md, and LICENSES contain\n"
        "the project and bundled asset terms. Preserve them when redistributing this archive.\n"
        "This is not a signed or notarized installer; no release was published.\n"
    ).encode()
    with tarfile.open(archive_path, "w:gz", dereference=False) as archive:
        archive.add(native, arcname=f"target/release/{native_name}")
        archive.add(marker, arcname="target/release/.cargo-lock")
        archive.add(engine, arcname="target/release/engine")
        for notice in notices:
            archive.add(notice, arcname=notice.relative_to(legal_root).as_posix())
        readme = tarfile.TarInfo("README.txt")
        readme.size = len(instructions)
        readme.mode = 0o644
        archive.addfile(readme, io.BytesIO(instructions))
        if target_platform == "windows":
            launcher = tarfile.TarInfo("Start Zombie Killer.cmd")
            launcher.size = len(WINDOWS_LAUNCHER)
            launcher.mode = 0o644
            archive.addfile(launcher, io.BytesIO(WINDOWS_LAUNCHER))
    with tarfile.open(archive_path, "r:gz") as archive:
        for notice in notices:
            stream = archive.extractfile(notice.relative_to(legal_root).as_posix())
            if stream is None or hashlib.sha256(stream.read()).hexdigest() != file_digest(notice):
                raise RuntimeError("archived native legal file does not match")
        for entry in manifest["entries"]:
            member = archive.getmember("target/release/engine/" + entry["path"])
            if entry["type"] == "symlink":
                if not member.issym() or member.linkname != entry["target"]:
                    raise RuntimeError("archived engine inventory symbolic link does not match")
            else:
                stream = archive.extractfile(member)
                if stream is None:
                    raise RuntimeError("archived engine inventory file is missing")
                hasher = hashlib.sha256()
                with stream:
                    while chunk := stream.read(1024 * 1024):
                        hasher.update(chunk)
                digest = hasher.hexdigest()
                if member.size != entry["size"] or digest != entry["sha256"]:
                    raise RuntimeError("archived engine inventory file does not match")
    archives = [archive_path]
    if target_platform == "windows":
        archives.append(windows_zip_from_tar(archive_path))
    (output_dir / "SHA256SUMS").write_text(
        "".join(f"{file_digest(path)}  {path.name}\n" for path in archives), encoding="utf-8"
    )
    return archive_path


def main() -> int:
    repository = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tauri-root", type=Path, default=repository / "apps" / "desktop" / "src-tauri"
    )
    parser.add_argument("--output-dir", type=Path, default=repository / "artifacts" / "native")
    parser.add_argument("--legal-root", type=Path, default=repository)
    parser.add_argument(
        "--platform", choices=("windows", "linux", "darwin"), default=platform.system().lower()
    )
    arguments = parser.parse_args()
    archive = package_native(
        arguments.tauri_root, arguments.output_dir, arguments.platform, arguments.legal_root
    )
    print(f"Packaged and verified unsigned native artifact: {archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
