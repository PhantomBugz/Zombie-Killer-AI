"""Build a PhantomBugz portable Windows launcher from a verified native ZIP."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import struct
import subprocess
import tempfile
import zipfile
import zlib
from contextlib import contextmanager
from pathlib import Path

MAX_FILES = 4096
MAX_BYTES = 512 * 1024 * 1024
MAX_MANIFEST = 4 * 1024 * 1024
ENGINE = "target/release/engine/"
REQUIRED = (
    "target/release/zombie-killer.exe",
    ENGINE + "BUILD-MANIFEST.json",
    ENGINE + "zombie-killer-engine.exe",
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
    "TRADEMARKS.md",
    "LICENSES/CC-BY-4.0.txt",
    "LICENSES/OFL-1.1.txt",
)
RESERVED = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
}
PRIVATE_SUFFIXES = {
    ".py",
    ".rs",
    ".ts",
    ".tsx",
    ".jsx",
    ".c",
    ".cpp",
    ".h",
    ".cs",
    ".js",
    ".mjs",
    ".cjs",
    ".pdb",
    ".map",
    ".ps1",
    ".pem",
    ".key",
}


def validate_path(name: str) -> str:
    # Conservative ASCII filenames avoid ambiguous Windows Unicode case aliases.
    if not isinstance(name, str) or not name or not name.isascii() or len(name) > 240:
        raise ValueError("unsafe Windows relative path")
    for part in name.split("/"):
        if (
            not part
            or part in (".", "..")
            or part.endswith((".", " "))
            or len(part) > 255
            or any(ord(c) < 32 or c in '\\:<>"|?*' for c in part)
            or part.split(".")[0].upper() in RESERVED
        ):
            raise ValueError(f"unsafe Windows relative path: {name}")
    return name.lower()


def reject_collision(name: str, seen: set[str]) -> None:
    key = validate_path(name)
    parts = key.split("/")
    if key in seen or any("/".join(parts[:i]) in seen for i in range(1, len(parts))):
        raise ValueError(f"duplicate or colliding Windows path: {name}")
    if any(prior.startswith(key + "/") for prior in seen):
        raise ValueError(f"file/directory collision: {name}")
    seen.add(key)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_inventory(files: dict[str, bytes]) -> None:
    for name in REQUIRED:
        if name not in files:
            raise ValueError(f"required portable file is missing: {name}")
    if len(files[ENGINE + "BUILD-MANIFEST.json"]) > MAX_MANIFEST:
        raise ValueError("engine inventory exceeds 4 MiB")
    try:
        manifest = json.loads(files[ENGINE + "BUILD-MANIFEST.json"])
        if (
            manifest["format"] != "pyinstaller-onedir"
            or manifest["platform"] != "windows"
            or manifest["architecture"] not in ("amd64", "x86_64")
        ):
            raise ValueError("engine inventory must identify Windows x64 onedir")
        entries = manifest["entries"]
        if not isinstance(entries, list) or len(entries) > MAX_FILES:
            raise ValueError("invalid engine inventory count")
        seen: set[str] = set()
        expected: set[str] = set()
        for entry in entries:
            if set(entry) != {"path", "type", "size", "sha256"} or entry["type"] != "file":
                raise ValueError("engine inventory contains a special entry")
            reject_collision(entry["path"], seen)
            name = ENGINE + entry["path"]
            data = files.get(name)
            if (
                data is None
                or type(entry["size"]) is not int
                or len(data) != entry["size"]
                or digest(data) != entry["sha256"]
            ):
                raise ValueError("engine inventory size/hash mismatch")
            expected.add(name)
        actual = {name for name in files if name.startswith(ENGINE)}
        if actual != expected | {ENGINE + "BUILD-MANIFEST.json"}:
            raise ValueError("engine inventory differs from source ZIP")
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError("invalid engine inventory") from error


def build_payload(archive: Path) -> bytes:
    """Validate first, then serialize exact ZIP file bytes in original order."""
    files: dict[str, bytes] = {}
    seen: set[str] = set()
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        if len(entries) > MAX_FILES:
            raise ValueError("archive entry count exceeds 4096")
        total = 0
        for entry in entries:
            name = entry.filename
            if entry.orig_filename != name or entry.flag_bits & 1:
                raise ValueError("encrypted or NUL-containing ZIP entries are unsupported")
            mode = entry.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if entry.is_dir():
                validate_path(name[:-1])
                if kind not in (0, stat.S_IFDIR):
                    raise ValueError("special ZIP directory entry")
                continue
            if kind not in (0, stat.S_IFREG):
                raise ValueError("special ZIP entries are unsupported")
            reject_collision(name, seen)
            parts = name.lower().split("/")
            if Path(name).suffix.lower() in PRIVATE_SUFFIXES or any(
                part in ("src", "source", "tests", "test", ".git", ".env", "credentials")
                or part.startswith(".env.")
                for part in parts
            ):
                raise ValueError(f"project sources/debug symbols/credentials must not ship: {name}")
            total += entry.file_size
            if total > MAX_BYTES:
                raise ValueError("archive uncompressed size exceeds 512 MiB")
            with source.open(entry) as stream:
                data = stream.read(entry.file_size + 1)
            if len(data) != entry.file_size:
                raise ValueError("ZIP file size mismatch")
            files[name] = data
    verify_inventory(files)
    manifest = json.dumps(
        {
            "format": 1,
            "files": [
                {"path": name, "size": len(data), "sha256": digest(data)}
                for name, data in files.items()
            ],
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(manifest) > MAX_MANIFEST:
        raise ValueError("payload manifest exceeds 4 MiB")
    compressor = zlib.compressobj(level=9)
    compressed = b"".join(compressor.compress(data) for data in files.values()) + compressor.flush()
    return b"ZKPORT01" + struct.pack("<I", len(manifest)) + manifest + compressed


@contextmanager
def publication_lock(output_dir: Path):
    # Keep the inode/file in place: OS locks disappear when the owning handle or
    # process exits. Deleting a stale lock file could split competing publishers.
    with (output_dir / ".portable-publication.lock").open("a+b") as lock_file:
        if os.name == "nt":
            import msvcrt

            lock_file.seek(0)
            try:
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as error:
                raise RuntimeError(
                    f"portable publication is already in progress for {output_dir}"
                ) from error
            try:
                yield
            finally:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise RuntimeError(
                    f"portable publication is already in progress for {output_dir}"
                ) from error
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def publish_executable(staged: Path, output_dir: Path) -> str:
    with publication_lock(output_dir):
        final = output_dir / "Zombie Killer.exe"
        descriptor, name = tempfile.mkstemp(prefix=".Zombie Killer.", suffix=".exe", dir=output_dir)
        os.close(descriptor)
        candidate = Path(name)
        try:
            shutil.copyfile(staged, candidate)
            os.replace(candidate, final)
        finally:
            candidate.unlink(missing_ok=True)
        with final.open("rb") as stream:
            checksum = hashlib.file_digest(stream, "sha256").hexdigest()
        (output_dir / "SHA256SUMS").write_text(f"{checksum}  Zombie Killer.exe\n", encoding="utf-8")
        return checksum


def check_portable_executable(command: list[str], scratch: Path) -> None:
    """Run the staged launcher against build-owned local application data."""
    local_state = scratch / "portable-check-localappdata"
    local_state.mkdir()
    environment = os.environ.copy()
    environment["LOCALAPPDATA"] = str(local_state)
    subprocess.run(command, check=True, env=environment)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    payload = build_payload(args.archive)
    # Each build has an owned target directory, so concurrent builds cannot swap payloads.
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (repository / "target").mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="zk-portable-build-", dir=repository / "target"
    ) as scratch:
        root = Path(scratch)
        packed = root / "payload.zk"
        packed.write_bytes(payload)
        env = os.environ.copy()
        env["ZK_PORTABLE_PAYLOAD"] = str(packed)
        env["ZK_PORTABLE_SHA256"] = digest(payload)
        subprocess.run(
            [
                "cargo",
                "+1.97.1",
                "build",
                "--release",
                "--locked",
                "--manifest-path",
                str(repository / "tools/portable-launcher/Cargo.toml"),
                "--target-dir",
                str(root / "cargo-target"),
            ],
            env=env,
            cwd=repository,
            check=True,
        )
        executable = root / "cargo-target/release/zombie-killer-portable.exe"
        staged = root / "Zombie Killer.exe"
        shutil.copyfile(executable, staged)
        # --check completes verification and cleanup before replacing any previous output.
        check_portable_executable([str(staged), "--check"], root)
        checksum = publish_executable(staged, args.output_dir)
        final = args.output_dir / "Zombie Killer.exe"
        print(
            json.dumps(
                {
                    "executable": str(final.resolve()),
                    "sha256": checksum,
                    "payload_sha256": digest(payload),
                }
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
