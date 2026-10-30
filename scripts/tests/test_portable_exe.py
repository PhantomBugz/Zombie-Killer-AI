"""Catch payload corruption, unsafe archives, and loss of original package bytes."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
import subprocess
import sys
import warnings
import zipfile
import zlib
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Protocol, cast

import pytest

SCRIPT = Path(__file__).parents[1] / "build-portable-exe.py"


class PortableBuilder(Protocol):
    def build_payload(self, archive: Path) -> bytes: ...

    def publication_lock(self, output_dir: Path) -> AbstractContextManager[None]: ...

    def publish_executable(self, staged: Path, output_dir: Path) -> str: ...

    def check_portable_executable(self, command: list[str], scratch: Path) -> None: ...


def builder() -> PortableBuilder:
    assert SCRIPT.is_file(), "portable payload builder has not been implemented"
    spec = importlib.util.spec_from_file_location("portable_builder", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return cast(PortableBuilder, module)


def fixture_files() -> dict[str, bytes]:
    files = {
        "target/release/zombie-killer.exe": b"MZ-native-fixture",
        "target/release/.cargo-lock": b"",
        "target/release/engine/zombie-killer-engine.exe": b"MZ-engine-fixture",
        "target/release/engine/_internal/data.bin": b"\x00\xffexact runtime bytes",
        "LICENSE": b"project license\r\n",
        "NOTICE": b"PhantomBugz attribution\n",
        "THIRD_PARTY_NOTICES.md": b"third-party terms\n",
        "TRADEMARKS.md": b"trademark terms\n",
        "LICENSES/CC-BY-4.0.txt": b"asset license\n",
        "LICENSES/OFL-1.1.txt": b"font license\n",
        "README.txt": b"original instructions\n",
        "Start Zombie Killer.cmd": b"@echo off\r\n",
    }
    entries = [
        {
            "path": name.removeprefix("target/release/engine/"),
            "type": "file",
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        for name, data in files.items()
        if name.startswith("target/release/engine/")
    ]
    files["target/release/engine/BUILD-MANIFEST.json"] = json.dumps(
        {
            "format": "pyinstaller-onedir",
            "platform": "windows",
            "architecture": "amd64",
            "entries": entries,
        }
    ).encode()
    return files


def archive(root: Path, files: dict[str, bytes]) -> Path:
    path = root / "native fixture.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as output:
        for name, data in files.items():
            entry = zipfile.ZipInfo(name)
            # zipfile normalizes backslashes on Windows when constructing an entry.
            entry.filename = name
            entry.orig_filename = name
            output.writestr(entry, data)
    return path


def decode_independently(payload: bytes) -> dict[str, bytes]:
    assert payload[:8] == b"ZKPORT01"
    length = struct.unpack("<I", payload[8:12])[0]
    manifest = json.loads(payload[12 : 12 + length])
    assert manifest["format"] == 1
    body = zlib.decompress(payload[12 + length :])
    restored = {}
    offset = 0
    for entry in manifest["files"]:
        data = body[offset : offset + entry["size"]]
        assert len(data) == entry["size"]
        assert hashlib.sha256(data).hexdigest() == entry["sha256"]
        restored[entry["path"]] = data
        offset += entry["size"]
    assert offset == len(body)
    return restored


def test_payload_restores_every_original_file_byte_for_byte(tmp_path: Path) -> None:
    files = fixture_files()
    payload = builder().build_payload(archive(tmp_path, files))
    assert decode_independently(payload) == files


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "/absolute",
        "C:/drive",
        "dir\\evil",
        "CON.txt",
        "dir/NUL",
        "a.",
        "a ",
        "dir/../x",
        "a:b",
        "dir//x",
        "LPT1.txt",
        "src/main.rs",
        "debug.pdb",
        "renderer.js.map",
        "renderer.js",
        "package.mjs",
        "engine.py",
        ".env",
    ],
)
def test_unsafe_or_private_files_are_rejected(tmp_path: Path, name: str) -> None:
    files = fixture_files()
    files[name] = b"must not ship"
    with pytest.raises(ValueError):
        builder().build_payload(archive(tmp_path, files))


@pytest.mark.parametrize("extra", ["NOTICE", "notice", "notice/subfile"])
def test_duplicates_and_file_directory_collisions_are_rejected(tmp_path: Path, extra: str) -> None:
    path = archive(tmp_path, fixture_files())
    with zipfile.ZipFile(path, "a") as output, warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        output.writestr(extra, b"collision")
    with pytest.raises(ValueError):
        builder().build_payload(path)


def test_symlink_archive_entry_is_rejected(tmp_path: Path) -> None:
    path = archive(tmp_path, fixture_files())
    entry = zipfile.ZipInfo("link")
    entry.create_system = 3
    entry.external_attr = 0o120777 << 16
    with zipfile.ZipFile(path, "a") as output:
        output.writestr(entry, b"NOTICE")
    with pytest.raises(ValueError):
        builder().build_payload(path)


@pytest.mark.parametrize(
    "change",
    [
        "missing-native",
        "missing-legal",
        "wrong-hash",
        "wrong-size",
        "unlisted-file",
        "wrong-platform",
        "unsafe-entry",
        "duplicate-entry",
    ],
)
def test_required_layout_and_sealed_engine_inventory_are_validated(
    tmp_path: Path, change: str
) -> None:
    files = fixture_files()
    manifest_name = "target/release/engine/BUILD-MANIFEST.json"
    manifest = json.loads(files[manifest_name])
    if change == "missing-native":
        del files["target/release/zombie-killer.exe"]
    elif change == "missing-legal":
        del files["LICENSES/OFL-1.1.txt"]
    elif change == "wrong-hash":
        manifest["entries"][0]["sha256"] = "0" * 64
    elif change == "wrong-size":
        manifest["entries"][0]["size"] += 1
    elif change == "unlisted-file":
        files["target/release/engine/surprise.bin"] = b"extra"
    elif change == "wrong-platform":
        manifest["platform"] = "linux"
    elif change == "unsafe-entry":
        manifest["entries"][0]["path"] = "../escape"
    elif change == "duplicate-entry":
        manifest["entries"].append(manifest["entries"][0])
    files[manifest_name] = json.dumps(manifest).encode()
    with pytest.raises(ValueError):
        builder().build_payload(archive(tmp_path, files))


def test_archive_file_count_limit_is_enforced_before_reading(tmp_path: Path) -> None:
    files = fixture_files()
    files.update({f"extras/{index}.bin": b"" for index in range(4096)})
    with pytest.raises(ValueError, match="count"):
        builder().build_payload(archive(tmp_path, files))


def test_declared_uncompressed_size_limit_is_enforced_before_inflating(tmp_path: Path) -> None:
    path = archive(tmp_path, fixture_files())
    data = bytearray(path.read_bytes())
    first_directory_record = data.index(b"PK\x01\x02")
    # Central-directory uncompressed size is a u32 at byte 24; data stays tiny.
    struct.pack_into("<I", data, first_directory_record + 24, 512 * 1024 * 1024 + 1)
    path.write_bytes(data)
    with pytest.raises(ValueError, match="512 MiB"):
        builder().build_payload(path)


def test_oversized_engine_inventory_is_rejected_before_json_decoding(tmp_path: Path) -> None:
    files = fixture_files()
    name = "target/release/engine/BUILD-MANIFEST.json"
    files[name] += b" " * (4 * 1024 * 1024 + 1 - len(files[name]))
    with pytest.raises(ValueError, match="4 MiB"):
        builder().build_payload(archive(tmp_path, files))


PUBLISH_CHILD = """
import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location('portable_builder', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
try:
    module.publish_executable(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]))
except RuntimeError as error:
    print(error)
else:
    print('published')
"""


def publication_builder() -> PortableBuilder:
    module = builder()
    assert hasattr(module, "publication_lock"), "publication is not serialized yet"
    assert hasattr(module, "publish_executable"), "publication critical section is missing"
    return module


def test_live_concurrent_publisher_is_rejected_without_changing_exe_or_checksum(
    tmp_path: Path,
) -> None:
    module = publication_builder()
    output = tmp_path / "output with spaces"
    output.mkdir()
    staged = tmp_path / "staged.exe"
    staged.write_bytes(b"new executable bytes")
    executable = output / "Zombie Killer.exe"
    checksums = output / "SHA256SUMS"
    executable.write_bytes(b"previous executable")
    checksums.write_bytes(b"previous checksum file\n")
    with module.publication_lock(output):
        child = subprocess.run(
            [sys.executable, "-I", "-c", PUBLISH_CHILD, str(SCRIPT), str(staged), str(output)],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        assert "publication is already in progress" in child.stdout
        assert executable.read_bytes() == b"previous executable"
        assert checksums.read_bytes() == b"previous checksum file\n"
    module.publish_executable(staged, output)
    assert executable.read_bytes() == b"new executable bytes"
    assert checksums.read_text() == (
        hashlib.sha256(b"new executable bytes").hexdigest() + "  Zombie Killer.exe\n"
    )


def test_publication_lock_releases_after_holder_exit_and_preserves_existing_lockfile(
    tmp_path: Path,
) -> None:
    module = publication_builder()
    output = tmp_path / "output"
    output.mkdir()
    lockfile = output / ".portable-publication.lock"
    lockfile.write_bytes(b"existing lockfile bytes must survive")
    holder_code = """
import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location('portable_builder', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
with module.publication_lock(pathlib.Path(sys.argv[2])):
    print('locked', flush=True)
    sys.stdin.readline()
"""
    holder = subprocess.Popen(
        [sys.executable, "-I", "-c", holder_code, str(SCRIPT), str(output)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout and holder.stdout.readline().strip() == "locked"
        holder.kill()  # Only this test-owned helper, modeling an interrupted publisher.
        holder.communicate(timeout=10)
        staged = tmp_path / "staged.exe"
        staged.write_bytes(b"published after interruption")
        module.publish_executable(staged, output)
        assert (output / "Zombie Killer.exe").read_bytes() == b"published after interruption"
        assert (output / "SHA256SUMS").read_text() == (
            hashlib.sha256(b"published after interruption").hexdigest() + "  Zombie Killer.exe\n"
        )
        assert lockfile.read_bytes() == b"existing lockfile bytes must survive"
    finally:
        if holder.poll() is None:
            holder.kill()
            holder.communicate(timeout=10)


def test_staged_check_uses_owned_local_state_instead_of_operator_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    operator_state = tmp_path / "operator local state"
    operator_state.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(operator_state))
    scratch = tmp_path / "owned build scratch"
    scratch.mkdir()
    recorded_state = tmp_path / "used-state.txt"
    check_code = (
        "import os, pathlib, sys; "
        "state = pathlib.Path(os.environ['LOCALAPPDATA']); "
        "state.mkdir(parents=True, exist_ok=True); "
        "(state / 'check-marker').write_text('owned', encoding='utf-8'); "
        "pathlib.Path(sys.argv[1]).write_text(str(state), encoding='utf-8')"
    )

    builder().check_portable_executable(
        [sys.executable, "-I", "-c", check_code, str(recorded_state)], scratch
    )

    used_state = Path(recorded_state.read_text(encoding="utf-8"))
    assert used_state.resolve().is_relative_to(scratch.resolve())
    assert (used_state / "check-marker").read_text(encoding="utf-8") == "owned"
    assert list(operator_state.iterdir()) == []
