from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol


@dataclass(frozen=True)
class RepositorySnapshot:
    digest: str
    tracked_count: int
    untracked_count: int


class Digest(Protocol):
    def update(self, value: bytes, /) -> None: ...


def _git(repository: Path, arguments: list[str]) -> bytes:
    completed = subprocess.run(
        ["git", "-C", os.fspath(repository), *arguments],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        command = " ".join(arguments[:2])
        raise RuntimeError(f"Git repository-state command failed ({command}).")
    return completed.stdout


def _framed_update(digest: Digest, label: bytes, value: bytes) -> None:
    for field in (label, value):
        digest.update(len(field).to_bytes(8, "big"))
        digest.update(field)


def _relative_path(repository: Path, raw_path: bytes) -> Path:
    path_text = raw_path.decode("utf-8", errors="surrogateescape")
    relative = PurePosixPath(path_text)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise RuntimeError("Git returned an unsafe repository-relative path.")
    return repository.joinpath(*relative.parts)


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_size,
        left.st_mtime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_size,
        right.st_mtime_ns,
    )


def _hash_path(
    digest: Digest,
    repository: Path,
    raw_path: bytes,
    *,
    missing_allowed: bool,
) -> None:
    path = _relative_path(repository, raw_path)
    _framed_update(digest, b"path", raw_path)
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        if not missing_allowed:
            raise RuntimeError("An untracked file vanished during repository snapshot.") from None
        _framed_update(digest, b"kind", b"missing")
        return

    permissions = stat.S_IMODE(before.st_mode).to_bytes(4, "big")
    _framed_update(digest, b"mode", permissions)
    if stat.S_ISLNK(before.st_mode):
        target = os.readlink(path)
        after = os.lstat(path)
        if not _same_file(before, after):
            raise RuntimeError("A symbolic link changed during repository snapshot.")
        _framed_update(digest, b"kind", b"symlink")
        _framed_update(digest, b"target", os.fsencode(target))
        return
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError("Repository snapshot encountered a non-file entry.")

    _framed_update(digest, b"kind", b"file")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if not _same_file(before, opened):
            raise RuntimeError("A file changed while repository snapshot opened it.")
        while chunk := stream.read(1024 * 1024):
            _framed_update(digest, b"content", chunk)
    after = os.lstat(path)
    if not _same_file(before, after):
        raise RuntimeError("A file changed during repository snapshot.")


def _nul_paths(value: bytes) -> list[bytes]:
    return sorted(item for item in value.split(b"\0") if item)


def _git_views(repository: Path) -> tuple[tuple[bytes, list[str], bytes], ...]:
    commands = (
        (b"head", ["rev-parse", "HEAD"]),
        (b"status", ["status", "--porcelain=v1", "-z", "--untracked-files=all"]),
        (b"index", ["ls-files", "--stage", "-z"]),
        (
            b"unstaged-diff",
            ["diff", "--no-ext-diff", "--no-textconv", "--binary", "--full-index"],
        ),
        (
            b"staged-diff",
            [
                "diff",
                "--cached",
                "--no-ext-diff",
                "--no-textconv",
                "--binary",
                "--full-index",
            ],
        ),
    )
    return tuple((label, arguments, _git(repository, arguments)) for label, arguments in commands)


def _snapshot_once(repository: Path) -> RepositorySnapshot:
    hasher = hashlib.sha256()
    views_before = _git_views(repository)
    for label, _arguments, value in views_before:
        _framed_update(hasher, label, value)

    tracked_before = _git(repository, ["ls-files", "-z"])
    untracked_before = _git(repository, ["ls-files", "--others", "--exclude-standard", "-z"])
    tracked = _nul_paths(tracked_before)
    untracked = _nul_paths(untracked_before)
    for raw_path in tracked:
        _hash_path(hasher, repository, raw_path, missing_allowed=True)
    for raw_path in untracked:
        _hash_path(hasher, repository, raw_path, missing_allowed=False)

    views_after = _git_views(repository)
    tracked_after = _git(repository, ["ls-files", "-z"])
    untracked_after = _git(repository, ["ls-files", "--others", "--exclude-standard", "-z"])
    if (
        views_after != views_before
        or tracked_after != tracked_before
        or untracked_after != untracked_before
    ):
        raise RuntimeError("Release-relevant content changed during repository snapshot.")

    return RepositorySnapshot(
        digest=hasher.hexdigest(),
        tracked_count=len(tracked),
        untracked_count=len(untracked),
    )


def snapshot_repository(repository_root: Path) -> RepositorySnapshot:
    repository = repository_root.resolve(strict=True)
    if not repository.is_dir():
        raise RuntimeError("Repository root is not a directory.")
    observed_root = Path(
        _git(repository, ["rev-parse", "--show-toplevel"]).decode("utf-8", errors="strict").strip()
    ).resolve(strict=True)
    if observed_root != repository:
        raise RuntimeError("Repository-state helper must target the Git worktree root.")

    first = _snapshot_once(repository)
    second = _snapshot_once(repository)
    if first != second:
        raise RuntimeError("Release-relevant content changed during repository snapshot.")
    return second


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a content-bound digest of release-relevant Git worktree state."
    )
    parser.add_argument("--repository-root", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _parse_args()
    try:
        snapshot = snapshot_repository(arguments.repository_root)
    except (OSError, RuntimeError, UnicodeError) as error:
        print(f"Repository snapshot failed safely: {error}", file=sys.stderr)
        return 1
    print(json.dumps(asdict(snapshot), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
