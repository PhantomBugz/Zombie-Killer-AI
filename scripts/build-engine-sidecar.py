"""Build, validate, smoke, and atomically publish the fixed engine resource."""

from __future__ import annotations

import sys

if __name__ == "__main__" and not sys.flags.isolated:
    raise SystemExit("the sidecar builder must be launched with isolated Python (-I)")

import hashlib
import importlib.metadata
import json
import os
import platform
import stat
import subprocess
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID

PYINSTALLER_VERSION = "6.18.0"
SOURCE_DATE_EPOCH = "1700000000"
_GENERATED_RELATIVE_PATHS = {
    ".sidecar-build": Path("apps/desktop/src-tauri/.sidecar-build"),
    ".engine-next": Path("apps/desktop/src-tauri/resources/.engine-next"),
    ".engine-previous": Path("apps/desktop/src-tauri/resources/.engine-previous"),
    ".engine-publish.json": Path("apps/desktop/src-tauri/resources/.engine-publish.json"),
    ".engine-publish.json.next": Path("apps/desktop/src-tauri/resources/.engine-publish.json.next"),
    ".engine-build.lock": Path("apps/desktop/src-tauri/resources/.engine-build.lock"),
}
_PUBLICATION_PHASES = {"prepared", "previous-moved", "candidate-committed"}
_PUBLICATION_VERSION = 1
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_MAX_MANIFEST_ENTRIES = 20_000
_MAX_SYMLINK_EXPANSIONS = _MAX_MANIFEST_ENTRIES * 8
_MAX_SYMLINK_FOLLOWS = 64
_MAX_SYMLINK_PENDING_COMPONENTS = 512


def _lexical_absolute(path: Path) -> Path:
    """Return an absolute normalized spelling without dereferencing any component."""
    return Path(os.path.abspath(os.fspath(path)))


def _same_lexical_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.fspath(_lexical_absolute(left))) == os.path.normcase(
        os.fspath(_lexical_absolute(right))
    )


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _require_direct_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise RuntimeError("generated sidecar ancestor does not exist") from error
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        raise RuntimeError("generated sidecar ancestor is a symbolic link or reparse point")
    if not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("generated sidecar ancestor is not a direct directory")


def _assert_safe_ancestors(path: Path, root: Path) -> None:
    lexical_root = _lexical_absolute(root)
    lexical_parent = _lexical_absolute(path).parent
    try:
        relative_parent = lexical_parent.relative_to(lexical_root)
    except ValueError as error:
        raise RuntimeError("generated sidecar path escaped the repository") from error
    current = lexical_root
    _require_direct_directory(current)
    for component in relative_parent.parts:
        current /= component
        _require_direct_directory(current)


def _ensure_resources_directory(root: Path) -> Path:
    resources = _lexical_absolute(root) / "apps/desktop/src-tauri/resources"
    _assert_safe_ancestors(resources, root)
    metadata = _lstat_optional(resources)
    if metadata is None:
        os.mkdir(resources)
        _sync_directory(resources.parent)
    _require_direct_directory(resources)
    return resources


def _is_lexically_within(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath(
            [
                os.path.normcase(os.fspath(_lexical_absolute(path))),
                os.path.normcase(os.fspath(_lexical_absolute(root))),
            ]
        ) == os.path.normcase(os.fspath(_lexical_absolute(root)))
    except ValueError:
        return False


def _require_isolated_runtime(repository: Path) -> None:
    if not sys.flags.isolated:
        raise RuntimeError("the sidecar builder requires isolated Python (-I)")
    runtime_modules = (hashlib, importlib.metadata, json, platform, stat, subprocess, tempfile)
    for module in runtime_modules:
        origin = getattr(module, "__file__", None)
        if origin is not None and _is_lexically_within(Path(origin), repository):
            raise RuntimeError("refusing a repository-shadowed builder dependency")


def _generated_target(path: Path, root: Path) -> Path:
    target = _lexical_absolute(path)
    relative = _GENERATED_RELATIVE_PATHS.get(target.name)
    if relative is None or not _same_lexical_path(target, _lexical_absolute(root) / relative):
        raise RuntimeError("refusing anything except an exact generated sidecar path")
    _assert_safe_ancestors(target, root)
    return target


def _rename_noreplace_at(
    source_descriptor: int,
    source: str,
    target_descriptor: int,
    target: str,
) -> None:
    import ctypes

    library = ctypes.CDLL(None, use_errno=True)
    rename: Callable[..., int] | None = None
    flags = 0
    if sys.platform.startswith("linux"):
        try:
            rename = library.renameat2
        except AttributeError as error:
            raise RuntimeError("safe no-replace rename is unavailable") from error
        flags = 0x1  # RENAME_NOREPLACE
    elif sys.platform == "darwin":
        try:
            rename = library.renameatx_np
        except AttributeError as error:
            raise RuntimeError("safe no-replace rename is unavailable") from error
        flags = 0x4  # RENAME_EXCL
    else:
        raise RuntimeError("safe no-replace rename is unavailable on this POSIX platform")
    if rename is None:
        raise RuntimeError("safe no-replace rename is unavailable")
    rename.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    if (
        rename(
            source_descriptor,
            os.fsencode(source),
            target_descriptor,
            os.fsencode(target),
            flags,
        )
        != 0
    ):
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), source)


def _private_tombstone_at(parent_descriptor: int) -> tuple[str, int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    for _attempt in range(128):
        name = f".zk-delete-{os.urandom(16).hex()}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            continue
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        try:
            opened = os.fstat(descriptor)
            current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or not os.path.samestat(opened, current)
                or stat.S_IMODE(opened.st_mode) & 0o077
            ):
                raise RuntimeError("private deletion tombstone is unsafe")
        except BaseException:
            os.close(descriptor)
            raise
        return name, descriptor, opened
    raise RuntimeError("could not allocate a private deletion tombstone")


def _remove_entry_at(
    parent_descriptor: int,
    name: str,
    display_path: Path,
    *,
    final: bool = False,
    phase_hook: Callable[[str, Path], None] | None = None,
) -> None:
    try:
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    is_link = stat.S_ISLNK(metadata.st_mode)
    if final and is_link:
        raise RuntimeError("refusing a generated symbolic link or reparse point")
    is_regular = stat.S_ISREG(metadata.st_mode)
    is_directory = stat.S_ISDIR(metadata.st_mode)
    if is_regular and metadata.st_nlink != 1:
        raise RuntimeError("refusing a generated hard link")
    if not (is_link or is_regular or is_directory):
        raise RuntimeError("refusing an unsupported generated filesystem entry")
    tombstone, tombstone_descriptor, tombstone_metadata = _private_tombstone_at(parent_descriptor)
    moved = False
    try:
        if phase_hook is not None:
            phase_hook("before-entry-quarantine", display_path)
        _rename_noreplace_at(
            parent_descriptor,
            name,
            tombstone_descriptor,
            "entry",
        )
        moved = True
        quarantined = os.stat(
            "entry",
            dir_fd=tombstone_descriptor,
            follow_symlinks=False,
        )
        if not os.path.samestat(metadata, quarantined):
            try:
                _rename_noreplace_at(
                    tombstone_descriptor,
                    "entry",
                    parent_descriptor,
                    name,
                )
                moved = False
            except OSError as rollback_error:
                raise RuntimeError(
                    "generated entry identity changed; private tombstone preserves it"
                ) from rollback_error
            raise RuntimeError("generated entry identity changed before quarantine")
        if is_regular and quarantined.st_nlink != 1:
            try:
                _rename_noreplace_at(
                    tombstone_descriptor,
                    "entry",
                    parent_descriptor,
                    name,
                )
                moved = False
            except OSError as rollback_error:
                raise RuntimeError(
                    "generated hard link is preserved in its private tombstone"
                ) from rollback_error
            raise RuntimeError("refusing a generated hard link")
        if is_link:
            os.unlink("entry", dir_fd=tombstone_descriptor)
            moved = False
        elif is_regular:
            current = os.stat(
                "entry",
                dir_fd=tombstone_descriptor,
                follow_symlinks=False,
            )
            if not os.path.samestat(quarantined, current):
                raise RuntimeError("private file identity changed before deletion")
            os.unlink("entry", dir_fd=tombstone_descriptor)
            moved = False
        else:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open("entry", flags, dir_fd=tombstone_descriptor)
            try:
                opened = os.fstat(descriptor)
                if not os.path.samestat(quarantined, opened):
                    raise RuntimeError("private directory identity changed before traversal")
                with os.scandir(descriptor) as children:
                    child_names = sorted(child.name for child in children)
                for child_name in child_names:
                    _remove_entry_at(
                        descriptor,
                        child_name,
                        display_path / child_name,
                        final=False,
                        phase_hook=phase_hook,
                    )
                current = os.stat(
                    "entry",
                    dir_fd=tombstone_descriptor,
                    follow_symlinks=False,
                )
                if not os.path.samestat(opened, current):
                    raise RuntimeError("private directory identity changed during deletion")
            finally:
                os.close(descriptor)
            os.rmdir("entry", dir_fd=tombstone_descriptor)
            moved = False
    except BaseException:
        if moved:
            try:
                _rename_noreplace_at(
                    tombstone_descriptor,
                    "entry",
                    parent_descriptor,
                    name,
                )
                moved = False
            except OSError as rollback_error:
                raise RuntimeError(
                    "failed deletion is preserved in its private tombstone"
                ) from rollback_error
        raise
    finally:
        os.close(tombstone_descriptor)
        if not moved:
            current_tombstone = os.stat(
                tombstone,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if not os.path.samestat(tombstone_metadata, current_tombstone):
                raise RuntimeError("private deletion tombstone identity changed")
            os.rmdir(tombstone, dir_fd=parent_descriptor)


def _windows_directory_entries(handle: int) -> list[tuple[str, int, int]]:
    import ctypes
    from ctypes import wintypes

    get_information = ctypes.WinDLL("kernel32", use_last_error=True).GetFileInformationByHandleEx
    get_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    get_information.restype = wintypes.BOOL
    entries: list[tuple[str, int, int]] = []
    while True:
        buffer = ctypes.create_string_buffer(64 * 1024)
        if not get_information(handle, 10, buffer, len(buffer)):  # FileIdBothDirectoryInfo
            error = ctypes.get_last_error()
            if error == 18:  # ERROR_NO_MORE_FILES
                break
            raise ctypes.WinError(error)
        raw = buffer.raw
        offset = 0
        while True:
            next_offset = int.from_bytes(raw[offset : offset + 4], "little")
            attributes = int.from_bytes(raw[offset + 56 : offset + 60], "little")
            name_length = int.from_bytes(raw[offset + 60 : offset + 64], "little")
            file_id = int.from_bytes(raw[offset + 96 : offset + 104], "little")
            name = raw[offset + 104 : offset + 104 + name_length].decode("utf-16-le")
            if name not in {".", ".."}:
                entries.append((name, file_id, attributes))
            if next_offset == 0:
                break
            offset += next_offset
    return sorted(entries, key=lambda entry: entry[0])


def _windows_directory_names(handle: int) -> list[str]:
    return [name for name, _file_id, _attributes in _windows_directory_entries(handle)]


def _open_windows_entry_handle(path: Path, *, access: int, share: int = 0x7) -> int:
    import ctypes
    from ctypes import wintypes

    create_file = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        access,
        share,
        None,
        3,  # OPEN_EXISTING
        0x02000000 | 0x00200000,  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
        None,
    )
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    return int(handle)


def _open_windows_relative_handle(
    parent_handle: int,
    name: str,
    *,
    access: int,
    directory: bool | None,
    share: int = 0x7,
) -> int:
    import ctypes
    from ctypes import wintypes

    class UnicodeString(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.USHORT),
            ("maximum_length", wintypes.USHORT),
            ("buffer", wintypes.LPWSTR),
        ]

    class ObjectAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.ULONG),
            ("root_directory", wintypes.HANDLE),
            ("object_name", ctypes.POINTER(UnicodeString)),
            ("attributes", wintypes.ULONG),
            ("security_descriptor", wintypes.LPVOID),
            ("security_quality_of_service", wintypes.LPVOID),
        ]

    class IoStatusBlock(ctypes.Structure):
        _fields_ = [("status", wintypes.LPVOID), ("information", ctypes.c_size_t)]

    name_buffer = ctypes.create_unicode_buffer(name)
    name_bytes = len(name.encode("utf-16-le"))
    unicode_name = UnicodeString(
        name_bytes,
        name_bytes + 2,
        ctypes.cast(name_buffer, wintypes.LPWSTR),
    )
    object_attributes = ObjectAttributes(
        ctypes.sizeof(ObjectAttributes),
        parent_handle,
        ctypes.pointer(unicode_name),
        0x40,  # OBJ_CASE_INSENSITIVE
        None,
        None,
    )
    io_status = IoStatusBlock()
    options = 0x00200000 | 0x00004000 | 0x20  # OPEN_REPARSE | BACKUP_INTENT | SYNC
    if directory is True:
        options |= 0x1  # FILE_DIRECTORY_FILE
    elif directory is False:
        options |= 0x40  # FILE_NON_DIRECTORY_FILE
    handle = wintypes.HANDLE()
    nt_open_file = ctypes.WinDLL("ntdll").NtOpenFile
    nt_open_file.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.ULONG,
        ctypes.POINTER(ObjectAttributes),
        ctypes.POINTER(IoStatusBlock),
        wintypes.ULONG,
        wintypes.ULONG,
    ]
    nt_open_file.restype = wintypes.LONG
    status = nt_open_file(
        ctypes.byref(handle),
        access | 0x00100000,  # SYNCHRONIZE is required for synchronous I/O.
        ctypes.byref(object_attributes),
        ctypes.byref(io_status),
        share,
        options,
    )
    if status < 0:
        rtl_status_to_error = ctypes.WinDLL("ntdll").RtlNtStatusToDosError
        rtl_status_to_error.argtypes = [wintypes.LONG]
        rtl_status_to_error.restype = wintypes.ULONG
        raise ctypes.WinError(rtl_status_to_error(status))
    if handle.value is None:
        raise RuntimeError("Windows returned an invalid relative file handle")
    return int(handle.value)


def _close_windows_handle(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    close_handle = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    if not close_handle(handle):
        raise ctypes.WinError(ctypes.get_last_error())


def _windows_handle_metadata(handle: int) -> tuple[int, int, int, int]:
    import ctypes
    from ctypes import wintypes

    class FileInformation(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("creation_time", wintypes.FILETIME),
            ("access_time", wintypes.FILETIME),
            ("write_time", wintypes.FILETIME),
            ("volume_serial", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        ]

    get_information = ctypes.WinDLL("kernel32", use_last_error=True).GetFileInformationByHandle
    get_information.argtypes = [wintypes.HANDLE, ctypes.POINTER(FileInformation)]
    get_information.restype = wintypes.BOOL
    information = FileInformation()
    if not get_information(handle, ctypes.byref(information)):
        raise ctypes.WinError(ctypes.get_last_error())
    file_id = (information.file_index_high << 32) | information.file_index_low
    size = (information.size_high << 32) | information.size_low
    return information.attributes, information.links, file_id, size


def _flush_windows_handle(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    flush = ctypes.WinDLL("kernel32", use_last_error=True).FlushFileBuffers
    flush.argtypes = [wintypes.HANDLE]
    flush.restype = wintypes.BOOL
    if not flush(handle):
        raise ctypes.WinError(ctypes.get_last_error())


def _hash_windows_handle(handle: int) -> tuple[str, int]:
    import ctypes
    from ctypes import wintypes

    before = _windows_handle_metadata(handle)
    set_pointer = ctypes.WinDLL("kernel32", use_last_error=True).SetFilePointerEx
    set_pointer.argtypes = [
        wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.DWORD,
    ]
    set_pointer.restype = wintypes.BOOL
    if not set_pointer(handle, 0, None, 0):  # FILE_BEGIN
        raise ctypes.WinError(ctypes.get_last_error())
    read_file = ctypes.WinDLL("kernel32", use_last_error=True).ReadFile
    read_file.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    read_file.restype = wintypes.BOOL
    buffer = ctypes.create_string_buffer(1024 * 1024)
    digest = hashlib.sha256()
    total = 0
    while True:
        read = wintypes.DWORD()
        if not read_file(handle, buffer, len(buffer), ctypes.byref(read), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if read.value == 0:
            break
        digest.update(buffer.raw[: read.value])
        total += read.value
    after = _windows_handle_metadata(handle)
    if before != after or total != before[3]:
        raise RuntimeError("sidecar file changed while hashing")
    return digest.hexdigest(), total


def _delete_windows_handle(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    class FileDispositionInformation(ctypes.Structure):
        _fields_ = [("delete_file", wintypes.BOOL)]

    disposition = FileDispositionInformation(True)
    set_information = ctypes.WinDLL("kernel32", use_last_error=True).SetFileInformationByHandle
    set_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    set_information.restype = wintypes.BOOL
    if not set_information(
        handle,
        4,  # FileDispositionInfo
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
    ):
        raise ctypes.WinError(ctypes.get_last_error())


def _seal_candidate_durable(
    candidate: Path,
    *,
    phase_hook: Callable[[str, Path], None] | None = None,
) -> None:
    def checkpoint(phase: str, path: Path) -> None:
        if phase_hook is not None:
            phase_hook(phase, path)

    if os.name == "nt":
        metadata = candidate.lstat()
        root_handle = _open_windows_entry_handle(
            candidate,
            access=0x40000000 | 0x80 | 0x1,
            share=0x1,
        )
        try:

            def seal_windows(
                handle: int,
                path: Path,
                *,
                expected_file_id: int,
            ) -> None:
                attributes, links, file_id, _size = _windows_handle_metadata(handle)
                if file_id != expected_file_id:
                    raise RuntimeError("candidate identity changed while sealing")
                is_reparse = bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
                if is_reparse:
                    checkpoint("sealed-link", path)
                    return
                is_directory = bool(attributes & getattr(stat, "FILE_ATTRIBUTE_DIRECTORY", 0x10))
                if is_directory:
                    for name, child_file_id, child_attributes in _windows_directory_entries(handle):
                        child_reparse = bool(
                            child_attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                        )
                        child_directory = bool(
                            child_attributes & getattr(stat, "FILE_ATTRIBUTE_DIRECTORY", 0x10)
                        )
                        child_access = 0x80 if child_reparse else 0x40000000 | 0x80
                        if child_directory and not child_reparse:
                            child_access |= 0x1
                        child_handle = _open_windows_relative_handle(
                            handle,
                            name,
                            access=child_access,
                            directory=None if child_reparse else child_directory,
                            share=0x1,
                        )
                        try:
                            seal_windows(
                                child_handle,
                                path / name,
                                expected_file_id=child_file_id,
                            )
                        finally:
                            _close_windows_handle(child_handle)
                    _flush_windows_handle(handle)
                    checkpoint("sealed-directory", path)
                    return
                if links != 1:
                    raise RuntimeError("candidate contains a hard-linked file")
                _flush_windows_handle(handle)
                checkpoint("sealed-file", path)

            seal_windows(root_handle, candidate, expected_file_id=metadata.st_ino)
        finally:
            _close_windows_handle(root_handle)
        return

    def seal_at(parent_descriptor: int, name: str, path: Path) -> None:
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode):
            checkpoint("sealed-link", path)
            return
        if stat.S_ISREG(metadata.st_mode):
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(name, flags, dir_fd=parent_descriptor)
            try:
                if not os.path.samestat(metadata, os.fstat(descriptor)):
                    raise RuntimeError("candidate identity changed while sealing")
                if metadata.st_nlink != 1:
                    raise RuntimeError("candidate contains a hard-linked file")
                os.fsync(descriptor)
                checkpoint("sealed-file", path)
            finally:
                os.close(descriptor)
            return
        if not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError("candidate contains an unsupported filesystem entry")
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        try:
            if not os.path.samestat(metadata, os.fstat(descriptor)):
                raise RuntimeError("candidate identity changed while sealing")
            with os.scandir(descriptor) as children:
                child_names = sorted(child.name for child in children)
            for child_name in child_names:
                seal_at(descriptor, child_name, path / child_name)
            os.fsync(descriptor)
            checkpoint("sealed-directory", path)
        finally:
            os.close(descriptor)

    parent_metadata = candidate.parent.lstat()
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_descriptor = os.open(candidate.parent, flags)
    try:
        if not os.path.samestat(parent_metadata, os.fstat(parent_descriptor)):
            raise RuntimeError("candidate parent identity changed while sealing")
        seal_at(parent_descriptor, candidate.name, candidate)
    finally:
        os.close(parent_descriptor)


def _remove_entry_windows(
    path: Path,
    *,
    final: bool = False,
    phase_hook: Callable[[str, Path], None] | None = None,
) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if not (
        stat.S_ISREG(metadata.st_mode)
        or stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse_point(metadata)
    ):
        raise RuntimeError("refusing an unsupported generated filesystem entry")
    access = 0x1 | 0x80 | 0x00010000  # LIST/READ_DATA | READ_ATTRIBUTES | DELETE
    handle = _open_windows_entry_handle(path, access=access)

    def remove_opened(
        current_handle: int,
        display_path: Path,
        *,
        expected_file_id: int,
        is_final: bool,
    ) -> None:
        attributes, links, file_id, _size = _windows_handle_metadata(current_handle)
        if file_id != expected_file_id:
            raise RuntimeError("generated entry identity changed before deletion")
        is_reparse = bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        if is_final and is_reparse:
            raise RuntimeError("refusing a generated symbolic link or reparse point")
        if is_reparse:
            if phase_hook is not None:
                phase_hook("before-leaf-delete", display_path)
            _delete_windows_handle(current_handle)
            return
        is_directory = bool(attributes & getattr(stat, "FILE_ATTRIBUTE_DIRECTORY", 0x10))
        if not is_directory:
            if links != 1:
                raise RuntimeError("refusing a generated hard link")
            if phase_hook is not None:
                phase_hook("before-leaf-delete", display_path)
            _delete_windows_handle(current_handle)
            return
        for name, child_file_id, child_attributes in _windows_directory_entries(current_handle):
            child_is_reparse = bool(
                child_attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            )
            child_is_directory = bool(
                child_attributes & getattr(stat, "FILE_ATTRIBUTE_DIRECTORY", 0x10)
            )
            try:
                child_handle = _open_windows_relative_handle(
                    current_handle,
                    name,
                    access=access,
                    directory=None if child_is_reparse else child_is_directory,
                )
            except OSError as error:
                raise RuntimeError("generated entry identity changed before deletion") from error
            try:
                remove_opened(
                    child_handle,
                    display_path / name,
                    expected_file_id=child_file_id,
                    is_final=False,
                )
            finally:
                _close_windows_handle(child_handle)
        _delete_windows_handle(current_handle)

    try:
        remove_opened(
            handle,
            path,
            expected_file_id=metadata.st_ino,
            is_final=final,
        )
    finally:
        _close_windows_handle(handle)


def _remove_generated(
    path: Path,
    root: Path,
    *,
    phase_hook: Callable[[str, Path], None] | None = None,
) -> None:
    target = _generated_target(path, root)
    if os.name == "nt":
        _remove_entry_windows(target, final=True, phase_hook=phase_hook)
        if _lstat_optional(target) is not None:
            raise RuntimeError("generated entry identity changed during deletion")
        return
    parent_metadata = target.parent.lstat()
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_descriptor = os.open(target.parent, flags)
    try:
        if not os.path.samestat(parent_metadata, os.fstat(parent_descriptor)):
            raise RuntimeError("generated parent identity changed before deletion")
        _remove_entry_at(
            parent_descriptor,
            target.name,
            target,
            final=True,
            phase_hook=phase_hook,
        )
    finally:
        os.close(parent_descriptor)


def _lstat_optional(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _direct_engine_directory_exists(path: Path, *, label: str) -> bool:
    metadata = _lstat_optional(path)
    if metadata is None:
        return False
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        raise RuntimeError(f"{label} is a symbolic link or reparse point")
    if not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError(f"{label} is not a direct directory")
    return True


def _fixed_destination(path: Path, root: Path) -> Path:
    destination = _lexical_absolute(path)
    expected = _lexical_absolute(root) / "apps/desktop/src-tauri/resources/engine"
    if not _same_lexical_path(destination, expected):
        raise RuntimeError("refusing anything except the fixed sidecar destination")
    _assert_safe_ancestors(destination, root)
    return destination


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _windows_move(source: Path, target: Path, *, replace: bool) -> None:
    import ctypes
    from ctypes import wintypes

    move_file_ex = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
    move_file_ex.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    move_file_ex.restype = wintypes.BOOL
    flags = 0x8 | (0x1 if replace else 0)  # WRITE_THROUGH | REPLACE_EXISTING
    if not move_file_ex(str(source), str(target), flags):
        raise ctypes.WinError(ctypes.get_last_error())


def _rename_durable(source: Path, target: Path) -> None:
    if os.name == "nt":
        _windows_move(source, target, replace=False)
        return
    source.rename(target)
    _sync_directory(target.parent)
    if source.parent != target.parent:
        _sync_directory(source.parent)


def _replace_durable(source: Path, target: Path) -> None:
    if os.name == "nt":
        _windows_move(source, target, replace=True)
        return
    os.replace(source, target)
    _sync_directory(target.parent)
    if source.parent != target.parent:
        _sync_directory(source.parent)


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("publication journal write made no progress")
        offset += written


def _write_publication_journal(
    journal: Path,
    root: Path,
    *,
    phase: str,
    had_destination: bool,
) -> None:
    if phase not in _PUBLICATION_PHASES:
        raise RuntimeError("invalid sidecar publication phase")
    journal = _generated_target(journal, root)
    temporary = _generated_target(journal.with_name(f"{journal.name}.next"), root)
    _remove_generated(temporary, root)
    existing = _lstat_optional(journal)
    if existing is not None and (
        stat.S_ISLNK(existing.st_mode)
        or _is_reparse_point(existing)
        or not stat.S_ISREG(existing.st_mode)
        or existing.st_nlink != 1
    ):
        raise RuntimeError("sidecar publication journal is not a direct regular file")
    record = {
        "version": _PUBLICATION_VERSION,
        "phase": phase,
        "had_destination": had_destination,
        "candidate": ".engine-next",
        "destination": "engine",
        "previous": ".engine-previous",
    }
    payload = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _replace_durable(temporary, journal)


def _load_publication_journal(journal: Path, root: Path) -> dict[str, object] | None:
    journal = _generated_target(journal, root)
    metadata = _lstat_optional(journal)
    if metadata is None:
        return None
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_reparse_point(metadata)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise RuntimeError("sidecar publication journal is not a direct regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(journal, flags)
    try:
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            parsed = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("sidecar publication journal is corrupt") from error
    if not isinstance(parsed, dict):
        raise RuntimeError("sidecar publication journal has an invalid record")
    expected_strings = {
        "candidate": ".engine-next",
        "destination": "engine",
        "previous": ".engine-previous",
    }
    if (
        parsed.get("version") != _PUBLICATION_VERSION
        or parsed.get("phase") not in _PUBLICATION_PHASES
        or type(parsed.get("had_destination")) is not bool
        or any(parsed.get(key) != value for key, value in expected_strings.items())
        or set(parsed)
        != {
            "version",
            "phase",
            "had_destination",
            "candidate",
            "destination",
            "previous",
        }
    ):
        raise RuntimeError("sidecar publication journal has an invalid record")
    return parsed


def _clear_publication_journal(journal: Path, root: Path) -> None:
    _remove_generated(journal.with_name(f"{journal.name}.next"), root)
    _remove_generated(journal, root)
    _sync_directory(_lexical_absolute(journal).parent)


def _rollback_publication(
    candidate: Path,
    destination: Path,
    previous: Path,
    journal: Path,
    root: Path,
    *,
    had_destination: bool,
) -> None:
    candidate_exists = _direct_engine_directory_exists(candidate, label="sidecar candidate")
    destination_exists = _direct_engine_directory_exists(
        destination, label="fixed sidecar destination"
    )
    previous_exists = _direct_engine_directory_exists(previous, label="previous sidecar")
    if had_destination:
        if previous_exists:
            if destination_exists:
                if candidate_exists:
                    raise RuntimeError("ambiguous sidecar rollback state preserves every copy")
                _rename_durable(destination, candidate)
                candidate_exists = True
                destination_exists = False
            _rename_durable(previous, destination)
            previous_exists = False
            destination_exists = True
        elif not destination_exists:
            raise RuntimeError("sidecar rollback cannot locate the last-good resource")
        if not destination_exists:
            raise RuntimeError("sidecar rollback did not restore the last-good resource")
    else:
        if previous_exists:
            raise RuntimeError("unexpected previous sidecar preserves every copy")
        if destination_exists:
            if candidate_exists:
                raise RuntimeError("ambiguous sidecar rollback state preserves every copy")
            _rename_durable(destination, candidate)
            candidate_exists = True
    if candidate_exists:
        _remove_generated(candidate, root)
    _clear_publication_journal(journal, root)


def _finish_committed_publication(
    candidate: Path,
    destination: Path,
    previous: Path,
    journal: Path,
    root: Path,
) -> bool:
    candidate_exists = _direct_engine_directory_exists(candidate, label="sidecar candidate")
    destination_exists = _direct_engine_directory_exists(
        destination, label="fixed sidecar destination"
    )
    previous_exists = _direct_engine_directory_exists(previous, label="previous sidecar")
    destination_valid = destination_exists and _engine_tree_is_valid(destination)
    candidate_valid = candidate_exists and _engine_tree_is_valid(candidate)
    previous_valid = previous_exists and _engine_tree_is_valid(previous)
    restored_previous = False
    if (
        destination_exists
        and candidate_exists
        and not (destination_valid and not candidate_valid and not previous_exists)
    ):
        raise RuntimeError("ambiguous committed sidecar state preserves every copy")
    if destination_exists and not destination_valid:
        if not previous_valid or candidate_exists:
            raise RuntimeError("invalid committed sidecar preserves every recoverable copy")
        _rename_durable(destination, candidate)
        candidate_exists = True
        candidate_valid = False
        destination_exists = False
        _rename_durable(previous, destination)
        destination_exists = True
        destination_valid = True
        previous_exists = False
        previous_valid = False
        restored_previous = True
    elif not destination_exists:
        if candidate_valid:
            _rename_durable(candidate, destination)
            destination_exists = True
            destination_valid = True
            candidate_exists = False
            candidate_valid = False
        elif previous_valid:
            _rename_durable(previous, destination)
            destination_exists = True
            destination_valid = True
            previous_exists = False
            previous_valid = False
            restored_previous = True
        else:
            raise RuntimeError("committed sidecar publication has no valid recoverable resource")
    if not destination_exists or not destination_valid or not _engine_tree_is_valid(destination):
        raise RuntimeError("committed sidecar destination failed validation")
    if previous_exists:
        _remove_generated(previous, root)
    if candidate_exists:
        _remove_generated(candidate, root)
    _clear_publication_journal(journal, root)
    return not restored_previous


def _recover_without_journal(
    candidate: Path, destination: Path, previous: Path, journal: Path, root: Path
) -> None:
    candidate_exists = _direct_engine_directory_exists(candidate, label="sidecar candidate")
    destination_exists = _direct_engine_directory_exists(
        destination, label="fixed sidecar destination"
    )
    previous_exists = _direct_engine_directory_exists(previous, label="previous sidecar")
    if previous_exists:
        if destination_exists:
            raise RuntimeError("orphaned previous sidecar preserves every copy")
        _rename_durable(previous, destination)
        destination_exists = True
    if candidate_exists:
        _remove_generated(candidate, root)
    _remove_generated(journal.with_name(f"{journal.name}.next"), root)


def _recover_publication(
    candidate: Path, destination: Path, previous: Path, journal: Path, root: Path
) -> None:
    candidate = _generated_target(candidate, root)
    previous = _generated_target(previous, root)
    journal = _generated_target(journal, root)
    destination = _fixed_destination(destination, root)
    record = _load_publication_journal(journal, root)
    if record is None:
        _recover_without_journal(candidate, destination, previous, journal, root)
        return
    if record["phase"] == "candidate-committed":
        _finish_committed_publication(candidate, destination, previous, journal, root)
        return
    _rollback_publication(
        candidate,
        destination,
        previous,
        journal,
        root,
        had_destination=bool(record["had_destination"]),
    )


@contextmanager
def _exclusive_build_lock(path: Path, root: Path) -> Iterator[None]:
    lock = _generated_target(path, root)
    before = _lstat_optional(lock)
    if before is not None and (
        stat.S_ISLNK(before.st_mode)
        or _is_reparse_point(before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
    ):
        raise RuntimeError("sidecar build lock is not a direct regular file")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock, flags, 0o600)
    locked = False
    try:
        opened = os.fstat(descriptor)
        after = lock.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or not os.path.samestat(opened, after)
            or (before is not None and not os.path.samestat(before, opened))
        ):
            raise RuntimeError("sidecar build lock identity changed while opening")
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(  # type: ignore[attr-defined]
                    descriptor,
                    fcntl.LOCK_EX | fcntl.LOCK_NB,  # type: ignore[attr-defined]
                )
        except OSError as error:
            raise RuntimeError("another sidecar build owns the release resource lock") from error
        locked = True
        os.ftruncate(descriptor, 0)
        _write_all(descriptor, f"{os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
        yield
    finally:
        try:
            if locked:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(  # type: ignore[attr-defined]
                        descriptor,
                        fcntl.LOCK_UN,  # type: ignore[attr-defined]
                    )
        finally:
            os.close(descriptor)


def _hash_descriptor(descriptor: int, expected: os.stat_result) -> tuple[str, int]:
    opened = os.fstat(descriptor)
    if (
        not os.path.samestat(expected, opened)
        or not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
    ):
        raise RuntimeError("sidecar file identity changed before hashing")
    digest = hashlib.sha256()
    total = 0
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
        total += len(chunk)
    after = os.fstat(descriptor)
    if (
        not os.path.samestat(opened, after)
        or total != opened.st_size
        or after.st_size != opened.st_size
        or after.st_mtime_ns != opened.st_mtime_ns
        or after.st_ctime_ns != opened.st_ctime_ns
    ):
        raise RuntimeError("sidecar file changed while hashing")
    return digest.hexdigest(), total


def _sha256(path: Path) -> str:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_reparse_point(metadata)
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise RuntimeError("sidecar hash input is not a direct regular file")
    if metadata.st_nlink != 1:
        raise RuntimeError("sidecar contains a hard-linked file")
    if os.name == "nt":
        handle = _open_windows_entry_handle(path, access=0x1 | 0x80, share=0x1)
        try:
            attributes, links, file_id, _size = _windows_handle_metadata(handle)
            if (
                file_id != metadata.st_ino
                or links != 1
                or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                or attributes & getattr(stat, "FILE_ATTRIBUTE_DIRECTORY", 0x10)
            ):
                raise RuntimeError("sidecar file identity changed before hashing")
            digest, _size = _hash_windows_handle(handle)
            return digest
        finally:
            _close_windows_handle(handle)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        digest, _size = _hash_descriptor(descriptor, metadata)
        current = path.lstat()
        if not os.path.samestat(metadata, current):
            raise RuntimeError("sidecar file identity changed while hashing")
        return digest
    finally:
        os.close(descriptor)


def _inventory(
    root: Path,
    *,
    phase_hook: Callable[[str, Path], None] | None = None,
) -> list[dict[str, object]]:
    lexical_root = _lexical_absolute(root)
    entries: list[dict[str, object]] = []
    known_paths = {os.path.normcase(os.fspath(lexical_root))}
    node_types = {os.path.normcase(os.fspath(lexical_root)): "dir"}
    node_spellings = {os.path.normcase(os.fspath(lexical_root)): os.fspath(lexical_root)}
    link_targets: dict[str, str] = {}
    resolved_link_targets: dict[str, str] = {}

    def checkpoint(phase: str, path: Path) -> None:
        if phase_hook is not None:
            phase_hook(phase, path)

    def relative_path(prefix: str, name: str) -> str:
        return f"{prefix}/{name}" if prefix else name

    def remember(path: Path, kind: str) -> str:
        normalized = os.path.normcase(os.fspath(_lexical_absolute(path)))
        spelling = os.fspath(_lexical_absolute(path))
        previous = node_spellings.get(normalized)
        if previous is not None and previous != spelling:
            raise RuntimeError("sidecar contains a normalized path collision")
        known_paths.add(normalized)
        node_types[normalized] = kind
        node_spellings[normalized] = spelling
        return normalized

    def record_link(path: Path, relative: str, target: str) -> None:
        if os.path.isabs(target) or bool(os.path.splitdrive(target)[0]):
            raise RuntimeError("sidecar contains an absolute symbolic link")
        link_key = remember(path, "symlink")
        link_targets[link_key] = target
        entries.append({"path": relative, "type": "symlink", "target": target})

    def validate_links() -> None:
        normalized_link_targets: dict[str, tuple[str, ...]] = {}
        grouped_targets: dict[str, list[str]] = {}
        for link, target in link_targets.items():
            grouped_targets.setdefault(os.path.normcase(link), []).append(target)
        normalized_link_targets = {
            link: tuple(targets) for link, targets in grouped_targets.items()
        }
        for link, target in link_targets.items():
            resolved_target = _resolve_symbolic_link_target(
                lexical_root,
                Path(link),
                target,
                link_targets,
                node_types,
                normalized_link_targets,
            )
            resolved_link_targets[link] = resolved_target
        for target in resolved_link_targets.values():
            if target not in known_paths:
                raise RuntimeError("sidecar symbolic link target does not exist directly")

    root_metadata = root.lstat()
    if stat.S_ISLNK(root_metadata.st_mode) or _is_reparse_point(root_metadata):
        raise RuntimeError("sidecar staging root is a symbolic link or reparse point")
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise RuntimeError("sidecar staging root is not a direct directory")
    checkpoint("before-root-open", root)

    if os.name == "nt":
        try:
            root_handle = _open_windows_entry_handle(
                root,
                access=0x1 | 0x80,  # FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES
                share=0x1,
            )
        except OSError as error:
            raise RuntimeError("sidecar staging root identity changed before open") from error
        try:
            attributes, _links, file_id, _size = _windows_handle_metadata(root_handle)
            if (
                file_id != root_metadata.st_ino
                or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                or not attributes & getattr(stat, "FILE_ATTRIBUTE_DIRECTORY", 0x10)
            ):
                raise RuntimeError("sidecar staging root identity changed or is a reparse point")

            def visit_windows(
                directory_handle: int,
                directory_path: Path,
                prefix: str,
            ) -> None:
                for name, expected_file_id, expected_attributes in _windows_directory_entries(
                    directory_handle
                ):
                    path = directory_path / name
                    relative = relative_path(prefix, name)
                    expected_reparse = bool(
                        expected_attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                    )
                    expected_directory = bool(
                        expected_attributes & getattr(stat, "FILE_ATTRIBUTE_DIRECTORY", 0x10)
                    )
                    if expected_directory and not expected_reparse:
                        checkpoint("before-directory-open", path)
                    elif not expected_reparse:
                        checkpoint("before-file-open", path)
                    try:
                        child_handle = _open_windows_relative_handle(
                            directory_handle,
                            name,
                            access=0x1 | 0x80,
                            directory=None if expected_reparse else expected_directory,
                            share=0x1,
                        )
                    except OSError as error:
                        raise RuntimeError("sidecar entry identity changed before open") from error
                    try:
                        child_attributes, links, child_file_id, _child_size = (
                            _windows_handle_metadata(child_handle)
                        )
                        if child_file_id != expected_file_id:
                            raise RuntimeError("sidecar entry identity changed before open")
                        is_reparse = bool(
                            child_attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                        )
                        is_directory = bool(
                            child_attributes & getattr(stat, "FILE_ATTRIBUTE_DIRECTORY", 0x10)
                        )
                        if is_reparse:
                            metadata = path.lstat()
                            if metadata.st_ino != child_file_id or not stat.S_ISLNK(
                                metadata.st_mode
                            ):
                                raise RuntimeError(
                                    "sidecar contains a junction or unsupported reparse point"
                                )
                            target = os.readlink(path)
                            if path.lstat().st_ino != child_file_id:
                                raise RuntimeError(
                                    "sidecar symbolic link identity changed during inspection"
                                )
                            record_link(path, relative, target)
                        elif is_directory:
                            remember(path, "dir")
                            visit_windows(child_handle, path, relative)
                        else:
                            if links != 1:
                                raise RuntimeError("sidecar contains a hard-linked file")
                            checkpoint("after-file-open", path)
                            digest, size = _hash_windows_handle(child_handle)
                            remember(path, "file")
                            entries.append(
                                {
                                    "path": relative,
                                    "type": "file",
                                    "sha256": digest,
                                    "size": size,
                                }
                            )
                    finally:
                        _close_windows_handle(child_handle)

            visit_windows(root_handle, root, "")
        finally:
            _close_windows_handle(root_handle)
    else:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            root_descriptor = os.open(root, flags)
        except OSError as error:
            raise RuntimeError("sidecar staging root identity changed before open") from error
        try:
            opened_root = os.fstat(root_descriptor)
            if not os.path.samestat(root_metadata, opened_root):
                raise RuntimeError("sidecar staging root identity changed before open")

            def visit_descriptor(
                directory_descriptor: int,
                directory_path: Path,
                prefix: str,
            ) -> None:
                with os.scandir(directory_descriptor) as children:
                    names = sorted(child.name for child in children)
                for name in names:
                    path = directory_path / name
                    relative = relative_path(prefix, name)
                    metadata = os.stat(
                        name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                    if stat.S_ISLNK(metadata.st_mode):
                        target = os.readlink(name, dir_fd=directory_descriptor)
                        current = os.stat(
                            name,
                            dir_fd=directory_descriptor,
                            follow_symlinks=False,
                        )
                        if not os.path.samestat(metadata, current):
                            raise RuntimeError(
                                "sidecar symbolic link identity changed during inspection"
                            )
                        record_link(path, relative, target)
                    elif stat.S_ISREG(metadata.st_mode):
                        checkpoint("before-file-open", path)
                        file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                        try:
                            descriptor = os.open(
                                name,
                                file_flags,
                                dir_fd=directory_descriptor,
                            )
                        except OSError as error:
                            raise RuntimeError(
                                "sidecar file identity changed before hashing"
                            ) from error
                        try:
                            checkpoint("after-file-open", path)
                            digest, size = _hash_descriptor(descriptor, metadata)
                        finally:
                            os.close(descriptor)
                        current = os.stat(
                            name,
                            dir_fd=directory_descriptor,
                            follow_symlinks=False,
                        )
                        if not os.path.samestat(metadata, current):
                            raise RuntimeError("sidecar file identity changed while hashing")
                        remember(path, "file")
                        entries.append(
                            {
                                "path": relative,
                                "type": "file",
                                "sha256": digest,
                                "size": size,
                            }
                        )
                    elif stat.S_ISDIR(metadata.st_mode):
                        checkpoint("before-directory-open", path)
                        try:
                            descriptor = os.open(
                                name,
                                flags,
                                dir_fd=directory_descriptor,
                            )
                        except OSError as error:
                            raise RuntimeError(
                                "sidecar directory identity changed before traversal"
                            ) from error
                        try:
                            opened = os.fstat(descriptor)
                            if not os.path.samestat(metadata, opened):
                                raise RuntimeError(
                                    "sidecar directory identity changed before traversal"
                                )
                            remember(path, "dir")
                            visit_descriptor(descriptor, path, relative)
                            current = os.stat(
                                name,
                                dir_fd=directory_descriptor,
                                follow_symlinks=False,
                            )
                            if not os.path.samestat(opened, current):
                                raise RuntimeError(
                                    "sidecar directory identity changed during traversal"
                                )
                        finally:
                            os.close(descriptor)
                    else:
                        raise RuntimeError("sidecar contains an unsupported filesystem entry")

            visit_descriptor(root_descriptor, root, "")
            current_root = root.lstat()
            if not os.path.samestat(opened_root, current_root):
                raise RuntimeError("sidecar staging root identity changed during traversal")
        finally:
            os.close(root_descriptor)

    validate_links()
    entries.sort(key=lambda entry: str(entry["path"]))
    return entries


def _validate_symbolic_link_graph(link_targets: dict[str, str], known_paths: set[str]) -> None:
    for link, target in link_targets.items():
        visited = {link}
        current = target
        while current in link_targets:
            if current in visited:
                raise RuntimeError("sidecar contains a symbolic-link cycle")
            visited.add(current)
            current = link_targets[current]
        if current not in known_paths:
            raise RuntimeError("sidecar symbolic link target does not exist directly")


def _resolve_symbolic_link_target(
    root: Path,
    link: Path,
    target: str,
    link_targets: dict[str, str],
    node_types: dict[str, str],
    normalized_link_targets: dict[str, tuple[str, ...]] | None = None,
) -> str:
    if os.path.isabs(target) or bool(os.path.splitdrive(target)[0]):
        raise RuntimeError("sidecar contains an absolute symbolic link")
    stack = [str(component) for component in link.parent.relative_to(root).parts]
    pending: list[str | None] = list(Path(target).parts)
    if _symlink_target_requires_directory(target):
        pending.append(None)
    seen_states: set[tuple[tuple[str, ...], tuple[str | None, ...]]] = set()
    if normalized_link_targets is None:
        grouped_targets: dict[str, list[str]] = {}
        for link_path, link_target in link_targets.items():
            grouped_targets.setdefault(os.path.normcase(link_path), []).append(link_target)
        normalized_link_targets = {
            link_path: tuple(targets) for link_path, targets in grouped_targets.items()
        }
    symlink_follows = 0
    for _ in range(_MAX_SYMLINK_EXPANSIONS):
        if len(pending) > _MAX_SYMLINK_PENDING_COMPONENTS:
            raise RuntimeError("sidecar symbolic link target has too many pending components")
        state = (tuple(stack), tuple(pending))
        if state in seen_states:
            raise RuntimeError("sidecar contains a symbolic-link cycle")
        seen_states.add(state)
        if not pending:
            if not stack:
                raise RuntimeError("sidecar symbolic link escaped the staging tree")
            resolved = _lexical_absolute(root.joinpath(*stack))
            resolved_key = os.path.normcase(os.fspath(resolved))
            if resolved_key not in node_types:
                raise RuntimeError("sidecar symbolic link target does not exist directly")
            return resolved_key
        component = pending.pop(0)
        if component is None:
            if not stack:
                raise RuntimeError("sidecar symbolic link escaped the staging tree")
            boundary = _lexical_absolute(root.joinpath(*stack))
            if node_types.get(os.path.normcase(os.fspath(boundary))) != "dir":
                raise RuntimeError("sidecar symbolic link target is not a directory")
            continue
        if component in ("", "."):
            continue
        if component == "..":
            if not stack:
                raise RuntimeError("sidecar symbolic link escaped the staging tree")
            stack.pop()
            continue
        candidate = _lexical_absolute(root.joinpath(*stack, component))
        candidate_key = os.path.normcase(os.fspath(candidate))
        kind = node_types.get(candidate_key)
        if kind is None:
            raise RuntimeError("sidecar symbolic link target does not exist directly")
        if kind == "symlink":
            symlink_follows += 1
            if symlink_follows > _MAX_SYMLINK_FOLLOWS:
                raise RuntimeError("sidecar symbolic link target follows too many symbolic links")
            matching_links = normalized_link_targets.get(candidate_key, ())
            if len(matching_links) != 1:
                raise RuntimeError("sidecar contains a normalized path collision")
            link_target = matching_links[0]
            replacement: list[str | None] = list(Path(link_target).parts)
            if _symlink_target_requires_directory(link_target):
                replacement.append(None)
            pending = replacement + pending
            continue
        if kind != "dir" and pending and pending[0] is not None:
            raise RuntimeError("sidecar symbolic link target contains a non-directory intermediate")
        stack.append(component)
        if len(stack) > 128:
            raise RuntimeError("sidecar symbolic link target is too deep")
    raise RuntimeError("sidecar symbolic link graph contains too many expansions")


def _symlink_target_requires_directory(target: str) -> bool:
    if os.name == "nt":
        stripped = target.rstrip("/\\")
        return target.endswith(("/", "\\")) or stripped.endswith(("/.", "\\."))
    stripped = target.rstrip("/")
    return target.endswith("/") or stripped.endswith("/.")


def _read_bounded_direct_file(path: Path, maximum_bytes: int) -> bytes:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_reparse_point(metadata)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > maximum_bytes
    ):
        raise RuntimeError("sidecar manifest is not a bounded direct regular file")
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        handle = _open_windows_entry_handle(path, access=0x1 | 0x80, share=0x1)
        try:
            before = _windows_handle_metadata(handle)
            if (
                before[2] != metadata.st_ino
                or before[1] != 1
                or before[3] != metadata.st_size
                or before[0] & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                or before[0] & getattr(stat, "FILE_ATTRIBUTE_DIRECTORY", 0x10)
            ):
                raise RuntimeError("sidecar manifest identity changed before reading")
            read_file = ctypes.WinDLL("kernel32", use_last_error=True).ReadFile
            read_file.argtypes = [
                wintypes.HANDLE,
                wintypes.LPVOID,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
                wintypes.LPVOID,
            ]
            read_file.restype = wintypes.BOOL
            remaining = maximum_bytes + 1
            chunks: list[bytes] = []
            total = 0
            while remaining > 0:
                buffer_size = min(1024 * 1024, remaining)
                buffer = ctypes.create_string_buffer(buffer_size)
                read = wintypes.DWORD()
                if not read_file(
                    handle,
                    buffer,
                    buffer_size,
                    ctypes.byref(read),
                    None,
                ):
                    raise ctypes.WinError(ctypes.get_last_error())
                if read.value == 0:
                    break
                chunks.append(buffer.raw[: read.value])
                total += read.value
                remaining -= read.value
            windows_after = _windows_handle_metadata(handle)
            if before != windows_after or total != before[3] or total > maximum_bytes:
                raise RuntimeError("sidecar manifest changed while reading")
            return b"".join(chunks)
        finally:
            _close_windows_handle(handle)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not os.path.samestat(metadata, opened):
            raise RuntimeError("sidecar manifest identity changed before reading")
        chunks = []
        total = 0
        while total <= maximum_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        opened_after = os.fstat(descriptor)
        current = path.lstat()
        if (
            not os.path.samestat(opened, opened_after)
            or not os.path.samestat(opened, current)
            or total != opened.st_size
            or total > maximum_bytes
            or opened_after.st_mtime_ns != opened.st_mtime_ns
            or opened_after.st_ctime_ns != opened.st_ctime_ns
        ):
            raise RuntimeError("sidecar manifest changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _engine_tree_is_valid(path: Path) -> bool:
    manifest_path = path / "BUILD-MANIFEST.json"
    try:
        first_payload = _read_bounded_direct_file(manifest_path, _MAX_MANIFEST_BYTES)
        actual = _inventory(path)
        second_payload = _read_bounded_direct_file(manifest_path, _MAX_MANIFEST_BYTES)
        if first_payload != second_payload:
            return False
        parsed = json.loads(first_payload)
    except (OSError, RuntimeError, UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(parsed, dict) or set(parsed) != {
        "format",
        "platform",
        "architecture",
        "python",
        "pyinstaller",
        "source_date_epoch",
        "entries",
    }:
        return False
    if (
        parsed.get("format") != "pyinstaller-onedir"
        or parsed.get("platform") != platform.system().lower()
        or parsed.get("architecture") != platform.machine().lower()
        or parsed.get("pyinstaller") != PYINSTALLER_VERSION
        or parsed.get("source_date_epoch") != SOURCE_DATE_EPOCH
    ):
        return False
    python_version = parsed.get("python")
    if (
        not isinstance(python_version, str)
        or not 1 <= len(python_version) <= 32
        or "." not in python_version
        or any(character not in "0123456789." for character in python_version)
    ):
        return False
    expected = parsed.get("entries")
    if not isinstance(expected, list) or not 1 <= len(expected) <= _MAX_MANIFEST_ENTRIES:
        return False
    seen: set[str] = set()
    for entry in expected:
        if not isinstance(entry, dict):
            return False
        relative = entry.get("path")
        if not isinstance(relative, str) or not relative or relative in seen:
            return False
        seen.add(relative)
        if entry.get("type") == "file":
            digest = entry.get("sha256")
            size = entry.get("size")
            if (
                set(entry) != {"path", "type", "sha256", "size"}
                or not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
                or type(size) is not int
                or size < 0
            ):
                return False
        elif entry.get("type") == "symlink":
            if set(entry) != {"path", "type", "target"} or not isinstance(entry.get("target"), str):
                return False
        else:
            return False
    manifests = [entry for entry in actual if entry.get("path") == "BUILD-MANIFEST.json"]
    if len(manifests) != 1 or manifests[0].get("type") != "file":
        return False
    actual_without_manifest = [
        entry for entry in actual if entry.get("path") != "BUILD-MANIFEST.json"
    ]
    executable_name = "zombie-killer-engine.exe" if os.name == "nt" else "zombie-killer-engine"
    if not any(
        entry.get("path") == executable_name and entry.get("type") == "file" for entry in expected
    ):
        return False
    return expected == actual_without_manifest


def _pyinstaller_command(
    *, source_root: Path, work: Path, spec: Path, dist: Path, entry: Path
) -> list[str]:
    return [
        sys.executable,
        "-I",
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",
        "--noupx",
        "--log-level",
        "WARN",
        # Pydantic's hook discovers its optional type-checker plugins. These
        # have no engine runtime role and otherwise collect the installed mypy
        # compiler and its native dependencies from the development environment.
        "--exclude-module",
        "pydantic.mypy",
        "--exclude-module",
        "pydantic.v1.mypy",
        "--exclude-module",
        "mypy",
        "--name",
        "zombie-killer-engine",
        "--paths",
        str(source_root),
        "--workpath",
        str(work),
        "--specpath",
        str(spec),
        "--distpath",
        str(dist),
        str(entry),
    ]


def _smoke(executable: Path, staging: Path) -> None:
    request_id = "11111111-1111-4111-8111-111111111111"
    request = {
        "protocol_version": "1.0",
        "request_id": request_id,
        "method": "system.info",
        "payload": {},
    }
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"LANG", "LC_ALL", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "WINDIR"}
    }
    environment.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "PYTHONUTF8": "1"})
    with tempfile.TemporaryDirectory(prefix="zombie-killer-sidecar-smoke-") as temporary:
        state_root = _lexical_absolute(Path(temporary))
        command = [
            str(executable),
            "protocol-once",
            "--internal-state-root",
            str(state_root),
        ]
        if os.name == "posix":
            command.append(f"--parent-pid={os.getpid()}")
        completed = subprocess.run(
            command,
            input=json.dumps(request, separators=(",", ":")) + "\n",
            text=True,
            encoding="utf-8",
            capture_output=True,
            cwd=staging,
            env=environment,
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("bundled engine smoke test failed")
        response = json.loads(completed.stdout)
        UUID(str(response.get("request_id")))
        result = response.get("result")
        if (
            response.get("protocol_version") != "1.0"
            or response.get("request_id") != request_id
            or response.get("method") != "system.info"
            or response.get("ok") is not True
            or not isinstance(result, dict)
            or result.get("local_only") is not True
            or result.get("network_listener") is not False
        ):
            raise RuntimeError("bundled engine returned an invalid smoke response")


def _publish(
    candidate: Path,
    destination: Path,
    previous: Path,
    journal: Path,
    root: Path,
    *,
    phase_hook: Callable[[str], None] | None = None,
) -> None:
    candidate = _generated_target(candidate, root)
    previous = _generated_target(previous, root)
    journal = _generated_target(journal, root)
    destination = _fixed_destination(destination, root)
    if _lstat_optional(journal) is not None or _lstat_optional(previous) is not None:
        _recover_publication(candidate, destination, previous, journal, root)
    if not _direct_engine_directory_exists(candidate, label="sidecar candidate"):
        raise RuntimeError("sidecar candidate is missing")

    def checkpoint(phase: str) -> None:
        if phase_hook is not None:
            phase_hook(phase)

    _seal_candidate_durable(candidate)
    checkpoint("after-candidate-sealed")
    had_destination = _direct_engine_directory_exists(
        destination, label="fixed sidecar destination"
    )
    _write_publication_journal(journal, root, phase="prepared", had_destination=had_destination)
    checkpoint("after-journal-prepared")
    try:
        if had_destination:
            _rename_durable(destination, previous)
            checkpoint("after-previous-renamed")
        _write_publication_journal(
            journal, root, phase="previous-moved", had_destination=had_destination
        )
        checkpoint("after-previous-journaled")
        # This is the durable equivalent of candidate.rename(destination).
        _rename_durable(candidate, destination)
        checkpoint("after-candidate-renamed")
        _write_publication_journal(
            journal, root, phase="candidate-committed", had_destination=had_destination
        )
        checkpoint("after-candidate-committed")
    except Exception:
        _recover_publication(candidate, destination, previous, journal, root)
        raise
    committed_new_candidate = _finish_committed_publication(
        candidate,
        destination,
        previous,
        journal,
        root,
    )
    if not committed_new_candidate:
        raise RuntimeError("committed sidecar failed validation; last-known-good was restored")


def main() -> int:
    repository = _lexical_absolute(Path(__file__)).parents[1]
    _require_isolated_runtime(repository)
    tauri_root = repository / "apps" / "desktop" / "src-tauri"
    build_root = tauri_root / ".sidecar-build"
    resources = tauri_root / "resources"
    resource_root = resources / "engine"
    candidate = resources / ".engine-next"
    previous = resources / ".engine-previous"
    journal = resources / ".engine-publish.json"
    lock_path = resources / ".engine-build.lock"
    entry = repository / "services" / "engine" / "src" / "zombie_killer_engine" / "__main__.py"
    source_root = entry.parents[1]

    installed = importlib.metadata.version("pyinstaller")
    if installed != PYINSTALLER_VERSION:
        raise RuntimeError(
            f"PyInstaller {PYINSTALLER_VERSION} is required; found {installed}. "
            "Run with uv --frozen."
        )

    resources = _ensure_resources_directory(repository)
    with _exclusive_build_lock(lock_path, repository):
        _recover_publication(candidate, resource_root, previous, journal, repository)
        _remove_generated(build_root, repository)
        _remove_generated(candidate, repository)
        work = build_root / "work"
        spec = build_root / "spec"
        dist = build_root / "dist"
        environment = dict(os.environ)
        for variable in ("PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONUSERBASE"):
            environment.pop(variable, None)
        environment.update(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0",
                "PYTHONNOUSERSITE": "1",
                "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
            }
        )
        command = _pyinstaller_command(
            source_root=source_root,
            work=work,
            spec=spec,
            dist=dist,
            entry=entry,
        )
        try:
            subprocess.run(command, cwd=repository, env=environment, check=True)
            built = dist / "zombie-killer-engine"
            executable_name = (
                "zombie-killer-engine.exe" if os.name == "nt" else "zombie-killer-engine"
            )
            executable = built / executable_name
            if not executable.is_file():
                raise RuntimeError("PyInstaller did not produce the fixed sidecar executable")
            _inventory(built)
            subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(repository / "scripts" / "collect-sidecar-legal.py"),
                    "--output",
                    str(built),
                ],
                cwd=repository,
                env=environment,
                check=True,
            )
            _smoke(executable, built)
            (built / ".gitkeep").touch()
            inventory = _inventory(built)
            manifest = {
                "format": "pyinstaller-onedir",
                "platform": platform.system().lower(),
                "architecture": platform.machine().lower(),
                "python": platform.python_version(),
                "pyinstaller": PYINSTALLER_VERSION,
                "source_date_epoch": SOURCE_DATE_EPOCH,
                "entries": inventory,
            }
            (built / "BUILD-MANIFEST.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            _rename_durable(built, candidate)
            _publish(candidate, resource_root, previous, journal, repository)
        finally:
            if _lstat_optional(journal) is None:
                _remove_generated(candidate, repository)
            _remove_generated(build_root, repository)

    print(f"Built and verified {len(inventory)} fixed sidecar resources.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
