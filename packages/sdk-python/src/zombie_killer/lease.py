"""Secure, dependency-free persistence for Zombie Killer lease protocol v1/v2."""

from __future__ import annotations

import ctypes
import hashlib
import json
import math
import os
import platform
import secrets
import stat
import sys
import tempfile
from collections import deque
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, cast

MAX_LEASE_BYTES: Final = 128 * 1024
MAX_CANCELLATION_BYTES: Final = 16 * 1024
_WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)


class LeaseSecurityError(OSError):
    """The runtime path could not be proven private to the current user."""


def _effective_user_id() -> int:
    provider = getattr(os, "geteuid", None)
    if provider is None:
        raise OSError("effective user identity is unavailable")
    return int(provider())


def _system_configuration(name: str) -> int:
    provider = getattr(os, "sysconf", None)
    if provider is None:
        raise OSError("system configuration is unavailable")
    return int(provider(name))


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    """The process fields shared by lease v1 and cancellation v2."""

    boot_id: str
    pid: int
    create_time: float
    executable: str | None = None
    user: str | None = None
    user_hash: str | None = None

    def __post_init__(self) -> None:
        if not self.boot_id.strip() or len(self.boot_id) > 256:
            raise ValueError("boot_id must be non-empty and at most 256 characters")
        if isinstance(self.pid, bool) or self.pid <= 0:
            raise ValueError("pid must be positive")
        if not math.isfinite(self.create_time) or self.create_time < 0:
            raise ValueError("create_time must be finite and non-negative")
        if self.executable is not None:
            _require_executable_path(self.executable)
        if self.user is not None and not 0 < len(self.user.strip()) <= 256:
            raise ValueError("user must contain 1 to 256 characters")
        if self.user_hash is not None and (
            len(self.user_hash) != 64
            or any(character not in "0123456789abcdef" for character in self.user_hash)
        ):
            raise ValueError("user_hash must be 64 lowercase hexadecimal characters")

    def as_dict(self) -> dict[str, object]:
        return {
            "boot_id": self.boot_id,
            "pid": self.pid,
            "create_time": self.create_time,
            "executable": self.executable,
            "user": self.user,
        }


def _windows_boot_time() -> float:
    class TimeOfDay(ctypes.Structure):
        _fields_ = [
            ("boot_time", ctypes.c_longlong),
            ("current_time", ctypes.c_longlong),
            ("time_zone_bias", ctypes.c_longlong),
            ("current_time_zone_id", ctypes.c_ulong),
            ("reserved", ctypes.c_ulong),
            ("boot_time_bias", ctypes.c_ulonglong),
            ("sleep_time_bias", ctypes.c_ulonglong),
        ]

    information = TimeOfDay()
    status = ctypes.WinDLL("ntdll").NtQuerySystemInformation(
        3, ctypes.byref(information), ctypes.sizeof(information), None
    )
    if status != 0:
        raise OSError("Windows boot time is unavailable")
    # Windows can apply a few 100 ns of clock correction between calls. Whole
    # seconds remain stable across independently running engine/SDK processes.
    return float(information.boot_time // 10_000_000 - 11_644_473_600)


def _darwin_boot_time() -> float:
    class Timeval(ctypes.Structure):
        _fields_ = [("seconds", ctypes.c_long), ("microseconds", ctypes.c_int)]

    value = Timeval()
    size = ctypes.c_size_t(ctypes.sizeof(value))
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    if libc.sysctlbyname(b"kern.boottime", ctypes.byref(value), ctypes.byref(size), None, 0) != 0:
        raise OSError(ctypes.get_errno(), "kern.boottime query failed")
    return float(value.seconds)


def current_boot_id() -> str:
    system = platform.system().casefold()
    if system == "linux":
        try:
            value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
            if 0 < len(value) <= 256:
                return value
        except (OSError, UnicodeError):
            pass
    if os.name == "nt":
        boot_time = _windows_boot_time()
    elif system == "linux":
        boot_time = _linux_boot_time()
    elif system == "darwin":
        boot_time = _darwin_boot_time()
    else:
        raise OSError("a stable operating-system boot identity is unavailable")
    label = "windows" if system.startswith("win") else system
    return f"{label}-{round(boot_time * 1_000_000):x}"


def _linux_boot_time() -> float:
    for line in Path("/proc/stat").read_text(encoding="ascii").splitlines():
        if line.startswith("btime "):
            return float(line.split()[1])
    raise OSError("Linux boot time is unavailable")


def _windows_process_create_time(pid: int) -> float:
    class FileTime(ctypes.Structure):
        _fields_ = [("low", ctypes.c_ulong), ("high", ctypes.c_ulong)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    handle = kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        raise OSError(ctypes.get_last_error(), "OpenProcess failed")
    creation = FileTime()
    exit_time = FileTime()
    kernel_time = FileTime()
    user_time = FileTime()
    try:
        if not kernel32.GetProcessTimes(
            ctypes.c_void_p(handle),
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            raise OSError(ctypes.get_last_error(), "GetProcessTimes failed")
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
    ticks = (creation.high << 32) | creation.low
    return float(ticks - 116_444_736_000_000_000) / 10_000_000


def _linux_process_create_time(pid: int) -> float:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    fields = raw[raw.rfind(")") + 2 :].split()
    start_ticks = int(fields[19])
    ticks_per_second = _system_configuration("SC_CLK_TCK")
    return _linux_boot_time() + float(start_ticks) / ticks_per_second


def _darwin_process_create_time(pid: int) -> float:
    class ProcessBsdInfo(ctypes.Structure):
        _fields_ = [
            ("pbi_flags", ctypes.c_uint32),
            ("pbi_status", ctypes.c_uint32),
            ("pbi_xstatus", ctypes.c_uint32),
            ("pbi_pid", ctypes.c_uint32),
            ("pbi_ppid", ctypes.c_uint32),
            ("pbi_uid", ctypes.c_uint32),
            ("pbi_gid", ctypes.c_uint32),
            ("pbi_ruid", ctypes.c_uint32),
            ("pbi_rgid", ctypes.c_uint32),
            ("pbi_svuid", ctypes.c_uint32),
            ("pbi_svgid", ctypes.c_uint32),
            ("rfu_1", ctypes.c_uint32),
            ("pbi_comm", ctypes.c_char * 16),
            ("pbi_name", ctypes.c_char * 32),
            ("pbi_nfiles", ctypes.c_uint32),
            ("pbi_pgid", ctypes.c_uint32),
            ("pbi_pjobc", ctypes.c_uint32),
            ("e_tdev", ctypes.c_uint32),
            ("e_tpgid", ctypes.c_uint32),
            ("pbi_nice", ctypes.c_int32),
            ("pbi_start_tvsec", ctypes.c_uint64),
            ("pbi_start_tvusec", ctypes.c_uint64),
        ]

    information = ProcessBsdInfo()
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    received = libproc.proc_pidinfo(
        pid,
        3,
        0,
        ctypes.byref(information),
        ctypes.sizeof(information),
    )
    if received != ctypes.sizeof(information):
        raise OSError(ctypes.get_errno(), "proc_pidinfo failed")
    return float(information.pbi_start_tvsec) + float(information.pbi_start_tvusec) / 1_000_000


def _windows_username() -> str:
    size = ctypes.c_ulong(0)
    secur32 = ctypes.WinDLL("secur32", use_last_error=True)
    secur32.GetUserNameExW(2, None, ctypes.byref(size))
    if size.value <= 1:
        raise OSError(ctypes.get_last_error(), "GetUserNameExW size failed")
    buffer = ctypes.create_unicode_buffer(size.value)
    if not secur32.GetUserNameExW(2, buffer, ctypes.byref(size)):
        raise OSError(ctypes.get_last_error(), "GetUserNameExW failed")
    return buffer.value


def _current_executable(pid: int) -> str:
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.QueryFullProcessImageNameW.argtypes = (
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_ulong),
        )
        size = ctypes.c_ulong(32_768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(
            kernel32.GetCurrentProcess(), 0, buffer, ctypes.byref(size)
        ):
            raise OSError(ctypes.get_last_error(), "QueryFullProcessImageNameW failed")
        return buffer.value
    if sys.platform == "linux":
        return os.readlink(f"/proc/{pid}/exe")
    if sys.platform == "darwin":
        buffer = ctypes.create_string_buffer(4096)
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        received = libproc.proc_pidpath(pid, buffer, len(buffer))
        if received <= 0:
            raise OSError(ctypes.get_errno(), "proc_pidpath failed")
        return buffer.value.decode("utf-8", errors="strict")
    raise OSError("process executable identity is unavailable on this platform")


def current_process_identity() -> ProcessIdentity:
    pid = os.getpid()
    if os.name == "nt":
        create_time = _windows_process_create_time(pid)
    elif sys.platform == "linux":
        create_time = _linux_process_create_time(pid)
    elif sys.platform == "darwin":
        create_time = _darwin_process_create_time(pid)
    else:
        raise OSError("process creation time is unavailable on this platform")
    if os.name == "nt":
        user = _windows_username()
    else:
        import pwd

        user = pwd.getpwuid(_effective_user_id()).pw_name  # type: ignore[attr-defined]
    return ProcessIdentity(
        boot_id=current_boot_id(),
        pid=pid,
        create_time=create_time,
        executable=_current_executable(pid),
        user=user,
        user_hash=(
            hashlib.sha256(_windows_process_sid(pid).encode("utf-8")).hexdigest()
            if os.name == "nt"
            else hashlib.sha256(str(_effective_user_id()).encode("ascii")).hexdigest()
        ),
    )


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("attributes", ctypes.c_ulong)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("user", _SidAndAttributes)]


def _windows_process_sid(pid: int) -> str:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    advapi32.OpenProcessToken.argtypes = (
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.ConvertSidToStringSidW.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_wchar_p),
    )
    process = kernel32.OpenProcess(0x1000, False, pid)
    if not process:
        raise OSError(ctypes.get_last_error(), "OpenProcess failed")
    token = ctypes.c_void_p()
    rendered = ctypes.c_wchar_p()
    try:
        if not advapi32.OpenProcessToken(process, 0x0008, ctypes.byref(token)):
            raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
        required = ctypes.c_ulong()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(required))
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token, 1, buffer, required.value, ctypes.byref(required)
        ):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation failed")
        token_user = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents
        if not advapi32.ConvertSidToStringSidW(token_user.user.sid, ctypes.byref(rendered)):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
        if not rendered.value:
            raise OSError("empty Windows SID")
        return rendered.value
    finally:
        if rendered.value:
            kernel32.LocalFree(rendered)
        if token.value:
            kernel32.CloseHandle(token)
        kernel32.CloseHandle(process)


def user_fingerprint(identity: ProcessIdentity) -> str | None:
    if identity.user_hash is not None:
        return identity.user_hash
    if identity.user is None:
        return None
    if os.name == "nt":
        source = _windows_process_sid(identity.pid)
    else:
        try:
            if sys.platform == "linux":
                source = str(os.stat(f"/proc/{identity.pid}").st_uid)
            elif identity.pid == os.getpid():
                source = str(_effective_user_id())
            else:
                import pwd

                source = str(
                    pwd.getpwnam(identity.user).pw_uid  # type: ignore[attr-defined]
                )
        except (ImportError, KeyError, OSError):
            source = identity.user
    return hashlib.sha256(source.encode("utf-8", errors="strict")).hexdigest()


def cancellation_target(identity: ProcessIdentity) -> dict[str, object]:
    executable_hash = None
    if identity.executable is not None:
        executable = identity.executable.casefold() if os.name == "nt" else identity.executable
        executable_hash = hashlib.sha256(executable.encode("utf-8")).hexdigest()
    return {
        "boot_id": identity.boot_id,
        "pid": identity.pid,
        "create_time_hash": hashlib.sha256(identity.create_time.hex().encode("ascii")).hexdigest(),
        "executable_hash": executable_hash,
        "user_hash": user_fingerprint(identity),
    }


def _is_redirect(path_stat: os.stat_result) -> bool:
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(path_stat.st_mode) or bool(
        getattr(path_stat, "st_file_attributes", 0) & reparse
    )


def _check_no_redirects(path: Path) -> None:
    current = path.absolute()
    while True:
        try:
            if _is_redirect(os.lstat(current)):
                raise LeaseSecurityError("runtime path contains a link or reparse point")
        except FileNotFoundError:
            pass
        parent = current.parent
        if parent == current:
            return
        current = parent


def _secure_directory(path: Path) -> None:
    _check_no_redirects(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    current = os.lstat(path)
    if _is_redirect(current) or not stat.S_ISDIR(current.st_mode):
        raise LeaseSecurityError("runtime path is not a direct directory")
    if os.name != "nt":
        if current.st_uid != _effective_user_id():
            raise LeaseSecurityError("runtime path is not owned by the current user")
        os.chmod(path, 0o700, follow_symlinks=False)
        verified = os.lstat(path)
        if verified.st_uid != _effective_user_id() or stat.S_IMODE(verified.st_mode) & 0o077:
            raise LeaseSecurityError("runtime path permissions are not private")
        return
    _secure_windows_directory(path)


def _secure_windows_directory(path: Path) -> None:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    advapi32.SetKernelObjectSecurity.argtypes = (
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
    )
    descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)", 1, ctypes.byref(descriptor), None
    ):
        raise LeaseSecurityError(ctypes.get_last_error(), "security descriptor conversion failed")
    kernel32.CreateFileW.restype = ctypes.c_void_p
    handle = kernel32.CreateFileW(
        str(path),
        0x00020000 | 0x00040000,
        0x00000007,
        None,
        3,
        0x02000000 | 0x00200000,
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        kernel32.LocalFree(descriptor)
        raise LeaseSecurityError(ctypes.get_last_error(), "secure directory open failed")
    try:
        if not advapi32.SetKernelObjectSecurity(handle, 0x00000004, descriptor):
            raise LeaseSecurityError(ctypes.get_last_error(), "directory DACL update failed")
    finally:
        kernel32.CloseHandle(handle)
        kernel32.LocalFree(descriptor)
    _verify_windows_directory(path)


def _verify_windows_directory(path: Path) -> None:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.ConvertSidToStringSidW.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_wchar_p),
    )
    owner = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = advapi32.GetNamedSecurityInfoW(
        str(path),
        1,
        0x00000001 | 0x00000004,
        ctypes.byref(owner),
        None,
        None,
        None,
        ctypes.byref(descriptor),
    )
    if result != 0 or not descriptor.value or not owner.value:
        raise LeaseSecurityError(result, "directory security query failed")
    rendered_owner = ctypes.c_wchar_p()
    rendered_dacl = ctypes.c_wchar_p()
    try:
        if not advapi32.ConvertSidToStringSidW(owner, ctypes.byref(rendered_owner)):
            raise LeaseSecurityError(ctypes.get_last_error(), "directory owner query failed")
        if rendered_owner.value != _windows_process_sid(os.getpid()):
            raise LeaseSecurityError("runtime path is not owned by the current user")
        control = ctypes.c_ushort()
        revision = ctypes.c_ulong()
        if (
            not advapi32.GetSecurityDescriptorControl(
                descriptor, ctypes.byref(control), ctypes.byref(revision)
            )
            or not control.value & 0x1000
        ):
            raise LeaseSecurityError("runtime directory DACL inheritance remains enabled")
        if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            1,
            0x00000004,
            ctypes.byref(rendered_dacl),
            None,
        ):
            raise LeaseSecurityError(ctypes.get_last_error(), "directory DACL query failed")
        rendered = rendered_dacl.value or ""
        required = {"(A;OICI;FA;;;OW)", "(A;OICI;FA;;;SY)"}
        actual = {"(" + component for component in rendered.split("(")[1:]}
        if actual != required:
            raise LeaseSecurityError("runtime directory DACL grants unexpected access")
        _check_no_redirects(path)
    finally:
        if rendered_owner.value:
            kernel32.LocalFree(rendered_owner)
        if rendered_dacl.value:
            kernel32.LocalFree(rendered_dacl)
        kernel32.LocalFree(descriptor)


def posix_runtime_dir(
    *,
    system: str,
    uid: int,
    home: Path,
    run_user: Path | None,
    owner_uid: int | None,
    mode: int | None = None,
    direct: bool | None = None,
) -> Path:
    """Resolve a deterministic POSIX runtime without reading process environment."""
    if system == "linux" and run_user is not None:
        try:
            details = os.lstat(run_user)
            resolved_owner = details.st_uid if owner_uid is None else owner_uid
            resolved_mode = stat.S_IMODE(details.st_mode) if mode is None else mode
            if direct is None:
                _check_no_redirects(run_user)
                resolved_direct = stat.S_ISDIR(details.st_mode) and not _is_redirect(details)
            else:
                resolved_direct = direct
            safe = resolved_direct and resolved_owner == uid and resolved_mode & 0o077 == 0
        except OSError:
            safe = False
        if safe:
            return run_user / "Zombie Killer"
    if system == "darwin":
        return home / "Library" / "Application Support" / "Zombie Killer" / "runtime"
    return home / ".local" / "state" / "Zombie Killer" / "runtime"


def default_runtime_dir() -> Path:
    """Return the engine-compatible per-user runtime path without environment access."""
    if os.name == "nt":
        local = ctypes.c_wchar_p()
        folder_id = ctypes.c_byte * 16
        # FOLDERID_LocalAppData: f1b32785-6fba-4fcf-9d55-7b8e7f157091
        raw = bytes.fromhex("8527b3f1ba6fcf4f9d557b8e7f157091")
        identifier = folder_id.from_buffer_copy(raw)
        result = ctypes.WinDLL("shell32").SHGetKnownFolderPath(
            ctypes.byref(identifier), 0, None, ctypes.byref(local)
        )
        if result != 0 or not local.value:
            raise OSError("LocalAppData is unavailable")
        try:
            return Path(local.value) / "Temp" / "Zombie Killer" / "Zombie Killer"
        finally:
            ctypes.windll.ole32.CoTaskMemFree(local)
    import pwd

    uid = _effective_user_id()
    home = Path(pwd.getpwuid(uid).pw_dir)  # type: ignore[attr-defined]
    return posix_runtime_dir(
        system="darwin" if sys.platform == "darwin" else "linux",
        uid=uid,
        home=home,
        run_user=None if sys.platform == "darwin" else Path("/run/user") / str(uid),
        owner_uid=None,
    )


def require_protocol_path(value: str, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    if not 0 < len(value) <= 4096:
        raise ValueError(f"{field} must contain 1 to 4096 characters")
    return value


def _require_executable_path(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("executable must be a string")
    if not 0 < len(value) <= 32_768:
        raise ValueError("executable must contain 1 to 32768 characters")
    return value


def _validate_agent_id(agent_id: str) -> None:
    if (
        not agent_id
        or len(agent_id) > 128
        or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
            for character in agent_id
        )
    ):
        raise ValueError("agent_id is not portable")
    if agent_id.endswith(".") or agent_id.split(".", 1)[0].casefold() in _WINDOWS_RESERVED:
        raise ValueError("agent_id is not portable")


def _encode(payload: dict[str, object], *, max_bytes: int) -> bytes:
    try:
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("payload must be finite JSON data") from error
    if len(encoded) > max_bytes:
        label = "128 KiB" if max_bytes == MAX_LEASE_BYTES else "16 KiB"
        raise ValueError(f"payload exceeds the {label} limit")
    return encoded


def _atomic_write(
    target: Path,
    payload: dict[str, object],
    *,
    max_bytes: int,
    verify: Callable[[], None] | None = None,
) -> None:
    encoded = _encode(payload, max_bytes=max_bytes)
    if verify is not None:
        verify()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.stem}-", suffix=".tmp", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        if os.name == "nt":
            os.chmod(temporary, stat.S_IREAD | stat.S_IWRITE)
        else:
            os.chmod(temporary, 0o600, follow_symlinks=False)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        if verify is not None:
            verify()
        os.replace(temporary, target)
        if verify is not None:
            verify()
        if os.name != "nt":
            directory = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            temporary.unlink()


def _read_json_nofollow(path: Path, *, max_bytes: int) -> object | None:
    try:
        before = os.lstat(path)
        if _is_redirect(before) or not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            return None
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                return None
            data = os.read(descriptor, max_bytes + 1)
            after = os.fstat(descriptor)
            if len(data) > max_bytes or (after.st_size, after.st_mtime_ns) != (
                opened.st_size,
                opened.st_mtime_ns,
            ):
                return None
        finally:
            os.close(descriptor)
        return cast(object, json.loads(data))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError, RecursionError):
        return None


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str) or not 0 < len(value) <= 64:
        raise ValueError("invalid timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include an offset")
    return parsed.astimezone(UTC)


class LeaseStore:
    """Private per-user lease and cancellation directory pair."""

    def __init__(self, state_dir: Path | str | None = None, *, strict: bool = False) -> None:
        self._runtime_dir = Path(state_dir) if state_dir is not None else None
        if self._runtime_dir is not None and not self._runtime_dir.is_absolute():
            raise ValueError("state_dir must be absolute")
        self.strict = strict
        self.available = False
        self.last_warning: str | None = None
        self._authority: dict[Path, tuple[tuple[object, ...], ...]] = {}
        self._compromised = False
        self._seen_requests: dict[tuple[str, str], deque[str]] = {}

    @property
    def runtime_dir(self) -> Path:
        if self._runtime_dir is None:
            self._runtime_dir = default_runtime_dir()
            if not self._runtime_dir.is_absolute():
                raise OSError("native runtime directory is not absolute")
        return self._runtime_dir

    @property
    def leases_dir(self) -> Path:
        return self.runtime_dir / "leases"

    @property
    def cancellations_dir(self) -> Path:
        return self.runtime_dir / "cancellations"

    @staticmethod
    def _snapshot(path: Path) -> tuple[tuple[object, ...], ...]:
        absolute = path.absolute()
        _check_no_redirects(absolute)
        parts = [absolute, *absolute.parents]
        snapshot: list[tuple[object, ...]] = []
        for component in reversed(parts):
            details = os.lstat(component)
            if not stat.S_ISDIR(details.st_mode) or _is_redirect(details):
                raise LeaseSecurityError("directory authority contains a redirect")
            snapshot.append(
                (
                    str(component),
                    details.st_dev,
                    details.st_ino,
                    details.st_mode,
                    getattr(details, "st_file_attributes", 0),
                )
            )
        if os.name == "nt":
            _verify_windows_directory(absolute)
        else:
            final = os.lstat(absolute)
            if final.st_uid != _effective_user_id() or stat.S_IMODE(final.st_mode) & 0o077:
                raise LeaseSecurityError("directory authority is not current-user private")
        return tuple(snapshot)

    def _verify_authority(self) -> None:
        if self._compromised or not self._authority:
            raise LeaseSecurityError("directory authority is unavailable")
        try:
            for path, expected in self._authority.items():
                if self._snapshot(path) != expected:
                    raise LeaseSecurityError("directory authority changed")
        except OSError as error:
            self._compromised = True
            self.available = False
            self.last_warning = "DIRECTORY_AUTHORITY_CHANGED"
            raise LeaseSecurityError("directory authority changed") from error

    def prepare(self) -> bool:
        if self._compromised:
            return False
        try:
            for path in (self.runtime_dir, self.leases_dir, self.cancellations_dir):
                _secure_directory(path)
            self._authority = {
                path: self._snapshot(path)
                for path in (self.runtime_dir, self.leases_dir, self.cancellations_dir)
            }
            self.available = True
            self.last_warning = None
        except OSError as error:
            self.available = False
            self.last_warning = type(error).__name__
            if self.strict:
                raise LeaseSecurityError(
                    "Zombie Killer runtime directory is unavailable"
                ) from error
        return self.available

    def lease_path(self, agent_id: str) -> Path:
        _validate_agent_id(agent_id)
        return self.leases_dir / f"{agent_id}.json"

    def cancellation_path(self, agent_id: str) -> Path:
        _validate_agent_id(agent_id)
        return self.cancellations_dir / f"{agent_id}.json"

    def ack_path(self, agent_id: str) -> Path:
        _validate_agent_id(agent_id)
        return self.cancellations_dir / f"{agent_id}.cleared"

    def write_lease(self, agent_id: str, payload: dict[str, object]) -> bool:
        if not self.available and not self.prepare():
            return False
        try:
            self._verify_authority()
            _atomic_write(
                self.lease_path(agent_id),
                payload,
                max_bytes=MAX_LEASE_BYTES,
                verify=self._verify_authority,
            )
            return True
        except (OSError, TypeError, ValueError) as error:
            self.available = False
            if self.last_warning != "DIRECTORY_AUTHORITY_CHANGED":
                self.last_warning = (
                    "LEASE_PAYLOAD_TOO_LARGE"
                    if isinstance(error, ValueError) and "128 KiB" in str(error)
                    else type(error).__name__
                )
            if self.strict:
                if isinstance(error, ValueError):
                    raise
                raise LeaseSecurityError("lease publication failed") from error
            return False

    def validate_lease(self, payload: dict[str, object]) -> None:
        """Validate serialization and size without touching persistent state."""
        _encode(payload, max_bytes=MAX_LEASE_BYTES)

    def write_cancellation_for_test(self, agent_id: str, payload: dict[str, object]) -> None:
        if not self.available:
            self.prepare()
        self._verify_authority()
        _atomic_write(
            self.cancellation_path(agent_id),
            payload,
            max_bytes=MAX_CANCELLATION_BYTES,
            verify=self._verify_authority,
        )

    def poll_cancellation(
        self,
        agent_id: str,
        *,
        registration_nonce: str,
        identity: ProcessIdentity,
        now: datetime | None = None,
    ) -> dict[str, object] | None:
        if not self.available and not self.prepare():
            return None
        try:
            self._verify_authority()
            payload = _read_json_nofollow(
                self.cancellation_path(agent_id), max_bytes=MAX_CANCELLATION_BYTES
            )
            self._verify_authority()
            if not isinstance(payload, dict):
                if os.path.lexists(self.cancellation_path(agent_id)):
                    self.last_warning = "CANCELLATION_MALFORMED"
                return None
            required = {
                "protocol_version",
                "agent_id",
                "registration_nonce",
                "plan_id",
                "request_id",
                "target",
                "requested_at",
                "expires_at",
            }
            if set(payload) != required or payload.get("protocol_version") != 2:
                self.last_warning = "CANCELLATION_MALFORMED"
                return None
            if (
                payload.get("agent_id") != agent_id
                or payload.get("registration_nonce") != registration_nonce
            ):
                self.last_warning = "CANCELLATION_UNBOUND"
                return None
            if payload.get("target") != cancellation_target(identity):
                self.last_warning = "CANCELLATION_UNBOUND"
                return None
            request_id = payload.get("request_id")
            plan_id = payload.get("plan_id")
            if not isinstance(request_id, str) or not request_id.strip() or len(request_id) > 256:
                self.last_warning = "CANCELLATION_MALFORMED"
                return None
            if not isinstance(plan_id, str) or not plan_id.strip() or len(plan_id) > 256:
                self.last_warning = "CANCELLATION_MALFORMED"
                return None
            generation = (agent_id, registration_nonce)
            seen = self._seen_requests.setdefault(generation, deque(maxlen=64))
            if request_id in seen:
                self.last_warning = "CANCELLATION_REUSED"
                return None
            requested = _parse_utc(payload.get("requested_at"))
            expires = _parse_utc(payload.get("expires_at"))
            observed = (now or datetime.now(UTC)).astimezone(UTC)
            lifetime = (expires - requested).total_seconds()
            if requested > observed or expires <= observed or not 0 < lifetime <= 30:
                self.last_warning = "CANCELLATION_EXPIRED"
                return None
            acknowledgement = _read_json_nofollow(
                self.ack_path(agent_id), max_bytes=MAX_CANCELLATION_BYTES
            )
            self._verify_authority()
            if isinstance(acknowledgement, dict) and acknowledgement == {
                "protocol_version": 2,
                "agent_id": agent_id,
                "request_id": request_id,
            }:
                self.last_warning = "CANCELLATION_REUSED"
                return None
            _atomic_write(
                self.ack_path(agent_id),
                {"protocol_version": 2, "agent_id": agent_id, "request_id": request_id},
                max_bytes=MAX_CANCELLATION_BYTES,
                verify=self._verify_authority,
            )
            seen.append(request_id)
            self.last_warning = None
            return payload
        except (OSError, TypeError, ValueError):
            if self.last_warning != "DIRECTORY_AUTHORITY_CHANGED":
                self.last_warning = "CANCELLATION_MALFORMED"
            return None


def capture_temp_fingerprint(path: Path) -> dict[str, object]:
    """Capture bounded, no-follow declaration evidence including descendant bytes."""
    initial = os.stat(path, follow_symlinks=False)
    inventory: list[list[object]] = []
    total_bytes = 0

    def snapshot(value: os.stat_result) -> tuple[int, ...]:
        # Reads can update atime on POSIX; it is not declaration identity.
        return (
            int(value.st_dev),
            int(value.st_ino),
            int(value.st_mode),
            int(value.st_size),
            int(value.st_mtime_ns),
            # Windows CRT fstat may report change time where path stat reports
            # creation time. Compare inode, mtime and bytes across handles;
            # retain path creation time as declaration evidence separately.
            0 if os.name == "nt" else int(value.st_ctime_ns),
            int(value.st_nlink),
            int(getattr(value, "st_file_attributes", 0)),
        )

    def visit(candidate: Path, depth: int) -> str:
        nonlocal total_bytes
        if depth > 16 or len(inventory) >= 1024:
            raise ValueError("temporary resource inventory exceeds declaration bounds")
        _check_no_redirects(candidate)
        before = os.stat(candidate, follow_symlinks=False)
        if before.st_dev != initial.st_dev:
            raise ValueError("temporary resource inventory crosses a mount point")
        if stat.S_ISREG(before.st_mode):
            if before.st_nlink != 1:
                raise ValueError("hard-linked temporary files cannot be declared")
            total_bytes += before.st_size
            if total_bytes > 64 * 1024 * 1024:
                raise ValueError("temporary resource exceeds declaration byte bounds")
            descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                if snapshot(os.fstat(stream.fileno())) != snapshot(before):
                    raise ValueError("temporary resource changed during declaration")
                digest = hashlib.sha256()
                remaining = before.st_size
                while chunk := stream.read(min(1024 * 1024, remaining + 1)):
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise ValueError("temporary resource grew during declaration")
                    digest.update(chunk)
                if remaining or snapshot(os.fstat(stream.fileno())) != snapshot(before):
                    raise ValueError("temporary resource changed during declaration")
            content = digest.hexdigest()
        elif stat.S_ISDIR(before.st_mode):
            content = "directory"
            with os.scandir(candidate) as children:
                names = []
                for child in children:
                    names.append(child.name)
                    if len(names) + len(inventory) > 1024:
                        raise ValueError("temporary resource inventory exceeds declaration bounds")
            for name in sorted(names):
                visit(candidate / name, depth + 1)
        else:
            raise ValueError("temporary resource must contain regular files and directories")
        if snapshot(os.stat(candidate, follow_symlinks=False)) != snapshot(before):
            raise ValueError("temporary resource changed during declaration")
        inventory.append(
            [
                candidate.relative_to(path).as_posix(),
                int(before.st_dev),
                int(before.st_ino),
                int(before.st_mode),
                int(before.st_size),
                int(before.st_mtime_ns),
                int(before.st_ctime_ns),
                content,
            ]
        )
        return content

    content = visit(path, 0)
    if stat.S_ISDIR(initial.st_mode):
        content = hashlib.sha256(
            json.dumps(inventory, ensure_ascii=True, separators=(",", ":")).encode()
        ).hexdigest()
    return {
        "device": int(initial.st_dev),
        "inode": int(initial.st_ino),
        "mode": int(initial.st_mode),
        "size": int(initial.st_size),
        "mtime_ns": int(initial.st_mtime_ns),
        "ctime_ns": int(initial.st_ctime_ns),
        "content_digest": content,
    }


def validate_temp_resource(path: Path | str, *, root: Path | str) -> dict[str, object]:
    candidate = Path(path)
    approved = Path(root)
    require_protocol_path(str(candidate), field="resource path")
    require_protocol_path(str(approved), field="resource root")
    if not candidate.is_absolute() or not approved.is_absolute():
        raise ValueError("temporary path and root must be absolute")
    raw = str(candidate)
    if any(character in raw for character in "*?[]"):
        raise ValueError("temporary paths cannot be globs")
    if os.name == "nt":
        normalized = raw.replace("/", "\\")
        if normalized.startswith(("\\\\", "\\\\?\\", "\\\\.\\")):
            raise ValueError("UNC and device paths are not supported")
        if ":" in normalized[2:]:
            raise ValueError("alternate data streams are not supported")
        if any(part.rstrip(". ").casefold() in _WINDOWS_RESERVED for part in candidate.parts[1:]):
            raise ValueError("reserved DOS aliases are not supported")
    _check_no_redirects(approved)
    _check_no_redirects(candidate)
    try:
        canonical_root = approved.resolve(strict=True)
        canonical_path = candidate.resolve(strict=True)
        canonical_path.relative_to(canonical_root)
    except (OSError, ValueError) as error:
        raise ValueError("temporary path must exist strictly beneath the approved root") from error
    if canonical_path == canonical_root:
        raise ValueError("the approved root itself cannot be tracked")
    canonical_path_text = require_protocol_path(
        str(canonical_path), field="canonical resource path"
    )
    require_protocol_path(str(canonical_root), field="canonical resource root")
    root_stat = os.stat(canonical_root, follow_symlinks=False)
    path_stat = os.stat(canonical_path, follow_symlinks=False)
    if path_stat.st_dev != root_stat.st_dev:
        raise ValueError("temporary path cannot cross a mount point")
    if os.name != "nt" and (
        root_stat.st_uid != _effective_user_id() or path_stat.st_uid != _effective_user_id()
    ):
        raise ValueError("temporary path must be owned by the current user")
    return {
        "kind": "temporary",
        "path": canonical_path_text,
        "approved_root": str(canonical_root),
        "resource_type": "directory" if stat.S_ISDIR(path_stat.st_mode) else "file",
        "cleanup_policy": "quarantine",
        "creation_fingerprint": capture_temp_fingerprint(canonical_path),
    }


def secure_random_nonce() -> str:
    return secrets.token_urlsafe(24)


__all__ = [
    "LeaseSecurityError",
    "LeaseStore",
    "ProcessIdentity",
    "cancellation_target",
    "current_process_identity",
    "default_runtime_dir",
    "posix_runtime_dir",
    "require_protocol_path",
    "secure_random_nonce",
    "validate_temp_resource",
]
