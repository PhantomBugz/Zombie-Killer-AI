"""Per-user application paths with dependency-injectable test seams."""

from __future__ import annotations

import ctypes
import os
import stat
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from zombie_killer_engine.redaction import redact_text


def _is_reparse_point(path_stat: os.stat_result) -> bool:
    attributes = getattr(path_stat, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & reparse_flag)


def _is_direct_directory(path_stat: os.stat_result) -> bool:
    return stat.S_ISDIR(path_stat.st_mode) and not _is_reparse_point(path_stat)


def _has_redirected_component(path: Path) -> bool:
    current = path
    while True:
        try:
            current_stat = os.lstat(current)
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(current_stat.st_mode) or _is_reparse_point(current_stat):
                return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def _effective_user_id() -> int:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        raise OSError("effective user ID is unavailable")
    return int(geteuid())


def _open_directory_nofollow(path: Path, *, create: bool) -> int:
    absolute = path.absolute()
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(absolute.anchor, flags)
    try:
        for component in absolute.parts[1:]:
            if create:
                with suppress(FileExistsError):
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
            child_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child_descriptor
        if not _is_direct_directory(os.fstat(descriptor)):
            raise OSError("application path is not a direct directory")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


@dataclass(frozen=True, slots=True)
class PathWarning:
    """A bounded, display-safe failure to prepare an application directory."""

    code: str
    path: str
    message: str


class PermissionBackend(Protocol):
    """Restrict one already-created directory to the current user."""

    def restrict(self, path: Path) -> None: ...


class PosixPermissionBackend:
    def restrict(self, path: Path) -> None:
        descriptor = _open_directory_nofollow(path, create=False)
        try:
            if os.fstat(descriptor).st_uid != _effective_user_id():
                raise OSError("application directory is not owned by the current user")
            os.fchmod(descriptor, 0o700)  # type: ignore[attr-defined]
        finally:
            os.close(descriptor)

    def verify(self, path: Path) -> None:
        descriptor = _open_directory_nofollow(path, create=False)
        try:
            current = os.fstat(descriptor)
            if current.st_uid != _effective_user_id():
                raise OSError("application directory is not owned by the current user")
            if stat.S_IMODE(current.st_mode) & 0o077:
                raise OSError("application directory permissions are not restrictive")
        finally:
            os.close(descriptor)


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("file_attributes", ctypes.c_ulong),
        ("creation_time_low", ctypes.c_ulong),
        ("creation_time_high", ctypes.c_ulong),
        ("access_time_low", ctypes.c_ulong),
        ("access_time_high", ctypes.c_ulong),
        ("write_time_low", ctypes.c_ulong),
        ("write_time_high", ctypes.c_ulong),
        ("volume_serial_number", ctypes.c_ulong),
        ("file_size_high", ctypes.c_ulong),
        ("file_size_low", ctypes.c_ulong),
        ("number_of_links", ctypes.c_ulong),
        ("file_index_high", ctypes.c_ulong),
        ("file_index_low", ctypes.c_ulong),
    ]


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [
        ("sid", ctypes.c_void_p),
        ("attributes", ctypes.c_ulong),
    ]


class _TokenUser(ctypes.Structure):
    _fields_ = [("user", _SidAndAttributes)]


class WindowsPermissionBackend:
    """Apply and verify a protected owner-and-SYSTEM-only Windows DACL."""

    SECURITY_DESCRIPTOR = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)"
    _OWNER_SECURITY_INFORMATION = 0x00000001
    _DACL_SECURITY_INFORMATION = 0x00000004
    _PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
    _SE_DACL_PROTECTED = 0x1000
    _READ_CONTROL = 0x00020000
    _WRITE_DAC = 0x00040000
    _FILE_SHARE_ALL = 0x00000007
    _OPEN_EXISTING = 3
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _TOKEN_QUERY = 0x00000008
    _TOKEN_USER = 1

    def restrict(self, path: Path) -> None:
        self._secure(path, apply=True)

    def verify(self, path: Path) -> None:
        self._secure(path, apply=False)

    def _secure(self, path: Path, *, apply: bool) -> None:
        if os.name != "nt":
            raise OSError("Windows security APIs are unavailable")
        if _has_redirected_component(path):
            raise OSError("application path contains a redirected component")
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
        advapi32.OpenProcessToken.argtypes = (
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_void_p),
        )
        advapi32.GetTokenInformation.argtypes = (
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
        )
        advapi32.EqualSid.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
        advapi32.EqualSid.restype = ctypes.c_int
        token = ctypes.c_void_p()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            self._TOKEN_QUERY,
            ctypes.byref(token),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            token_size = ctypes.c_ulong()
            advapi32.GetTokenInformation(
                token,
                self._TOKEN_USER,
                None,
                0,
                ctypes.byref(token_size),
            )
            if token_size.value == 0:
                raise ctypes.WinError(ctypes.get_last_error())
            token_buffer = ctypes.create_string_buffer(token_size.value)
            if not advapi32.GetTokenInformation(
                token,
                self._TOKEN_USER,
                token_buffer,
                token_size.value,
                ctypes.byref(token_size),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            token_user = ctypes.cast(
                token_buffer,
                ctypes.POINTER(_TokenUser),
            ).contents
            current_user_sid = token_user.user.sid
        finally:
            kernel32.CloseHandle(token)
        kernel32.CreateFileW.restype = ctypes.c_void_p
        kernel32.CreateFileW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_void_p,
        )
        kernel32.GetFileInformationByHandle.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_ByHandleFileInformation),
        )
        advapi32.SetKernelObjectSecurity.argtypes = (
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_void_p,
        )
        advapi32.GetKernelObjectSecurity.argtypes = (
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
        )
        handle = kernel32.CreateFileW(
            str(path),
            self._READ_CONTROL | self._WRITE_DAC,
            self._FILE_SHARE_ALL,
            None,
            self._OPEN_EXISTING,
            self._FILE_FLAG_BACKUP_SEMANTICS | self._FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        opened_information = _ByHandleFileInformation()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(opened_information)):
            kernel32.CloseHandle(handle)
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            current_stat = os.lstat(path)
            opened_inode = (
                opened_information.file_index_high << 32
            ) | opened_information.file_index_low
            invalid_target = (
                bool(
                    opened_information.file_attributes
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                )
                or not _is_direct_directory(current_stat)
                or current_stat.st_ino != opened_inode
                or _has_redirected_component(path)
            )
        except BaseException:
            kernel32.CloseHandle(handle)
            raise
        if invalid_target:
            kernel32.CloseHandle(handle)
            raise OSError("application path changed while opening")
        try:
            owner_size = ctypes.c_ulong()
            advapi32.GetKernelObjectSecurity(
                handle,
                self._OWNER_SECURITY_INFORMATION,
                None,
                0,
                ctypes.byref(owner_size),
            )
            if owner_size.value == 0:
                raise ctypes.WinError(ctypes.get_last_error())
            owner_descriptor = ctypes.create_string_buffer(owner_size.value)
            if not advapi32.GetKernelObjectSecurity(
                handle,
                self._OWNER_SECURITY_INFORMATION,
                owner_descriptor,
                owner_size.value,
                ctypes.byref(owner_size),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            existing_owner_sid = ctypes.c_void_p()
            existing_owner_defaulted = ctypes.c_int()
            if not advapi32.GetSecurityDescriptorOwner(
                owner_descriptor,
                ctypes.byref(existing_owner_sid),
                ctypes.byref(existing_owner_defaulted),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if not advapi32.EqualSid(existing_owner_sid, current_user_sid):
                raise OSError("application directory is not owned by the current user")
        except BaseException:
            kernel32.CloseHandle(handle)
            raise
        descriptor = ctypes.c_void_p()
        if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            self.SECURITY_DESCRIPTOR,
            1,
            ctypes.byref(descriptor),
            None,
        ):
            kernel32.CloseHandle(handle)
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            security_information = (
                self._DACL_SECURITY_INFORMATION | self._PROTECTED_DACL_SECURITY_INFORMATION
            )
            if apply and not advapi32.SetKernelObjectSecurity(
                handle, security_information, descriptor
            ):
                raise ctypes.WinError(ctypes.get_last_error())

            required = ctypes.c_ulong()
            read_security_information = (
                self._OWNER_SECURITY_INFORMATION | self._DACL_SECURITY_INFORMATION
            )
            advapi32.GetKernelObjectSecurity(
                handle,
                read_security_information,
                None,
                0,
                ctypes.byref(required),
            )
            if required.value == 0:
                raise ctypes.WinError(ctypes.get_last_error())
            current = ctypes.create_string_buffer(required.value)
            if not advapi32.GetKernelObjectSecurity(
                handle,
                read_security_information,
                current,
                required.value,
                ctypes.byref(required),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            control = ctypes.c_ushort()
            revision = ctypes.c_ulong()
            if not advapi32.GetSecurityDescriptorControl(
                current, ctypes.byref(control), ctypes.byref(revision)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if not control.value & self._SE_DACL_PROTECTED:
                raise OSError("directory DACL inheritance remains enabled")
            owner_sid = ctypes.c_void_p()
            owner_defaulted = ctypes.c_int()
            if not advapi32.GetSecurityDescriptorOwner(
                current,
                ctypes.byref(owner_sid),
                ctypes.byref(owner_defaulted),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if not advapi32.EqualSid(owner_sid, current_user_sid):
                raise OSError("application directory is not owned by the current user")
            rendered = ctypes.c_wchar_p()
            if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                current,
                1,
                self._DACL_SECURITY_INFORMATION,
                ctypes.byref(rendered),
                None,
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                rendered_value = rendered.value or ""
                required_aces = (
                    "(A;OICI;FA;;;OW)",
                    "(A;OICI;FA;;;SY)",
                )
                if not all(ace in rendered_value for ace in required_aces):
                    raise OSError("directory DACL is not inheritable and restrictive")
                rendered_aces = {"(" + component for component in rendered_value.split("(")[1:]}
                if rendered_aces != set(required_aces):
                    raise OSError("directory DACL grants access to unexpected principals")
            finally:
                kernel32.LocalFree(rendered)
            if _has_redirected_component(path):
                raise OSError("application path changed during DACL application")
        finally:
            kernel32.LocalFree(descriptor)
            kernel32.CloseHandle(handle)


def _windows_local_app_data() -> Path:
    local = ctypes.c_wchar_p()
    folder_id = ctypes.c_byte * 16
    identifier = folder_id.from_buffer_copy(bytes.fromhex("8527b3f1ba6fcf4f9d557b8e7f157091"))
    result = ctypes.WinDLL("shell32").SHGetKnownFolderPath(
        ctypes.byref(identifier), 0, None, ctypes.byref(local)
    )
    if result != 0 or not local.value:
        raise OSError("LocalAppData is unavailable")
    try:
        return Path(local.value)
    finally:
        ctypes.windll.ole32.CoTaskMemFree(local)


def _posix_runtime_dir(*, system: str, uid: int, home: Path) -> Path:
    if system == "linux":
        run_user = Path("/run/user") / str(uid)
        try:
            details = os.lstat(run_user)
            safe = (
                _is_direct_directory(details)
                and details.st_uid == uid
                and stat.S_IMODE(details.st_mode) & 0o077 == 0
                and not _has_redirected_component(run_user)
            )
        except OSError:
            safe = False
        if safe:
            return run_user / "Zombie Killer"
    if system == "darwin":
        return home / "Library" / "Application Support" / "Zombie Killer" / "runtime"
    return home / ".local" / "state" / "Zombie Killer" / "runtime"


def _native_current_user_paths() -> tuple[Path, Path, Path]:
    if os.name == "nt":
        local = _windows_local_app_data()
        application = local / "Zombie Killer" / "Zombie Killer"
        return application, application, local / "Temp" / "Zombie Killer" / "Zombie Killer"
    import pwd

    uid = _effective_user_id()
    home = Path(pwd.getpwuid(uid).pw_dir)  # type: ignore[attr-defined]
    system = "darwin" if sys.platform == "darwin" else "linux"
    if system == "darwin":
        application = home / "Library" / "Application Support" / "Zombie Killer"
        return application, application, _posix_runtime_dir(system=system, uid=uid, home=home)
    return (
        home / ".local" / "share" / "Zombie Killer",
        home / ".local" / "state" / "Zombie Killer",
        _posix_runtime_dir(system=system, uid=uid, home=home),
    )


@dataclass(frozen=True, slots=True)
class AppPaths:
    """All mutable application roots, injectable for tests and embedding."""

    data_dir: Path
    state_dir: Path
    runtime_dir: Path
    backups_dir: Path
    graveyard_dir: Path

    @property
    def leases_dir(self) -> Path:
        return self.runtime_dir / "leases"

    @property
    def cancellations_dir(self) -> Path:
        return self.runtime_dir / "cancellations"

    @classmethod
    def for_current_user(cls) -> AppPaths:
        """Resolve deterministic OS-native paths without reading environment."""
        data, state, runtime = _native_current_user_paths()
        return cls(
            data_dir=data,
            state_dir=state,
            runtime_dir=runtime,
            backups_dir=data / "backups",
            graveyard_dir=data / "graveyard",
        )

    def ensure(
        self,
        *,
        platform_name: str | None = None,
        permission_backend: PermissionBackend | None = None,
    ) -> tuple[PathWarning, ...]:
        """Best-effort create directories and restrict them to the current user."""
        warnings: list[PathWarning] = []
        selected_platform = platform_name or ("windows" if os.name == "nt" else "posix")
        backend = permission_backend
        if backend is None:
            backend = (
                WindowsPermissionBackend()
                if selected_platform.casefold() == "windows"
                else PosixPermissionBackend()
            )
        unique_paths = dict.fromkeys(
            (
                self.data_dir,
                self.state_dir,
                self.runtime_dir,
                self.backups_dir,
                self.graveyard_dir,
                self.leases_dir,
                self.cancellations_dir,
            )
        )
        for path in unique_paths:
            try:
                redirected_component = _has_redirected_component(path)
            except OSError as error:
                warnings.append(
                    PathWarning(
                        code="DIRECTORY_PREPARE_FAILED",
                        path=redact_text(path, max_length=256),
                        message=redact_text(
                            "Could not inspect application directory ancestry "
                            f"({type(error).__name__}).",
                            max_length=512,
                        ),
                    )
                )
                continue
            if redirected_component:
                warnings.append(
                    PathWarning(
                        code="DIRECTORY_REDIRECTED",
                        path=redact_text(path, max_length=256),
                        message="Redirected application directory was rejected.",
                    )
                )
                continue
            try:
                existing_stat = os.lstat(path)
            except FileNotFoundError:
                existing_stat = None
            except OSError as error:
                warnings.append(
                    PathWarning(
                        code="DIRECTORY_PREPARE_FAILED",
                        path=redact_text(path, max_length=256),
                        message=redact_text(
                            f"Could not inspect application directory ({type(error).__name__}).",
                            max_length=512,
                        ),
                    )
                )
                continue
            if existing_stat is not None and not _is_direct_directory(existing_stat):
                warnings.append(
                    PathWarning(
                        code="DIRECTORY_REDIRECTED",
                        path=redact_text(path, max_length=256),
                        message="Redirected application directory was rejected.",
                    )
                )
                continue
            try:
                if os.name == "nt":
                    path.mkdir(mode=0o700, parents=True, exist_ok=True)
                else:
                    prepared_descriptor = _open_directory_nofollow(
                        path,
                        create=True,
                    )
                    os.close(prepared_descriptor)
            except OSError as error:
                warnings.append(
                    PathWarning(
                        code="DIRECTORY_PREPARE_FAILED",
                        path=redact_text(path, max_length=256),
                        message=redact_text(
                            f"Could not prepare application directory ({type(error).__name__}).",
                            max_length=512,
                        ),
                    )
                )
                continue
            try:
                redirected_component = _has_redirected_component(path)
            except OSError as error:
                warnings.append(
                    PathWarning(
                        code="DIRECTORY_PREPARE_FAILED",
                        path=redact_text(path, max_length=256),
                        message=redact_text(
                            "Could not verify application directory ancestry "
                            f"({type(error).__name__}).",
                            max_length=512,
                        ),
                    )
                )
                continue
            if redirected_component:
                warnings.append(
                    PathWarning(
                        code="DIRECTORY_REDIRECTED",
                        path=redact_text(path, max_length=256),
                        message="Redirected application directory was rejected.",
                    )
                )
                continue
            try:
                prepared_stat = os.lstat(path)
            except OSError as error:
                warnings.append(
                    PathWarning(
                        code="DIRECTORY_PREPARE_FAILED",
                        path=redact_text(path, max_length=256),
                        message=redact_text(
                            f"Could not verify application directory ({type(error).__name__}).",
                            max_length=512,
                        ),
                    )
                )
                continue
            if not _is_direct_directory(prepared_stat):
                warnings.append(
                    PathWarning(
                        code="DIRECTORY_REDIRECTED",
                        path=redact_text(path, max_length=256),
                        message="Redirected application directory was rejected.",
                    )
                )
                continue
            try:
                backend.restrict(path)
            except Exception as error:
                warnings.append(
                    PathWarning(
                        code="DIRECTORY_PERMISSION_RESTRICTION_FAILED",
                        path=redact_text(path, max_length=256),
                        message=redact_text(
                            "Could not restrict application directory permissions "
                            f"({type(error).__name__}).",
                            max_length=512,
                        ),
                    )
                )
        return tuple(warnings)
