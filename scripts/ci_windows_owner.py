"""Run a Windows CI command with new files owned by the token's user SID.

GitHub's elevated runner can create files owned by BUILTIN\\Administrators.
The product correctly rejects those paths. This launcher changes only its
process token's default owner, then verifies that a child process inherits it.
It never changes an existing file's owner or the product's ACL policy.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

_TOKEN_QUERY = 0x0008
_TOKEN_ADJUST_DEFAULT = 0x0080
_TOKEN_USER = 1
_TOKEN_OWNER = 4
_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION = 1


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("attributes", ctypes.c_ulong)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("user", _SidAndAttributes)]


class _TokenOwner(ctypes.Structure):
    _fields_ = [("owner", ctypes.c_void_p)]


def _libraries() -> tuple[Any, Any]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
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
    advapi32.SetTokenInformation.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_ulong,
    )
    advapi32.GetNamedSecurityInfoW.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.GetNamedSecurityInfoW.restype = ctypes.c_ulong
    advapi32.EqualSid.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    return kernel32, advapi32


def _open_current_token(kernel32: Any, advapi32: Any, access: int) -> ctypes.c_void_p:
    token = ctypes.c_void_p()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), access, ctypes.byref(token)):
        raise OSError("current process token could not be opened")
    return token


def _token_user_sid(advapi32: Any, token: ctypes.c_void_p) -> tuple[object, int]:
    size = ctypes.c_ulong()
    advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(size))
    if size.value < ctypes.sizeof(_TokenUser):
        raise OSError("token user SID size is invalid")
    buffer = ctypes.create_string_buffer(size.value)
    if not advapi32.GetTokenInformation(token, _TOKEN_USER, buffer, size.value, ctypes.byref(size)):
        raise OSError("token user SID could not be read")
    sid = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents.user.sid
    if not sid:
        raise OSError("token user SID is empty")
    return buffer, sid


def _assert_new_directory_owner(kernel32: Any, advapi32: Any, user_sid: int) -> None:
    path = Path(tempfile.mkdtemp(prefix="zombie-ci-owner-"))
    try:
        owner = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        result = advapi32.GetNamedSecurityInfoW(
            str(path),
            _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            None,
            None,
            ctypes.byref(descriptor),
        )
        if result != 0 or not owner.value or not descriptor.value:
            raise OSError("new directory owner could not be read")
        try:
            if not advapi32.EqualSid(owner, user_sid):
                raise OSError("new directory owner differs from token user")
        finally:
            kernel32.LocalFree(descriptor)
    finally:
        path.rmdir()


def _probe_child_owner() -> None:
    kernel32, advapi32 = _libraries()
    token = _open_current_token(kernel32, advapi32, _TOKEN_QUERY)
    try:
        _token_buffer, user_sid = _token_user_sid(advapi32, token)
        _assert_new_directory_owner(kernel32, advapi32, user_sid)
    finally:
        kernel32.CloseHandle(token)


def _launch(command: list[str]) -> int:
    kernel32, advapi32 = _libraries()
    token = _open_current_token(kernel32, advapi32, _TOKEN_QUERY | _TOKEN_ADJUST_DEFAULT)
    try:
        _token_buffer, user_sid = _token_user_sid(advapi32, token)
        owner = _TokenOwner(user_sid)
        if not advapi32.SetTokenInformation(
            token, _TOKEN_OWNER, ctypes.byref(owner), ctypes.sizeof(owner)
        ):
            raise OSError("token default owner could not be set")
        _assert_new_directory_owner(kernel32, advapi32, user_sid)
        probe = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--probe"], check=False
        )
        if probe.returncode != 0:
            raise OSError("child process did not inherit the user default owner")
        return subprocess.run(command, check=False).returncode
    finally:
        kernel32.CloseHandle(token)


def main(argv: list[str]) -> int:
    if os.name != "nt":
        print("Windows CI owner launcher requires Windows.", file=sys.stderr)
        return 2
    try:
        if argv == ["--probe"]:
            _probe_child_owner()
            return 0
        if len(argv) < 2 or argv[0] != "--":
            print("Usage: ci_windows_owner.py -- executable [arguments...]", file=sys.stderr)
            return 2
        return _launch(argv[1:])
    except OSError:
        print("Windows CI owner setup or command launch failed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
