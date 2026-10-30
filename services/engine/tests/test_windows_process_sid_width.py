"""Real Windows process-token SID checks across engine and SDK boundaries."""

from __future__ import annotations

import ctypes
import hashlib
import os
import re
import subprocess
from pathlib import Path

import pytest

from zombie_killer.lease import _secure_windows_directory, _windows_process_sid
from zombie_killer_engine.actions import _windows_token_sid
from zombie_killer_engine.leases import cancellation_user_fingerprint


def _current_user_sid() -> str:
    output = subprocess.check_output(["whoami", "/user", "/fo", "csv", "/nh"])
    match = re.search(rb"\bS-\d+(?:-\d+)+\b", output)
    assert match is not None
    return match.group().decode("ascii")


def _check_pointer_width(monkeypatch: pytest.MonkeyPatch) -> None:
    real_windll = ctypes.WinDLL

    class PointerCall:
        def __init__(self, real_function: object) -> None:
            self.real_function = real_function
            self.argtypes: object = None
            self.restype: object = None

        def __call__(self, *args: object) -> object:
            assert isinstance(args[0], ctypes.c_void_p) or (
                isinstance(self.argtypes, tuple) and self.argtypes[0] is ctypes.c_void_p
            ), "Win32 pointer argument must keep pointer width"
            if self.argtypes is not None:
                self.real_function.argtypes = self.argtypes
            if self.restype is not None:
                self.real_function.restype = self.restype
            return self.real_function(*args)

    class LibraryProxy:
        def __init__(self, library: object, wrapped: set[str]) -> None:
            self.library = library
            for name in wrapped:
                setattr(self, name, PointerCall(getattr(library, name)))

        def __getattr__(self, name: str) -> object:
            return getattr(self.library, name)

    def windll(name: str, *, use_last_error: bool = False) -> object:
        library = real_windll(name, use_last_error=use_last_error)
        wrapped = {
            "advapi32": {"OpenProcessToken", "ConvertSidToStringSidW", "SetKernelObjectSecurity"},
            "kernel32": {"CloseHandle"},
        }.get(name.casefold())
        return LibraryProxy(library, wrapped) if wrapped else library

    monkeypatch.setattr(ctypes, "WinDLL", windll)


@pytest.mark.skipif(os.name != "nt", reason="Win32 process-token APIs are Windows-only")
def test_engine_cancellation_fingerprint_uses_complete_process_sid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _check_pointer_width(monkeypatch)
    expected = hashlib.sha256(_current_user_sid().encode("ascii")).hexdigest()

    assert cancellation_user_fingerprint(os.getpid(), "unused", platform_name="nt") == expected


@pytest.mark.skipif(os.name != "nt", reason="Win32 process-token APIs are Windows-only")
def test_sdk_process_sid_uses_complete_process_sid(monkeypatch: pytest.MonkeyPatch) -> None:
    _check_pointer_width(monkeypatch)
    assert _windows_process_sid(os.getpid()) == _current_user_sid()


@pytest.mark.skipif(os.name != "nt", reason="Win32 process-token APIs are Windows-only")
def test_action_process_sid_uses_complete_process_sid(monkeypatch: pytest.MonkeyPatch) -> None:
    _check_pointer_width(monkeypatch)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.OpenProcess.argtypes = (ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel32.CloseHandle.restype = ctypes.c_int
    process = kernel32.OpenProcess(0x1000, False, os.getpid())
    assert process
    try:
        assert _windows_token_sid(advapi32, kernel32, process) == _current_user_sid()
    finally:
        assert kernel32.CloseHandle(ctypes.c_void_p(process))


@pytest.mark.skipif(os.name != "nt", reason="Win32 directory ACL APIs are Windows-only")
def test_sdk_directory_security_uses_full_handle_width(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _check_pointer_width(monkeypatch)
    protected = tmp_path / "sdk-private"
    protected.mkdir()
    _secure_windows_directory(protected)
