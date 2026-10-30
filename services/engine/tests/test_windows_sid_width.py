"""Exercise pointer-sized SID owner comparisons on Windows."""

from __future__ import annotations

import ctypes
import os
from pathlib import Path

import pytest

from zombie_killer_engine.paths import WindowsPermissionBackend
from zombie_killer_engine.store import _restrict_windows_database_file


@pytest.mark.skipif(os.name != "nt", reason="Win32 SID APIs are Windows-only")
def test_directory_and_database_owner_comparisons_use_pointer_sized_sids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_windll = ctypes.WinDLL
    equal_sid_calls: list[tuple[object, object]] = []

    class EqualSidProbe:
        def __init__(self, real_equal_sid: object) -> None:
            self.real_equal_sid = real_equal_sid
            self.argtypes: object = None
            self.restype: object = None

        def __call__(self, left: object, right: object) -> int:
            assert self.argtypes == (ctypes.c_void_p, ctypes.c_void_p)
            assert self.restype is ctypes.c_int
            self.real_equal_sid.argtypes = self.argtypes
            self.real_equal_sid.restype = self.restype
            equal_sid_calls.append((left, right))
            return int(self.real_equal_sid(left, right))

    class Advapi32Proxy:
        def __init__(self, library: object) -> None:
            self.library = library
            self.EqualSid = EqualSidProbe(library.EqualSid)

        def __getattr__(self, name: str) -> object:
            return getattr(self.library, name)

    def windll(name: str, *, use_last_error: bool = False) -> object:
        library = real_windll(name, use_last_error=use_last_error)
        return Advapi32Proxy(library) if name.lower() == "advapi32" else library

    monkeypatch.setattr(ctypes, "WinDLL", windll)
    protected = tmp_path / "protected"
    protected.mkdir()
    WindowsPermissionBackend().restrict(protected)
    database = protected / "database.sqlite3"
    database.touch()
    _restrict_windows_database_file(database)
    assert len(equal_sid_calls) == 3
