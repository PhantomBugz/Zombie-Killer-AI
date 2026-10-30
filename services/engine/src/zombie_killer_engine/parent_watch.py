"""Broker-owned liveness channel for terminating orphaned native sidecars."""

from __future__ import annotations

import os
import signal
import threading
from collections.abc import Callable
from contextlib import suppress
from typing import cast

_BROKER_FD_ENV = "ZK_PARENT_FD"
_BROKER_FD = 198
_PARENT_LOST_EXIT = 70


def _terminate_process_group() -> None:
    try:
        kill_group = cast(Callable[[int, int], None], os.__dict__["killpg"])
        process_group = cast(Callable[[], int], os.__dict__["getpgrp"])
        kill_group(process_group(), cast(int, signal.__dict__["SIGKILL"]))
    finally:
        os._exit(_PARENT_LOST_EXIT)


def _watch_broker_fd(fd: int, terminate: Callable[[], None]) -> None:
    try:
        while os.read(fd, 1):
            pass
    except OSError:
        pass
    finally:
        with suppress(OSError):
            os.close(fd)
    terminate()


def install_broker_liveness_watch() -> None:
    raw_fd = os.environ.pop(_BROKER_FD_ENV, None)
    if raw_fd is None:
        return
    if os.name != "posix" or raw_fd != str(_BROKER_FD):
        os._exit(_PARENT_LOST_EXIT)
    try:
        os.set_inheritable(_BROKER_FD, False)
        os.fstat(_BROKER_FD)
    except OSError:
        os._exit(_PARENT_LOST_EXIT)
    threading.Thread(
        target=_watch_broker_fd,
        args=(_BROKER_FD, _terminate_process_group),
        name="zombie-killer-broker-liveness",
        daemon=True,
    ).start()


__all__ = ["install_broker_liveness_watch"]
