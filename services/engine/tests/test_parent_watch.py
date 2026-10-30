from __future__ import annotations

import os
import threading

from zombie_killer_engine.parent_watch import _watch_broker_fd


def test_broker_liveness_watch_fires_only_after_writer_closes() -> None:
    reader, writer = os.pipe()
    terminated = threading.Event()
    watcher = threading.Thread(
        target=_watch_broker_fd,
        args=(reader, terminated.set),
        daemon=True,
    )
    watcher.start()

    assert not terminated.wait(timeout=0.05)
    os.close(writer)
    assert terminated.wait(timeout=2)
    watcher.join(timeout=2)
    assert not watcher.is_alive()
