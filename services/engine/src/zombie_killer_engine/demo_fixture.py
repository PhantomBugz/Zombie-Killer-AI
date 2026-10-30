"""Harmless local Zombie Lab heartbeat fixture; never contacts a network."""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path


def _write_heartbeat(path: Path, token: str) -> None:
    payload = json.dumps(
        {
            "heartbeat_at": datetime.now(UTC).isoformat(),
            "pid": os.getpid(),
            "token": token,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(payload, encoding="utf-8")
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Local-only Zombie Lab fixture")
    parser.add_argument("--token", required=True)
    parser.add_argument("--heartbeat", required=True, type=Path)
    parser.add_argument("--stale-after", type=float)
    arguments = parser.parse_args()
    arguments.heartbeat.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    while True:
        if arguments.stale_after is None or time.monotonic() - started < arguments.stale_after:
            _write_heartbeat(arguments.heartbeat, arguments.token)
        time.sleep(0.25)


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    raise SystemExit(main())
