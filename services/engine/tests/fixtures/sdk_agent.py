"""Test-only SDK agent that publishes a real lease until terminated."""

from __future__ import annotations

import argparse
import signal
import sys
import threading
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPOSITORY_ROOT / "packages" / "sdk-python" / "src"))

from zombie_killer import Agent  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-dir", required=True, type=Path)
    parser.add_argument("--agent-id", required=True)
    arguments = parser.parse_args()
    stopped = threading.Event()

    def stop(_signum: int, _frame: object) -> None:
        stopped.set()

    signal.signal(signal.SIGTERM, stop)
    if hasattr(signal, "SIGINT"):
        signal.signal(signal.SIGINT, stop)

    agent = Agent(
        provider="custom",
        project="Action identity integration",
        role="SDK fixture",
        state_dir=arguments.runtime_dir,
        agent_id=arguments.agent_id,
        heartbeat_interval=1,
    ).start()
    try:
        stopped.wait()
    finally:
        agent.close()


if __name__ == "__main__":
    main()
