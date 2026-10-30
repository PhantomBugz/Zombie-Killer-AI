"""Test-only worker that consumes the real bound cancellation protocol."""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

ENGINE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ENGINE_ROOT / "src"))

from zombie_killer_engine.actions import PsutilProcessController  # noqa: E402
from zombie_killer_engine.leases import (  # noqa: E402
    clear_cancellation_request,
    observe_cancellation_request,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", required=True)
    parser.add_argument("--idle", action="store_true")
    parser.add_argument("--cancellation-dir", type=Path)
    parser.add_argument("--agent-id")
    parser.add_argument("--registration-nonce")
    arguments = parser.parse_args()
    token = arguments.token
    if not arguments.idle and (
        arguments.cancellation_dir is None
        or arguments.agent_id is None
        or arguments.registration_nonce is None
    ):
        parser.error("bound cancellation arguments are required unless --idle is set")
    controller = PsutilProcessController()
    identity = controller.read_identity(os.getpid())
    while True:
        if not token:
            raise RuntimeError("the unique test token disappeared")
        if not arguments.idle:
            request = observe_cancellation_request(
                arguments.cancellation_dir,
                arguments.agent_id,
                observer_identity=identity,
                registration_nonce=arguments.registration_nonce,
            )
            if request is not None and clear_cancellation_request(
                arguments.cancellation_dir,
                arguments.agent_id,
                observer_identity=identity,
                registration_nonce=arguments.registration_nonce,
            ):
                return
        time.sleep(0.02)


if __name__ == "__main__":
    main()
