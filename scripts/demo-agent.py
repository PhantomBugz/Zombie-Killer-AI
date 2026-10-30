#!/usr/bin/env python3
"""Synthetic, local-only SDK agent used by the deterministic release fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from threading import Event

_CONTENT = {
    "target": b"Zombie Killer release fixture target artifact\n",
    "sibling": b"Zombie Killer release fixture sibling artifact\n",
}
_PROVIDER_ENVIRONMENT_NAMES = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "GOOGLE_API_KEY",
        "HACKENPROOF_API_KEY",
        "OPENAI_API_KEY",
    }
)


def _deny_network(event: str, _arguments: tuple[object, ...]) -> None:
    if event == "socket.__new__" or event.startswith("socket."):
        raise PermissionError("the synthetic release agent is local-only")


def _atomic_json(path: Path, payload: dict[str, object]) -> None:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--approved-root", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--ready-file", required=True, type=Path)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--kind", required=True, choices=tuple(_CONTENT))
    parser.add_argument("--max-runtime-seconds", required=True, type=float)
    arguments = parser.parse_args()
    if not 5 <= arguments.max_runtime_seconds <= 60:
        parser.error("--max-runtime-seconds must be between 5 and 60")
    return arguments


def main() -> int:
    arguments = _parse_arguments()
    sys.addaudithook(_deny_network)
    from zombie_killer import register

    root = arguments.approved_root.resolve(strict=True)
    artifact = arguments.artifact.absolute()
    artifact.parent.resolve(strict=True).relative_to(root)
    if artifact.exists():
        raise FileExistsError("the synthetic artifact already exists")
    content = _CONTENT[arguments.kind]
    with artifact.open("xb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())

    cancelled = Event()
    agent = register(
        provider="local",
        project="Zombie Killer Release Fixture",
        role="Synthetic same-script agent",
        state_dir=arguments.state_dir,
        agent_id=arguments.agent_id,
        run_id=arguments.run_id,
        heartbeat_interval=1.0,
        lease_ttl=5.0,
        strict=True,
        on_cancel=cancelled.set,
    )
    try:
        if not agent.track_temp(artifact, root=root):
            raise RuntimeError("the synthetic artifact declaration was not published")
        agent.status(f"Synthetic {arguments.kind} agent awaiting cooperative stop")
        _atomic_json(
            arguments.ready_file,
            {
                "agent_id": agent.agent_id,
                "artifact_sha256": hashlib.sha256(content).hexdigest(),
                "network_guard_active": True,
                "pid": os.getpid(),
                "provider_credentials_present": any(
                    name in os.environ for name in _PROVIDER_ENVIRONMENT_NAMES
                ),
            },
        )
        deadline = time.monotonic() + arguments.max_runtime_seconds
        while not cancelled.wait(0.05):
            if time.monotonic() >= deadline:
                agent.close(result="failed")
                return 2
        agent.close(result="cancelled")
        return 0
    except BaseException:
        agent.close(result="failed")
        raise


if __name__ == "__main__":
    raise SystemExit(main())
