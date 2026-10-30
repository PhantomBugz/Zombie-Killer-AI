# Zombie Killer Python SDK

`zombie-killer-sdk` is the standard-library-only lifecycle broadcaster for the local
Zombie Killer application. Your application continues normally when Zombie Killer is
not installed or its per-user runtime directory is unavailable.

```python
from pathlib import Path

from zombie_killer import Agent


def search(approved_root: Path) -> None:
    output = approved_root / "cards.json"
    output.touch()
    with Agent(provider="google-gemini", project="MTGA Cardbot", role="Search Bot") as agent:
        agent.status("Searching local card files")
        agent.track_temp(output, root=approved_root)
        agent.record_usage(requests=1, input_tokens=10, output_tokens=2, cost_usd=None)
        if agent.cancelled:
            return
```

`register(...)` constructs and starts the same `Agent`. Both synchronous and asynchronous
context managers are supported. `close(result="completed" | "failed" | "cancelled")`
writes a terminal lease and is idempotent.

Canonical provider slugs are `openai`, `anthropic-claude`, `google-gemini`, `xai-grok`,
`local`, and `custom`. Use `parent_pid`, `parent_identity`, and `parent_agent_id` for an
attached worker, or set `survive_parent=True` for explicit detached intent. `run_id` and all
agent/owner IDs are UUIDs.

## Privacy and safety

The SDK never reads prompts, response bodies, command lines, provider credentials, or process
environment data. Default paths come from native OS identity/location APIs: the Windows Local
AppData known folder, a verified private `/run/user/<uid>` on Linux with a passwd-home fallback,
or passwd-home Application Support on macOS. Lease files contain only bounded lifecycle
metadata. Status text is
secret-redacted, but status labels must still never contain prompts, PII, credentials, or
arbitrary exception text.

Temporary resources require an existing absolute path strictly below an existing absolute
approved root. Canonical resource paths and roots are limited to 4096 characters before the
resource list changes. A declaration is informational cleanup evidence only; it is not proof of
continuing path or mount authority and is never permission to follow links, cross mounts, or touch
siblings. The engine independently revalidates ownership, containment, links, mount boundaries,
and cleanup authority immediately before any cleanup. Expected ports are loopback intent only and
never cleanup authority.

Cancellation is cooperative. The SDK accepts only an unexpired protocol-v2 request bound to
the full current process identity and registration nonce, acknowledges that request, exposes
`agent.cancelled`, and optionally invokes a callback on the heartbeat thread. It never sends
signals or terminates the application.

`state_dir=` is an integration/test override for the runtime root containing `leases/` and
`cancellations/`. It must be absolute and is accepted only when the SDK can prove a direct,
current-user-private directory. `strict=True` turns registration failure into a safe
`SDKError`; default mode retains local status and retries quietly.

## Cooperative budgets

Configure `max_requests`, `max_tokens`, `max_runtime_seconds`, `max_idle_seconds`, or
`max_rss_bytes`. Wrap provider activity with `agent.before_request(callback)`. It atomically
reserves one request by default; pass `BudgetReservation(requests=1, input_tokens=10,
output_tokens=2, cost_usd=None, runtime_seconds=0)` to reserve estimated capacity. Concurrent
in-flight reservations count toward limits. Callback success commits requests, tokens, and cost
once, while an exception releases them. Runtime reservation is concurrent capacity; runtime
telemetry remains monotonic wall time. Calling `before_request()` without a callback immediately
commits the reservation. Do not also call `record_usage` for the same reserved values. The method
raises `BudgetExceeded` before the callback when capacity is unavailable. Budgets are telemetry
and cooperative control only; the SDK performs no network calls and contains no pricing table.
