# Python Lifecycle SDK

`zombie-killer-sdk` adds trusted lifecycle context that an operating-system process scan cannot infer. Its runtime uses only the Python standard library and remains nonfatal by default when Zombie Killer is absent.

## Install from this source tree

```powershell
uv pip install -e packages/sdk-python
```

Published package installation is not yet claimed. Verify source, version, and hashes before installing any package presented under this name.

## Basic use

```python
from pathlib import Path
from zombie_killer import Agent

approved_root = Path.cwd() / "temporary-output"
approved_root.mkdir(exist_ok=True)

with Agent(provider="custom", project="Indexer", role="Search worker") as agent:
    output = approved_root / "batch.json"
    output.write_text("{}", encoding="utf-8")
    agent.track_temp(output, root=approved_root)
    agent.status("Indexing local fixtures")
    if agent.cancelled:
        raise SystemExit(0)
```

`register(...)` starts the same agent object. Synchronous and asynchronous context managers write terminal results, including cancellation during asynchronous startup. Attached workers report an expected parent PID and optional parent agent ID; `parent_identity` currently supplies the PID, rather than persisting the full parent identity. `survive_parent=True` declares intentional detach behavior.

## Lease contract

Leases are atomic, bounded, per-user files containing process identity, random registration nonce, lifecycle labels, heartbeat, terminal state, optional parent, declared resources, expected loopback ports, and optional usage counters. They do not contain prompts, response bodies, provider keys, or process environments. Status text is redacted and bounded, but callers must still use a short operational label—not user content, PII, credentials, or arbitrary exceptions.

Cancellation is cooperative. The SDK accepts only a current protocol-v2 request bound to the complete process identity and registration nonce, acknowledges it, and exposes `agent.cancelled` or invokes an optional callback. It never installs replacement signal handlers or sends a termination signal.

## Resources

`track_temp(path, root=approved_root)` accepts only an existing absolute resource strictly below an existing absolute root that can be proved current-user-private. New declarations retain that root, the resource type, and a bounded creation fingerprint. Declare the resource after its intended contents exist; changing it afterward invalidates cleanup until it is declared again.

The local engine composes complete declarations into individually reviewed cleanup manifests, bound to the exact lease identity and registration nonce. Legacy path-only declarations do not acquire cleanup authority. A declaration never grants permission to follow links, cross mounts, mutate siblings, or clean up without revalidation. The engine remains authoritative; SDK registration alone never triggers cleanup.

## Counters and budgets

`record_usage` stores values the application supplies. It makes no network call and does not know provider pricing. Use `cost_usd=None` when cost is not measured. Cooperative request/token/runtime/idle/RSS budgets can reject a caller before its provider callback, but they are not external billing limits and cannot cancel a request already accepted by a provider.

## Failure behavior

Default mode retains local status and retries quietly if the runtime directory is unavailable. `strict=True` raises a bounded `SDKError`, which is useful during integration testing. The SDK derives default paths from OS identity APIs; a custom `state_dir` is for integrations/tests and is accepted only when it is absolute and current-user-private.

See the package-level [SDK README](../packages/sdk-python/README.md) for the full API contract.
