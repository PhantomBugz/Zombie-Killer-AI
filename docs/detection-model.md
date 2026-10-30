# Detection and Evidence Model

Zombie Killer separates **what was observed** from **what state is inferred**. A state never grants authority to stop or modify a process.

## Identity

A live target is bound to at least PID, operating-system boot identity, creation time, and executable evidence. The engine exposes an opaque `process_instance_id` derived from the binding. Every process plan records the reviewed binding and revalidates it immediately before each signal. A matching PID or process name alone is insufficient because PIDs are reused.

SDK leases add a registration nonce, project, role, provider label, heartbeat, parent identity, declared detach intent, and optional resource/counter evidence. A lease enriches a process only when its identity matches. Old-boot, malformed, oversized, mismatched, or inaccessible leases produce bounded warnings rather than ownership.

## Evidence grades

| Grade | Meaning |
| --- | --- |
| `confirmed` | Current process identity and valid SDK lifecycle evidence agree |
| `strong` | Multiple current signals support the state, but one lifecycle fact is indirect or expired |
| `partial` | Some relevant evidence exists but is not sufficient for a strong conclusion |
| `signature_only` | Command/executable resembles an agent tool; no managed identity is established |
| `insufficient` | The available evidence cannot support a useful classification |

Signature-only candidates remain `unmanaged` and are not actionable by default.

## Lifecycle states

| State | Interpretation |
| --- | --- |
| `healthy` | Valid managed lease is advancing within the configured grace period |
| `idle` | Agent declared an intentional idle state and its lease remains current |
| `stale` | Heartbeat/lifecycle evidence expired, but orphaning or unresponsiveness is not established |
| `orphaned` | A live attached agent's verified parent instance is gone; declared detached agents are not labeled orphaned for that reason |
| `unresponsive` | Strong live evidence indicates missed heartbeat plus corroborating lack of progress |
| `unmanaged` | Candidate resembles an agent runtime without a trusted SDK identity |
| `interrupted` | Managed lifecycle ended without a clean terminal state or reconciliation remains incomplete |
| `defunct` | POSIX process has exited but its parent has not reaped its status |
| `completed`, `failed`, `cancelled` | SDK declared a terminal outcome |
| `unknown` | Evidence is missing, contradictory, inaccessible, or unsafe to interpret |

A true POSIX `defunct` process is already dead: it performs no API calls and uses no active application RAM/CPU. Sending another signal cannot fix it. The living parent must wait/reap, or the operating system must adopt and reap it. Windows has no directly equivalent `psutil` process state.

## Coverage

Each scan reports whether coverage is complete plus warnings and counts for inaccessible or raced processes. Permission boundaries, process exit during collection, platform API gaps, and protected processes can reduce visibility. `zero results + incomplete coverage` means “nothing confirmed in visible scope,” not “nothing exists.”

The scanner reads low-cost process attributes and does not read process environments. Command-line evidence is bounded and redacted. Provider usage cost remains `unknown` unless an instrumented agent explicitly supplies measured counters; the project has no price table or API billing access.

On Windows, the scanner captures parent PIDs from one system-table snapshot. The pinned `psutil` Windows backend cannot report POSIX-style defunct processes, and its per-process status call only distinguishes running from fully suspended while repeatedly walking the system process/thread table. Zombie Killer therefore records an unprobed Windows OS status as `unknown` instead of claiming `running` or `stopped`. Process presence, creation time, parent PID, owner, executable evidence, and action identity remain in the scan. POSIX status collection is unchanged.

## Presets

Presets alter corroboration thresholds and stale windows; they never enable automatic killing. `Conservative` requires the most corroboration, `Balanced` is the default, and `Aggressive` shortens stale windows while retaining identity and review requirements. In the current native desktop composition, preset controls may be unavailable even though settings exist in the engine.

## False reports

Use the [detection issue form](../.github/ISSUE_TEMPLATE/detection.yml) with synthetic or redacted evidence. Include platform, version, coverage warning, state, grade, reason codes, and expected result. Never include provider keys, raw prompts, private memory content, or unrelated process data.
