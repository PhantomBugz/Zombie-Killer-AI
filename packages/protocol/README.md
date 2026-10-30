# Zombie Killer local protocol

Version `1.0` is a local-only, newline-delimited JSON protocol between the desktop broker or CLI and the Python engine. It has no network listener. Each input line receives exactly one response line, and engine logs use standard error only.

Requests carry only `protocol_version`, a UUID `request_id`, a finite `method`, and a method-specific `payload`. Authorization context is trusted launcher state supplied out of band; a JSON request cannot select its client kind, capability, or local-control authority. Responses repeat the version, request ID, and resolved method and contain either a non-null typed result or a structured, redacted error. Unknown versions and methods fail closed; compatibility requires an exact major/minor match for v1.

Error details use only the fixed keys `correlation_id`, `field`, `reason`, and `supported_version`, plus engine-generated `redacted_detail_N` placeholders. Unrecognized keys and their values are replaced rather than echoed.

The input frame limit is 1 MiB and the output frame limit is 4 MiB. JSON nesting, collection sizes, strings, duplicate object keys, invalid UTF-8, non-finite numbers, multiple JSON values, and embedded newlines are bounded or rejected. Persistent stdio recovers at the next line after an invalid frame and keeps a bounded LRU/TTL cache of request IDs for the session; replayed IDs fail with `conflict` before dispatch. One-shot mode reads one frame through EOF and rejects trailing or smuggled frames.

Capabilities are `read`, `planning`, and `execution`. SDK and telemetry contexts cannot plan or execute. Execution additionally requires a local-control context plus the exact stored plan ID and digest; there is no `force=true` shortcut. A user-selected vault path is accepted only by named probe/register requests. Probe is read-only, while every destructive action remains a separate preview-and-execute flow.

Scans expose an opaque `process_instance_id` alongside each PID. `action.plan` requires the reviewed PID and binding, rejects restarts or PID reuse with `target_changed`, and returns the authoritative bound target and state. Settings reads return one persisted revision; updates require `expected_revision` and atomically apply all supplied keys or none. Activity and quarantine pages use opaque cursors. Quarantine `partial` and `interrupted` entries are honest non-restorable public outcomes, not confirmed quarantine success.

## Meaning of state and evidence

State and evidence are separate. `unmanaged` with `signature_only` evidence means a conservative candidate, never a confirmed agent. `unknown` means available evidence is insufficient. `coverage.complete=false` means partial visibility; callers must display the warnings and must not treat an empty result as proof that nothing exists.

On POSIX, `defunct` has its technical process meaning: the child has exited, but its living parent has not yet called a wait operation to collect the exit status. The kernel retains a process-table entry containing the PID and exit status. It is not running and cannot be fixed by sending another signal; it disappears after the parent waits (or after adoption and reaping). Windows does not expose the same process state.

Receipts distinguish verified outcomes from failures before issue and uncertain outcomes. `uncertain` means an operation might have crossed the operating-system boundary without a durable final receipt; the UI must not relabel it as success or failure without reconciliation. Every receipt includes a bounded `partial_failures` array (at most 64 redacted reasons of at most 2,048 characters each). A nonempty array means action issuance may be verified while follow-up work or verification remained incomplete, so callers must label the receipt partial and must never render it as completed success.

Provider usage cost is `unknown` unless measured evidence is available. Unknown cost is never shown as a `$0` guess. Every successful Memory Vault result carries this warning: "Changes affect only local user-controlled memory; they do not change provider safety, rate limits, account state, or guarantee continuation."

Diagnostics export is a planned local action. The destination must be selected and approved locally, and the preview excludes raw command lines, memory contents, filesystem paths, and secrets by default. Engines that cannot produce that sanitized export return the typed `unsupported` error instead of dumping broader data.
