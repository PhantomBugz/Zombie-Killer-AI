# Architecture

Zombie Killer is a local desktop application with a separately testable engine and opt-in lifecycle SDK. It does not require a cloud control plane.

```text
React WebView (untrusted display/input)
        │ one typed Tauri command, request <= 128 KiB
        ▼
Rust broker (method allowlist, timeout, verified engine bundle)
        │ one JSON request / one JSON response over inherited stdio
        ▼
Python engine (classification, planning, adapters, receipts)
   ├── OS process APIs
   ├── per-user SQLite state
   ├── per-user runtime leases and cancellation requests
   ├── backups and Graveyard
   └── explicitly registered local memory sources

Instrumented agent ──atomic local lease──► runtime directory
```

## Components and trust boundaries

### React renderer

The renderer displays redacted engine results and gathers operator intent. It has no generic shell permission and cannot choose an executable. Browser preview uses deterministic synthetic data and cannot inspect or mutate the host. The renderer is not trusted to authorize an operation; the engine validates the method payload, plan digest, revision, expiry, and target again.

### Rust broker

The Tauri command accepts a finite Serde-tagged method set. It launches only the packaged engine entry selected by the verified resource manifest, sends one bounded frame, reads bounded stdout/stderr, applies method-specific timeouts, and contains descendants. It does not expose a shell plugin or arbitrary executable/path command.

Current broker limits are 128 KiB from renderer to broker, 1 MiB engine input, 4 MiB engine output, and 64 KiB captured stderr. Default method timeouts range from 10 to 45 seconds. On timeout or abnormal completion, the broker terminates/reaps the exact child group and returns a redacted structured error.

The packaged sidecar is a trust boundary: its manifest and hashes must be generated from the exact build, verified before launch, distributed with license notices, and produced only by a trusted release workflow. A same-user attacker who can replace running application code or control the user's account is outside the core boundary.

### Python engine

The engine owns process collection, evidence classification, immutable plans, process-instance revalidation, quarantine, Memory Vault adapters, settings, and receipts. Protocol v1.0 uses newline-delimited JSON with a 1 MiB input and 4 MiB output limit, nesting depth 32, at most 10,000 collection members, and 65,536-character strings. Unknown methods, extra model fields, duplicate keys, invalid UTF-8, non-finite numbers, and replayed request IDs fail closed.

### Lifecycle SDK

The standard-library Python SDK writes bounded leases atomically to the current user's runtime directory. It exposes cooperative cancellation; it never signals the host process, contacts a provider, reads the process environment, or handles provider credentials. Resource declarations are evidence, not standalone cleanup authority. Complete root/fingerprint declarations can be composed into reviewed engine cleanup manifests; legacy path-only declarations cannot.

## State and deletion

The [privacy document](../PRIVACY.md) lists platform paths. The data root contains backups and `graveyard`; the state root contains the WAL-mode audit database and settings; the runtime root contains leases and cancellation requests. The engine attempts current-user-only permissions and reports degraded preparation.

Quarantine carries 30-day retention **metadata**, but this alpha performs no automatic purge. Memory snapshots are retained for 30 days by metadata and are not silently deleted. Receipts and backups persist until a user removes local application data or a future verified purge is implemented. Deleting backups or Graveyard content destroys recovery options.

## Capability composition

The default engine composes source registration, supported memory mutation/snapshot/restore, declared-resource quarantine and exact restore, local diagnostics export, revisioned settings, and receipt lookup. Plans and private executable authority persist across separate one-shot engine invocations. The Rust broker validates finite method-specific payloads and results; the native renderer enables workflows only after the engine reports their methods and the adapter reports the relevant capability.

Consequences:

- Use the browser demo to evaluate complete UI flows without host changes.
- Register an explicit local source before native Memory Vault operations; recognized vector formats stay read-only or inventory-only.
- Quarantine only complete, unchanged SDK-declared temporary resources; restore the exact recorded entry without overwriting its original destination.
- Export diagnostics only to a reviewed explicit local destination; existing files are preserved and private memory drafts are excluded.
- Process actions remain platform-specific: Windows stable handles and Linux runtime-probed pidfd support. macOS native operation remains experimental and unqualified; its current engine code declines process actions. `zk action plan` requires exact scan-derived PID and process-instance ID, not an agent ID alone.
- Separate adapter tests, real one-shot broker integration, native startup smoke, browser checks, and clean-machine release evidence.

Supported concurrency limits are documented in [Memory Vault](memory-vault.md). Signing, clean-machine verification, and platform release coverage remain explicit gates in [release verification](release-verification.md) and [ROADMAP.md](../ROADMAP.md).

## No provider-side effect

All runtime effects are local to the user's machine. Editing a supported local memory record does not change a provider's safety decisions, account state, rate limits, remote memory, or billing. The engine opens no provider connection and contains no provider authentication flow. Package managers, Git, GitHub Actions, operating-system WebViews, and user-opened documentation links are separate tools with their own network behavior.
