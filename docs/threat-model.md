# Threat Model

## Assets

- Correct identity of a process selected for containment
- Availability and integrity of unrelated local processes
- User files, registered memory stores, backups, and Graveyard entries
- Confidentiality of credentials, prompts, memory content, paths, and diagnostics
- Integrity of plans, receipts, settings, engine bundle, source, dependencies, and release artifacts
- Operator understanding of partial evidence and uncertain outcomes

## Trust boundaries

1. Operator and operating-system account
2. React WebView to Rust broker
3. Rust broker to packaged Python engine over inherited standard I/O
4. Engine to operating-system process/filesystem APIs
5. Engine to SQLite audit state, backups, Graveyard, and registered sources
6. SDK-instrumented agent to atomic runtime lease
7. Source/dependency/release automation to distributed artifacts

The current user's account is the administrative boundary. Zombie Killer attempts per-user permissions, but it cannot defend against an attacker already able to run arbitrary same-user code, replace the installed application, debug the process, or modify the operating system.

## Principal threats and controls

| Threat | Controls | Residual risk |
| --- | --- | --- |
| PID reuse/wrong process | Boot ID, PID, creation time, executable/process-instance binding; revalidate before every signal | Platform APIs may be incomplete; action refuses instead of guessing |
| Spoofed/stale lease | Private directory, strict schema/size, nonce, full identity, expiry/boot checks | Same-user malicious code remains in scope of OS account trust |
| Signature false positive | `signature_only` → `unmanaged`; no default action | Operator may misinterpret labels; UI must retain evidence grade |
| Renderer command injection | One typed Tauri command, finite methods, no shell plugin, fixed engine path | Broker/parser defects; bounded fuzz/unit tests required |
| Engine substitution | Build-time manifest, hash verification, fixed resource resolution, child containment | Compromised release/build chain or same-user installation tampering |
| Protocol denial/confusion | Frame/depth/string/collection limits, duplicate-key refusal, request correlation/replay checks, timeouts | Expensive valid OS calls; method-specific limits and cancellation remain important |
| Path escape/overwrite | Canonical and descriptor-relative checks, link/reparse/mount refusal, approved roots, atomic no-replace | Platform primitive unavailable; operation must refuse |
| Memory corruption | Read-only first, revision/digest/expiry, verified snapshot, atomic/transactional write, reopen/integrity check, rollback | External writer races or exotic SQLite formats; fail closed |
| Secret disclosure | No environment/prompt collection; bounded redaction; content-free receipts; safe scanner output | Redaction is heuristic; operators must review exports |
| Excess privilege | Current-user operation, explicit capability context, minimal Tauri permission | User may run elevated; that expands impact and is discouraged |
| Supply-chain compromise | Exact locks, immutable action pins, CodeQL/dependency/secret review, SBOM, source hashes | Maintainer/action/dependency compromise; signing alone does not solve it |

## Abuse cases

- An operator targets another user's or unrelated local process.
- A malicious agent registers broad resource roots or lies about ownership.
- A renderer compromise attempts arbitrary methods, paths, or executable launch.
- A local attacker plants a symlink/junction after preview or swaps a PID/file before execution.
- A crafted memory database exploits parser limits or attempts extension/attached-database behavior.
- A diagnostics/error path exfiltrates a credential or prompt.
- A fork workflow steals secrets or publishes an unreviewed artifact.

Controls reduce these risks but do not create authorization. The operator must own or be explicitly authorized to manage the target. Default workflows never use `pull_request_target`, never expose repository secrets to fork code, and do not publish releases.

## Security invariants

- Unknown or partial evidence never becomes affirmative ownership or success.
- No destructive action executes without a current stored plan ID/digest and current identity/revision.
- No user-supplied executable reaches the broker.
- No resource outside a declared approved root is eligible for cleanup.
- Restore never overwrites an existing destination.
- Provider cost, safety, account, or remote state is never inferred from local edits.
- Secret values are suppressed in scan output, errors, and receipts.

Update this model whenever a change adds a data source, platform primitive, adapter, Tauri capability, network path, updater, plugin, release permission, or external integration.
