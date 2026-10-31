# Changelog

All notable changes to this project are documented in this file. The format follows [Keep a Changelog 2.0.0](https://keepachangelog.com/en/2.0.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Target source version: `[0.1.0-alpha.1]`. This section remains unreleased until a maintainer creates and verifies the corresponding tag.

### Added

- Evidence-based local process scanning with explicit coverage and unmanaged states.
- Short-lived, immutable, process-instance-bound stop plans, including explicit scan-derived PID/process-instance CLI planning and execution.
- Reviewed SDK-declared resource quarantine and exact Graveyard restore through the default service, desktop, and finite CLI, with legacy restore-only recovery.
- Explicit local source registration, backup-first JSON/JSONL and constrained SQLite scalar repair, snapshot history, and planned restore across separate engine invocations.
- Bounded, inventory-only recognition of common little-endian 64-bit FAISS IP/L2 flat-index headers; recognized Chroma SQLite remains read-only.
- Durable mixed-operation receipts and reviewed local diagnostics export without overwriting existing files or exporting private memory drafts.
- Versioned, bounded local JSON protocol, headless CLI, and Python lifecycle SDK.
- Tauri/React Containment Console, deterministic browser demo, activity receipts, settings, and command palette.
- One-command synthetic browser demo (`pnpm demo`) that installs lockfile-pinned JavaScript dependencies and binds Vite to localhost without starting the native engine.
- Narrow Rust broker that launches only the verified local engine resource over standard I/O.
- Open-source governance, security, privacy, documentation, and verification workflows.
- Layout-preserving unsigned native archives with hidden engine inventory entries, source legal material, and manifest-bound Python runtime attribution.
- A single-file unsigned Windows x64 portable wrapper built from the verified native ZIP, with an extraction diagnostic and native smoke coverage. The executable is not a signed installer or public download yet.
- This alpha source tree does not certify a signed installer, package publication, or clean-machine/platform release approval; those are separate release decisions.

### Fixed

- Stale Swarm results on route remount and incomplete coverage labeling when eligible scan results are truncated.
- Detail lookup for agents beyond the scan-list projection limit.
- SDK asynchronous startup cancellation leaking a background lease.
- Memory writer/restore races, snapshot-integrity gaps, and rollback paths that could replace a later external version; JSON still requires cooperating or quiescent writers.
- Windows Graveyard destination namespace rebinding and restore errors that incorrectly reported failure before an already-issued move.
- Native broker mutation interruptions now preserve uncertain outcomes rather than implying no action occurred.

### Security

- Redaction at collection, protocol, diagnostics, and export boundaries.
- PID-reuse defense, path revalidation, digest/expiry checks, and restore-without-overwrite behavior.

[Unreleased]: https://github.com/PhantomBugz/Zombie-Killer-AI/commits/main
[0.1.0-alpha.1]: https://github.com/PhantomBugz/Zombie-Killer-AI/releases/tag/v0.1.0-alpha.1
