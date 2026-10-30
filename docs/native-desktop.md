# Native desktop boundary

This alpha qualifies native source and verification artifacts on Windows and Ubuntu Linux. macOS native builds and mutation workflows remain experimental and unqualified; macOS CI covers only scanner unit tests and the browser frontend.

Zombie Killer exposes one Tauri command to its main window: `engine_request`. The renderer can submit only the finite, typed request variants compiled into the Rust broker. It cannot select an executable, command-line argument, working directory, environment variable, or protocol request ID. Local source registration and diagnostics export accept an explicitly selected path through their specific bounded methods; they do not expose a general filesystem or shell interface. Cleanup uses the selected agent's registered resource ID, not a renderer-supplied cleanup path.

The broker owns the remaining authority:

- Debug builds resolve the repository's fixed `.venv` interpreter and invoke `python -I -m zombie_killer_engine protocol-once` from the repository root.
- Release builds resolve only `engine/zombie-killer-engine[.exe]` inside Tauri's application resource directory.
- Both launch modes clear the inherited environment and restore only a small platform/runtime allowlist. POSIX launches also add the broker PID for an independent identity watcher; Windows relies on the assigned Job Object because interpreter launchers can mediate the reported parent PID.
- A native transport failure is surfaced as an error. It never falls back to Demo lab data.

Every call receives a broker-generated UUID and runs through the same serialized request path. Renderer input is limited to 128 KiB, the encoded engine request to 1 MiB, engine stdout to 4 MiB, and engine stderr to 64 KiB. Engine invocations have method-specific deadlines of 10 to 45 seconds. On a timeout, stream-limit violation, or transport failure, the broker attempts to kill and reap the child. It also validates the response version, method, request ID, shape, and method-specific result before returning data to the renderer.

## Sidecar build and release gate

From the repository root:

```text
uv run --frozen python -I scripts/build-engine-sidecar.py
```

The pinned builder requires isolated Python, invokes PyInstaller 6.18.0 through `python -I`, and produces an `onedir` sidecar rather than a self-extracting `onefile` executable. It builds outside the live resource directory under a kernel-backed exclusive lock that is released automatically if its owner crashes. Cleanup is limited to exact generated paths, rejects unsafe ancestors and special final entries, and uses no-follow directory traversal. Inventory uses no-follow descriptors or handles, rejects encountered junctions and unsupported reparse points, preserves only bounded relative symbolic links, and binds each regular file's size and hash to the same opened identity.

The builder excludes `pydantic.mypy`, `pydantic.v1.mypy`, and `mypy` from collection. Pydantic's collection hook otherwise includes its optional type-checker plugins and pulls the development environment's mypy compiler and native dependencies into the sidecar. The Pydantic runtime and the engine's other runtime dependencies remain included; runtime legal collection is unchanged.

Before sealing the sidecar inventory, the isolated legal collector preserves installed license/notice texts for the engine's marker-filtered runtime dependency graph, the PyInstaller bootloader exception, and the exact installed CPython interpreter. `engine/LEGAL/MANIFEST.json` records their versions, scope, sizes, and SHA-256 hashes; those files are also included in `BUILD-MANIFEST.json`. Development-only dependency extras are not treated as runtime dependencies. This is attribution evidence, not a complete license approval: optional modules actually collected by PyInstaller, platform libraries, and the desktop's JavaScript/Rust components still require artifact-specific review.

Before publication, the staged executable serves a real local-only `system.info` request with `--internal-state-root` fixed to a fresh temporary directory. The smoke database and all other smoke state are removed afterward; current-user application paths are never selected. After writing the manifest, the builder recursively flushes every candidate regular file, including `BUILD-MANIFEST.json`, and then flushes candidate directories from the leaves up to the candidate root. A sealing failure occurs before the publication journal or last-known-good directory is touched. Publication then uses a durably replaced phase journal. A pre-commit interruption restores the prior `resources/engine`, while a recorded commit finishes cleanup on the next run. Rename or rollback failures preserve the last-known-good directory and journal for recovery instead of deleting them.

Tauri's `beforeBuildCommand` always runs `pnpm native:prepare`, which first builds the web assets and then runs the frozen sidecar builder. The Rust release build script independently parses the bounded manifest, validates target metadata and safe relative paths, verifies the complete file/symlink inventory and file hashes, and refuses to continue unless the fixed executable is present in that inventory. It compiles the verified manifest digest into the release broker as a trust anchor. Before each release sidecar launch, the broker requires the packaged manifest to match that compiled digest and reruns the bounded inventory and hash checks. Generated sidecar resources remain ignored by Git; source, lockfiles, and the builder are committed.

On Unix, a successful pre-launch check copies every signed regular file from its already-opened,
no-follow source handle into a path-preserving private execution tree beneath an effective-user-owned
`0700` runtime parent. The broker rechecks the copied sizes, hashes, and exact inventory, then
recreates only signed relative links whose lexically resolved targets remain in that inventory. It
launches the real executable path inside that tree so PyInstaller onedir discovery continues to find
the copied `_internal` directory. A close-on-exec owner lock remains held by the broker through child
execution; normal teardown removes the tree, and the next materialization removes only exact stale
tree/lock pairs whose exclusive owner lock is no longer held. This protects launch from changes to
the installed source tree after verification and recovers snapshots left by broker crashes or
reboots. It is not an isolation boundary against arbitrary hostile code already running under the
same effective user.

These gates pin the inputs and resource layout and verify artifacts at defined build and pre-launch checkpoints. They do not assert bit-for-bit reproducible PyInstaller output across operating systems or toolchains, or general containment of hostile reparse-point races.

## Broker-loss containment

The broker uses platform-specific containment in addition to the engine's parent-identity watcher:

- On Windows, each child is created suspended, assigned to a preconfigured private Job Object with `KILL_ON_JOB_CLOSE`, and resumed only after assignment succeeds. If creation, configuration, assignment, or resume fails, the broker rejects the invocation and terminates the child.
- On POSIX systems, the child starts in a private process group and inherits one fixed broker-owned liveness descriptor. Closing that descriptor causes the engine watcher to terminate its process group; dropping the Rust containment object also sends `SIGKILL` to that group.
- On POSIX, the engine also validates that the supplied broker PID is its direct parent, records that process's creation time, and exits if the identity disappears or the PID is reused. This is a fallback for parent loss, not a substitute for the liveness channel. Windows uses the Job Object directly instead of trusting parent PID reporting through an interpreter launcher.

These mechanisms cover children that remain in the assigned Job Object or private process group. They are not a claim that Zombie Killer can contain a process that deliberately escapes the operating-system containment primitive.

## v0.1 capability boundary

The local workflow composition covers scan and agent detail, activity and receipt lookup, explicit Vault source registration, supported Vault queries and scalar edits, snapshot history and restore, declared-resource quarantine and Graveyard restore, selected-path diagnostics export, and revisioned settings. The desktop enables a workflow only when `doctor` reports its required plan, execution, and supporting methods available. An invocation or schema error leaves the affected capability disabled and permits a later probe. Unsupported operations are reported instead of simulated with Demo data.

Memory workflows preserve engine revision digests. A plan does not represent an already-verified backup; the adapter must create and verify the backup before a mutation is issued. Plans, executable authority, snapshots, and receipts persist across the broker's one-shot engine invocations. Cleanup authority requires the exact registration nonce, creating process identity, approved root, and resource fingerprint. Legacy path-only resource declarations remain inspectable without being upgraded into cleanup authorization.

At engine startup, a supported platform must also pass a non-signaling bind, identity validation, and close against the already-read engine process identity before action methods are installed. This catches Linux kernels that expose a Python `pidfd_open` wrapper but reject the runtime syscall. This alpha supports process actions through stable Windows process handles and through Linux only when both `pidfd_open` and `pidfd_send_signal` are available and that runtime probe succeeds. Linux hosts without working pidfd support remain read-only for process actions. macOS native behavior is unqualified; its current engine code declines process actions. The Swarm and Settings views label unavailable capabilities and do not expose their review or execute controls.

Native action and activity receipts preserve the protocol's bounded, redacted `partial_failures`. Any nonempty list is shown as a partial outcome even when action issuance itself is verified; it is never presented as completed success.

The following remain outside the supported native capability boundary:

- process actions on Linux hosts without working support for both required pidfd primitives, and all macOS native workflows in this alpha;
- generic writable Chroma or FAISS adapters; recognized Chroma SQLite remains read-only and common FAISS flat-index headers provide bounded inventory only, not vector validation;
- arbitrary SQL, shell commands, filesystem browsing, and remote fleet control; and
- unattended process termination, automatic updates, and signed/notarized installer distribution.

Settings updates include an expected-revision check against the authoritative revision persisted with the settings in SQLite. The service performs the read, comparison, writes, and revision increment in one `BEGIN IMMEDIATE` transaction, so compare-and-swap applies across desktop and CLI service instances that share the state database; it is not broker-local. Demo lab retains only its clearly labeled deterministic, reversible examples.
