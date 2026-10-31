# Release Verification

`0.1.0-alpha.1` is a public source alpha. Its GitHub Release contains source archives only; native and portable binaries produced by CI remain verification artifacts, not release downloads. No signed installer or package-registry distribution is claimed. The [project page](https://phantombugz.com/zombie-killer.html) links to the release.

The alpha native qualification targets the hosted `windows-2025` and `ubuntu-24.04` runners. macOS native operation and mutation workflows remain experimental and unqualified: CI checks only scanner unit tests and the browser frontend on `macos-15`, and the native workflow produces no macOS artifact.

## Reproduce checks

Use PowerShell 7+, Node `24.18.0`, pnpm `10.33.2`, Python 3.11-3.13, uv `0.12.3`, and Rust `1.97.1`. Install exact locks, then run:

```powershell
pwsh -NoProfile -File scripts/verify.ps1
```

`pnpm verify` delegates to the same command. On Windows and Linux, the default gate proves `uv.lock` is current before installing both frozen lockfiles; checks documentation, frontend, Python, Rust, native desktop, fixture containment, secrets, and SBOMs; verifies packaged legal files; and requires an unchanged clean worktree. On Windows it also builds the single-file portable executable from this run's native ZIP, runs a full native smoke, and separately checks the portable lifecycle. The Windows-only Job Object/UI Automation native and portable smokes are reported as not applicable on Linux; Linux still runs the Rust, Tauri, sidecar, fixture, and SBOM gates. The orchestrator exits `0` only after a complete clean run on a qualified platform. Generated distributions and SBOMs use an owned temporary directory and are removed after verification. A macOS frontend or scanner-only pass does not qualify the native application.

Run the Windows native and portable UI smokes only in a disposable Windows user profile or an ephemeral runner. The engine resolves some per-user state through `SHGetKnownFolderPath`; redirecting `APPDATA` or `LOCALAPPDATA` environment variables alone does not isolate that state. A local run that withholds either smoke is a scoped check, not a release pass. No current local native or portable smoke pass is claimed here.

Explicit `-SkipDependencyInstall`, `-SkipDocs`, `-SkipWeb`, `-SkipPython`, `-SkipRust`, `-SkipNativeBuild`, `-SkipReleaseFixture`, `-SkipNativeSmoke`, `-SkipPortableExe`, `-SkipSecretScan`, or `-SkipSbom` switches exist for focused development checks. `-AllowDirty` permits an unchanged dirty baseline. Every override prints a `NON-RELEASE` warning and a passing scoped run exits `2`, never `0`. `pnpm verify:web` is the documentation/frontend subset and is not release approval.

## Required end-to-end gates

- Confirm the verified identity-bound `zk action plan` PID/process-instance CLI regression gate remains green.
- Exercise cooperative cancellation on only a uniquely tagged fixture and prove a same-name sibling remains alive.
- Quarantine and restore an exact synthetic file with matching SHA-256.
- Register temporary JSON/JSONL/SQLite sources, execute a reviewed scalar edit, inspect its verified snapshot, and restore it across separate engine invocations.
- Verify diagnostics export is bounded, redacted, explicitly selected, and refuses an existing destination.
- Verify the native desktop loads the real engine, opens no application-controlled listener, and contains the broker child on exit/timeout.
- On Windows, build the single-file portable executable from this run's verified native ZIP; run its `--check` diagnostic and `scripts/portable-smoke.ps1` against that same ZIP. Confirm original ZIP bytes, native readiness, process identity, no TCP listener, independent concurrent launches, and cleanup.
- Inspect browser UI at desktop, 390px, 320 CSS pixels, 200% zoom, keyboard-only, reduced-motion, and forced-color modes with no console errors.
- Verify native capability labels match the default service composition; no disabled mutation may appear enabled.
- Run tracked-tree and Git-history secret scans whose output suppresses matched values.
- Validate every Markdown link, YAML/CFF document, action pin, donation placement, license mapping, and version declaration.

The sidecar-bound SBOM is generated only after this run's native build has produced and verified `BUILD-MANIFEST.json`; stale ignored build output is never accepted as a substitute.

## Python package legal scope

Build both a wheel and source distribution for `zombie-killer-engine` and `zombie-killer-sdk` from the release commit. For each archive, verify that core metadata declares `License-Expression: Apache-2.0` and lists `LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES.md` as `License-File` entries. Confirm those exact files exist in the wheel's `.dist-info/licenses/` directory and at the source-distribution root, and compare their bytes with the corresponding package-local source files.

The package-local notices are deliberately narrower than the repository notice. The Python archives do not ship desktop artwork, generated icons, or bundled fonts, so their notices must not import the repository's asset-license paths or terms. Direct dependency summaries are informational upstream declarations, not a complete transitive license conclusion; review the resolved environment separately before publishing or redistributing it.

## Source integrity, SBOM, and provenance

The verification-only release workflow creates a source archive and lockfile SBOMs, hashes them, and uploads them only to that workflow run. The Windows/Linux native workflow separately builds the fixed sidecar and records every manifest entry in SPDX and CycloneDX evidence. Neither workflow publishes a GitHub release. A SHA-256 checksum proves byte identity only after the expected checksum is obtained through a trusted channel. An SBOM describes components but does not prove they are benign or that a binary came from this source. Build provenance describes a process but is not native code signing.

For Windows and Linux, the native workflow uploads a checksummed `unsigned-native-<platform>-<architecture>.tar.gz`, preserving the full engine inventory, including hidden files, symbolic links, and executable permissions. It also preserves root `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `TRADEMARKS.md`, and every file under `LICENSES/`, including bundled font and artwork terms. Windows additionally receives a checksummed ZIP with identical file contents for Explorer's **Extract All**, plus a root **Start Zombie Killer.cmd** launcher. Extract the whole archive before opening the launcher; it starts the native app, not a browser demo. Alternatively, launch `target/release/zombie-killer.exe` on Windows or `target/release/zombie-killer` on Linux. Keep that directory layout, its `.cargo-lock` marker, and the adjacent `engine/` tree intact: the pinned [Tauri resource resolver](https://github.com/tauri-apps/tauri/blob/tauri-v2.11.5/crates/tauri-utils/src/platform.rs) recognizes the Cargo output layout on Linux; relocating just the executable changes resource lookup. These archives need the same platform system prerequisites as source builds and are unsigned verification builds, not installers. The Windows native job runs the Job Object/UI Automation smoke against the extracted ZIP before upload; Linux archive layout and permissions are covered by the Python matrix, while native UI smoke remains Windows-only. No macOS native archive is produced by this alpha workflow.

The Windows single-file `Zombie Killer.exe` is a separate unsigned artifact built from that exact verified ZIP. Its staged `--check` verifies extraction and cleanup before the executable is placed in the artifact directory. The Windows portable smoke then compares extracted files with the ZIP and exercises native readiness, sequential and concurrent launches, process isolation, listener absence, and cleanup. The wrapper, ZIP, checksum files, and smoke report must be reviewed together; neither a browser demo nor a successful `--check` alone proves the native workflow. Reproduction commands and runtime limitations are in the [portable Windows guide](portable-windows.md).

The native sidecar build collects exact installed runtime license/notice texts into `engine/LEGAL/` before its hash-bound manifest is sealed. Its legal manifest covers the engine's active runtime dependency graph, the PyInstaller bootloader terms, and installed CPython terms; it excludes unrelated development tools. Inspect the manifest and preserved texts alongside the actual assembled binaries. A dependency graph is not proof of which optional modules were bundled, and does not settle platform-library or desktop JavaScript/Rust obligations. Missing collected runtime or interpreter terms fail the build; residual platform-specific review remains a human publication gate.

Repository tests require deterministic bytes for identical inputs, SPDX 2.3/CycloneDX 1.6 structural contracts, unique references, and exact package-set coverage of `pnpm-lock.yaml`, `uv.lock`, the main-native `apps/desktop/src-tauri/Cargo.lock`, the standalone Unix-harness `apps/desktop/src-tauri/build_support/unix-test-harness/Cargo.lock`, and the portable-launcher `tools/portable-launcher/Cargo.lock`. When a sidecar manifest is explicitly supplied, they also require a one-for-one hash-bound file/link inventory. Generated dependency license fields remain `NOASSERTION`: confirm packaged Python, portable-launcher, and platform-runtime licenses/notices independently and reject unexplained components. Rebuild from a clean clone/tag, not a dirty working tree.

## Human signing gates

Windows Authenticode requires a maintainer-controlled code-signing certificate and protected signing process. Any future macOS distribution would first require native qualification, then an Apple Developer ID certificate, hardened runtime/entitlements review, signing, notarization, and stapling. Those credentials must never be available to fork pull requests or committed to the repository.

Signing identifies the signer and protects artifact integrity after signing; it does not replace tests, SBOM review, malware analysis, or source review. The workflow stays verification-only until maintainers document certificate custody, approval, recovery/revocation, and exact verification commands.

## Publish checklist

1. Confirm release commit, clean tree, version, changelog date, and citation date.
2. Pass all automated and end-to-end gates on supported platforms, including the Windows single-file portable build and smoke if that EXE is offered.
3. Review dependencies, licenses, SBOMs, secret scan, CodeQL, and dependency review.
4. Confirm the intended public repository and private security-reporting form are live before linking to them.
5. Publish source-only release notes that state known capability gaps and tested platforms.
6. Before attaching native binaries in a later release, rebuild from the tag with protected release permissions; review the exact artifacts, legal texts, SBOMs, and hashes; and verify portable runtime behavior on a clean machine.
7. Sign/notarize only through the documented human gate if distributing installers, then verify any claimed signatures.

No donation, urgency, or version label can waive these gates.
