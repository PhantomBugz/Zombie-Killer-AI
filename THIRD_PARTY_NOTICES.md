# Third-Party Notices

Zombie Killer is Apache-2.0 software, but source and built artifacts depend on third-party components under their own licenses. The identifiers below summarize upstream metadata for pinned direct components and are not a complete transitive dependency or license inventory. This document is informational and does not replace the legal files distributed by those projects.

## Python distribution boundaries

The engine and SDK wheels and source distributions ship package-local `LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES.md` files. Those files describe only the archive that contains them. They intentionally omit the desktop artwork and font-license terms because the Python archives do not contain those assets. The engine's direct dependencies are installed as separate distributions; the SDK declares no third-party runtime dependencies.

## Pinned repository components and candidate artifact inputs

An entry in this table does not mean the component is bundled into every release artifact. Package-local notices and the hash-bound build manifest define the actual contents of a particular archive or native build.

| Component | Pinned version | Upstream-declared license |
| --- | --- | --- |
| IBM Plex Sans / IBM Plex Mono font files via Fontsource | 5.3.0 | SIL Open Font License 1.1 |
| React / React DOM | 19.2.8 | MIT |
| `@tauri-apps/api` | 2.11.1 | Apache-2.0 OR MIT |
| Tauri Rust crates | 2.11.5 | Apache-2.0 OR MIT |
| psutil | 7.2.2 | BSD-3-Clause |
| Pydantic | 2.13.4 | MIT |
| Typer | 0.27.1 | MIT |
| PyInstaller build tooling and bundled bootloader | 6.18.0 | GPL-2.0-or-later with the PyInstaller bootloader exception |
| `yaml` (repository policy tooling) | 2.8.1 | ISC |

The full IBM Plex font license is included at [LICENSES/OFL-1.1.txt](LICENSES/OFL-1.1.txt). Apache-2.0 dependencies may use the root [LICENSE](LICENSE) text; their own notices remain controlling. Complete JavaScript, Python, main-native Rust, Unix-harness Rust, and portable-launcher Rust dependency graphs are pinned in `pnpm-lock.yaml`, `uv.lock`, `apps/desktop/src-tauri/Cargo.lock`, `apps/desktop/src-tauri/build_support/unix-test-harness/Cargo.lock`, and `tools/portable-launcher/Cargo.lock`.

Native PyInstaller builds can contain CPython runtime files, OpenSSL libraries, SQLite code, and platform C/C++ runtime files. Platform builds differ. The sidecar builder preserves the exact installed CPython terms, installed license/notice texts from the engine's active runtime dependency graph, and PyInstaller's bootloader exception under `engine/LEGAL/`; the legal manifest records their scope, versions, and hashes and the build manifest binds those files to the artifact. The native verification archive also preserves this repository notice and its referenced asset-license files.

The manifest-bound SBOM records each file and hash but intentionally leaves transitive license conclusions as `NOASSERTION`. Neither it nor the collected runtime dependency graph proves which optional modules were bundled or supplies every platform-library and desktop JavaScript/Rust obligation. Inspect actual binaries and their corresponding legal texts on each release runner; retained metadata and license texts are evidence, not a legal certification.

Publishing a native artifact requires inspecting both lockfile and manifest-bound sidecar inventories and preserving every license/notice applicable to the actual bundled files. This source-only alpha attaches no native binary; CI artifacts are verification evidence, not GitHub Release downloads. A later binary release requires the human artifact review in [release verification](docs/release-verification.md).

## Original project artwork

The Zombie Killer mark and generated application icons are original project artwork, not third-party components. Their attribution and CC BY 4.0 license mapping are in [NOTICE](NOTICE).
