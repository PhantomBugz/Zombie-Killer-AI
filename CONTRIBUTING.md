# Contributing

Thank you for improving Zombie Killer. Contributions must preserve the project's local-first, evidence-based, preview-before-mutation model.

## Before starting

1. Search existing issues. Use the bug, feature, or detection report form as appropriate.
2. For a security vulnerability, follow [SECURITY.md](SECURITY.md); do not open a public issue.
3. Keep a change focused. Large architecture changes should start with an issue and a threat-boundary proposal.
4. Never commit real credentials, prompts, memory stores, crash dumps, databases, signing keys, or user process listings.

## Development setup

Install PowerShell 7 or newer (`pwsh`). Use the pinned versions in `.node-version`, `package.json`, and `rust-toolchain.toml`. Then run:

```powershell
corepack enable
corepack prepare pnpm@10.33.2 --activate
python -m pip install uv==0.12.3
uv sync --frozen
pnpm install --frozen-lockfile
pnpm verify
```

Native contributors also need the [Tauri system prerequisites](https://v2.tauri.app/start/prerequisites/). Platform-specific tests may skip only when the prerequisite primitive is genuinely unavailable and the skip states why.

## Change standards

- Add a failing test first, then the smallest implementation, then refactor.
- Treat PID + creation time + executable/process-instance binding as one identity.
- Keep destructive operations behind immutable, expiring previews and revalidation.
- Prefer quarantine and verified restore over deletion.
- Redact at collection boundaries; errors and tests must not echo secret fixtures.
- Show unknown and partial states honestly. Do not convert missing evidence to zero or success.
- Do not add outbound network behavior, telemetry, provider integrations, or generic shell access without an accepted design and threat-model update.
- Update public documentation and `CHANGELOG.md` when behavior changes.

Run the affected package tests and the complete repository gate before requesting review:

```powershell
pnpm verify
uv run pytest services/engine/tests packages/sdk-python/tests -q
cargo test --locked --manifest-path apps/desktop/src-tauri/Cargo.toml
pnpm secret:scan
```

## Developer Certificate of Origin

Zombie Killer uses the [Developer Certificate of Origin 1.1](DCO). It is not a copyright assignment. Sign every commit with:

```text
Signed-off-by: Your Name <address-you-control>
```

Git can add the line using `git commit -s`. By signing, you certify the statements in the unmodified `DCO` file. A maintainer may ask you to amend unsigned commits.

## Pull requests

- Complete the pull-request template and link the issue.
- Explain user-visible behavior, trust-boundary changes, tests, and platform limits.
- Include no generated build output, local state, or screenshots containing private data.
- Expect review against [Responsible Use](RESPONSIBLE_USE.md), [Privacy](PRIVACY.md), and the [threat model](docs/threat-model.md).

Contributions are licensed under Apache-2.0 unless a file is explicitly mapped to another license in [NOTICE](NOTICE). Brand artwork changes require maintainer approval because trademark rights are separate from copyright licensing.
