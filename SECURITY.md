# Security Policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| `0.1.0-alpha.1` | Best effort while the alpha is current |
| Older snapshots | No |

This alpha is not a hardened security boundary. It operates with the permissions of the current user; a same-user process can interfere with local state despite defensive permissions and integrity checks.

## Report privately

Once the public repository exists and GitHub private vulnerability reporting is enabled, use its [private vulnerability reporting form](https://github.com/PhantomBugz/Zombie-Killer-AI/security/advisories/new). Include the affected commit/version, platform, prerequisite access, impact, minimal reproduction, and whether a safe test fixture exists. Remove credentials, prompts, personal information, real memory databases, and unrelated process data.

If the repository or private form is unavailable, do **not** open a public vulnerability issue or include exploit details in a conduct report. Wait for this file to publish an enabled private channel. The project does not currently publish an email intake address.

Maintainers will acknowledge an enabled private report when available, validate it in an isolated fixture, coordinate a fix and disclosure, and credit the reporter if requested. No response-time or bounty promise is made.

## Scope priorities

- Wrong-process termination, PID reuse, or process-instance confusion
- Path traversal, symlink/junction/mount escape, overwrite, or unsafe restore
- Memory corruption, backup failure, or revision/digest bypass
- Renderer-to-broker command expansion, engine replacement, protocol confusion, or unsafe child containment
- Credential, prompt, memory-content, filesystem-path, or diagnostics disclosure
- Workflow, dependency, build, or release supply-chain compromise

Reports that depend only on disabling local operating-system protections, controlling the current user's account, or modifying the source before building may still be useful hardening feedback but are not automatically vulnerabilities.

## Safe research

Use only systems and data you own or are explicitly authorized to test. Use synthetic fixtures; do not test provider accounts, third-party agents, or production memory. Stop if testing could terminate an unrelated process, cross an approved root, expose secrets, or consume paid services. See [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md).

## Release trust

Source integrity, checksums, SBOMs, code signing, and macOS notarization answer different questions. Current source builds are unsigned. Follow [release verification](docs/release-verification.md) and treat any future signature claim as valid only when documented for that exact release.
