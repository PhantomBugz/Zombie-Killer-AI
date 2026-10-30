# Responsible Use

This document is safety guidance, not an additional software-license restriction. The Apache-2.0 license in [LICENSE](LICENSE) controls use of the code.

Zombie Killer can stop processes and move or edit local files. Use it only on systems, processes, and data you own or are explicitly authorized to administer.

## Expected use

- Investigate your own abandoned or stalled agent workloads.
- Ask an SDK-instrumented process to cancel cooperatively.
- Review and stop an exact local process instance after validating the preview.
- Quarantine only resources an authorized agent declared beneath an approved root.
- Inspect and repair a supported local memory store after a verified backup.
- Test detection and recovery using the synthetic Zombie Lab fixtures.

## Unsafe use

- Stopping or modifying another person's workload without authorization
- Treating a heuristic, process name, or keyword as proof of ownership
- Editing provider-controlled safety, account, billing, or rate-limit systems
- Using Memory Vault to misrepresent an external service state or bypass safeguards
- Registering broad roots, credential folders, source repositories, or unrelated databases for cleanup
- Sharing diagnostics that contain secrets, prompts, personal data, or third-party process information

## Operator checklist

1. Confirm scope and ownership.
2. Read coverage warnings and evidence grades.
3. Prefer cooperative cancellation.
4. Confirm PID, creation time, executable/process-instance binding, affected children, and resource list.
5. Keep an independent backup before memory or file operations.
6. Use quarantine, not deletion; verify receipts and restore paths.
7. Stop on `target_changed`, `partial`, `interrupted`, or `uncertain` and investigate rather than retrying blindly.

No receipt makes an unauthorized action acceptable. If you discover a safety defect, follow [SECURITY.md](SECURITY.md).
