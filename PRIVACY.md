# Privacy

Zombie Killer is local-first. The core application has no telemetry, account system, cloud service, provider integration, updater, or listening network socket. The renderer communicates with a fixed local engine process over bounded standard input/output through the Tauri broker.

## Data processed locally

- Low-cost current-user process metadata: PID, creation time, executable identity, parent relationship, status, and bounded/redacted command-line evidence where the OS permits it
- SDK lifecycle leases: project/role/provider labels, process identity, heartbeat, declared temporary resources, cooperative cancellation state, and optional measured counters
- User-registered JSON, JSONL, or SQLite memory sources when inspected
- Plans, hashes, revisions, receipts, settings, warnings, and redacted diagnostics

The engine does not read process environments. The SDK does not collect prompts, responses, credentials, or arbitrary exception text. Memory content is read only after a user registers a supported local source; mutation requires a separate preview and execution path.

## Local storage

| Platform | Data and Graveyard | State and audit database | Runtime leases |
| --- | --- | --- | --- |
| Windows | `%LOCALAPPDATA%\Zombie Killer\Zombie Killer` | same directory | `%LOCALAPPDATA%\Temp\Zombie Killer\Zombie Killer` |
| macOS | `~/Library/Application Support/Zombie Killer` | same directory | `~/Library/Application Support/Zombie Killer/runtime` |
| Linux | `~/.local/share/Zombie Killer` | `~/.local/state/Zombie Killer` | private `/run/user/<uid>/Zombie Killer` when verified, otherwise `~/.local/state/Zombie Killer/runtime` |

The macOS path describes experimental source behavior; this alpha does not qualify a macOS native release or mutation workflow.

The application derives locations from OS identity APIs rather than environment variables. It attempts current-user-only permissions and reports preparation failures. Backups are below the data directory; quarantined resources are below `graveyard`; leases and cancellation requests are below the runtime directory. The SQLite audit store is below the state directory.

## Retention and deletion

The default quarantine retention metadata is 30 days, but this alpha does **not** automatically purge files. A retention date is not proof that deletion occurred. Backups and receipts persist until the user removes them or a documented future purge succeeds. Terminal leases may be removed after their bounded lifecycle. Browser demo state exists only in that page session.

To remove local data, close Zombie Killer and its instrumented agents, make any needed independent backup, and delete the platform directories above using your operating system. Deleting the Graveyard or backups makes recovery impossible. Unregistering a memory source does not delete the source itself. The project cannot delete copies created by backups, version control, operating-system snapshots, or third-party tools.

## Network and third parties

Core runtime behavior makes no provider or telemetry calls. Package installation, source control, operating-system WebView components, GitHub Actions, and optional links in documentation are separate tools with their own network and privacy behavior. The Python SDK records usage supplied by the application; it does not contact providers or infer pricing.

## Diagnostics and reports

Review every export before sharing it. Redaction reduces risk but is not a proof that arbitrary user content is safe. Public issues must use synthetic examples and exclude secrets, prompts, memory contents, personal data, raw command lines, and private paths.
