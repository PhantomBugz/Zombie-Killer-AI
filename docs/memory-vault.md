# Memory Vault

Memory Vault is a constrained editor for supported **local, user-controlled** stores. It is not a provider memory console and cannot alter external safety flags, account status, billing, rate limits, or guarantee that an agent resumes.

## Supported adapters

| Format | Inventory/search | Mutation and restore | Native UI |
| --- | --- | --- | --- |
| JSON object/list | Yes | Backup-first atomic replacement for supported record shapes | Registration, scalar repair, snapshots, restore |
| JSONL objects | Yes | Backup-first complete-file replacement with line/object validation | Registration, scalar repair, snapshots, restore |
| SQLite tables | Yes | Constrained scalar updates for tables with exactly one declared primary key; restore requires an unchanged supported ordinary schema | Registration, scalar repair, capability-gated restore |
| Recognized Chroma SQLite | Inventory only | No; intentionally read-only | Read-only/unsupported details |
| Common little-endian 64-bit FAISS IP/L2 flat-index headers | Bounded header inventory only, not vector search or full index validation | No | Inventory-only details |

There is no arbitrary SQL editor, extension loading, script execution, or binary vector mutation. Virtual tables, ambiguous/no primary keys, attached databases, unsupported runtime value types, and unrecognized schemas fail closed.

## Read path

Sources must be selected and registered through an explicit capability path. The adapter opens read-only for inventory/query, applies file and row/cell bounds, limits JSON nesting, uses allowlisted schema identifiers, and parameterizes values. Stable record IDs and a source revision bind later operations.

Use the **Memory Vault** source-registration form to enter the exact local file path. The engine probes the file, reports its capabilities, and persists registration. A filename extension does not establish a supported format. Browser demo sources remain synthetic and do not open local files.

## Mutation path

1. Retrieve the record and current source/record revision.
2. Draft a change to one supported scalar field. There is no arbitrary SQL or whole-document script editor.
3. Preview a field-level diff and local-only warning.
4. Create a short-lived immutable plan containing operation, record, expected revisions, and digest.
5. Create and verify a snapshot before mutation.
6. Revalidate the source at the write boundary.
7. Write to a complete temporary replacement (JSON/JSONL) or run a constrained SQLite transaction.
8. Reopen/parse or run `PRAGMA integrity_check`, verify the result, and record a content-free receipt.

SQLite backups use the SQLite backup API. JSON replacements are flushed, synchronized, atomically replaced, and reopened. A detected source revision or file identity change causes a conflict rather than merging silently. Audit records store IDs, hashes, operation metadata, and bounded redacted errors—not raw memory values. The private executable draft is retained in restricted local state for execution across separate engine invocations; it is not included in public receipts or diagnostics.

Restore is also a planned mutation. It validates snapshot size/hash, current source revision, adapter/format, and destination identity, creates rollback material, restores, and verifies integrity. SQLite restore updates the existing database in a transaction rather than replacing its inode behind open connections. Unsupported schemas disable restore. A post-commit verification failure preserves the source and recovery evidence rather than overwriting a possibly newer external version.

## Concurrent writers and platform limits

Pause external writers before editing or restoring JSON/JSONL. The application holds its persistent sidecar lock and rechecks revision and identity immediately before replacement, but an OS rename is not compare-and-swap against arbitrary writers that ignore that lock. Use only cooperating writers or a quiescent source; this limit applies on Windows and POSIX.

SQLite transactions exclude ordinary SQLite connection writers during the write transaction, including supported DELETE and WAL modes. This does not authorize out-of-band file replacement or promise coordination with arbitrary filesystem writers. The UI exposes only the capabilities reported by the current adapter. Windows working-tree checks do not establish clean-machine or macOS/Linux release approval; see [release verification](release-verification.md).

## Backups and retention

Backups live below the per-user data directory, not beside the source. Snapshot metadata uses a 30-day retention date, but no automatic purge runs in this alpha. Keep independent backups: application snapshots do not replace database-native backups, version control, or tested disaster recovery.

Never “fix” a provider error by changing a local string to “resolved” unless the string is purely local application state and the operator understands the consumer. Local edits do not override an external fact.
