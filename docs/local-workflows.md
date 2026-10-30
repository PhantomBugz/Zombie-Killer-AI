# Local workflow guide

The desktop and headless engine operate on the current user's local machine. Browser preview is a separate synthetic demo. Native controls appear only when the engine reports their methods and the selected adapter reports its capabilities.

## Memory repair and restore

1. Pause outside writers and keep an independent backup, especially for JSON/JSONL.
2. Open **Memory Vault**, enter the exact absolute local file path in the registration form, and review the adapter's capabilities.
3. Select a record and a supported scalar field. Review the proposed change, current digest revision, consequences, and warnings.
4. Confirm the exact short-lived plan. The engine creates and verifies a snapshot before committing; a draft preview is not proof of a completed backup.
5. Inspect the durable receipt and refreshed record. If an outcome is uncertain, refresh and reconcile rather than retrying the old mutation.
6. Use the record's **History** tab to review a verified whole-source snapshot restore. Restore is another planned operation and may be unavailable for unsupported SQLite schemas.

JSON/JSONL writers must honor the application's persistent sidecar lock or remain paused. SQLite restore preserves bounded logical state in an existing database transaction, not identical database bytes or physical file-revision metadata. See [Memory Vault](memory-vault.md) for exact limits. Recognized Chroma and supported FAISS headers do not enable vector editing or vector search.

## Temporary resources and Graveyard

Instrumented agents call `track_temp(path, root=approved_root)` after a temporary file or directory's intended contents exist. New declarations retain their exact root, resource type, and creation fingerprint. Legacy incomplete declarations remain inspectable only.

In **Swarm**, inspect the agent's declared artifacts and review one eligible resource. The engine-listed declaration digest binds the selected identity, registration nonce, index, and resource fingerprint; the desktop also sends the selected process identity. Quarantine is independent of process stopping; neither operation silently authorizes the other. Changed declarations, content, identity, or root invalidate the review. In **Activity → Graveyard**, review restore of the exact entry. An existing original destination is preserved. Retention is metadata only; no automatic purge runs.

## Diagnostics and settings

In **Settings**, enter an explicit new absolute destination for local diagnostics, review the export, and confirm. The destination's parent must already exist and pass local ownership/path checks. The export contains a bounded reviewed snapshot with at most 20 public receipts, selected settings, and basic engine checks; it excludes memory contents, executable drafts, command lines, paths, and secrets. It makes no upload and never overwrites a file. Interrupted exports are inspected, not blindly recreated.

Revisioned native settings apply scan visibility, heartbeat grace, retention for new entries, refresh cadence, theme, and motion preferences. Unsupported detection presets and dense mode remain visibly unavailable rather than pretending to change engine behavior.

## Headless commands

All new workflow commands emit JSON, with `--json` accepted explicitly. These examples use placeholders from actual returned results; do not substitute identifiers from a different source or scan.

```powershell
uv run zk vault register C:\path\owned-memory.json
uv run zk vault list
uv run zk vault query <source-id>
uv run zk vault get <source-id> <record-id>
uv run zk vault mutation-plan <source-id> <record-id> --expected-revision <revision> --operation update_content --value-json '"updated local text"'
uv run zk vault mutation-execute <plan-id> <digest> --confirm
uv run zk vault snapshots <source-id>
uv run zk vault restore-plan <source-id> <snapshot-id> --snapshot-digest <snapshot-digest> --expected-revision <current-revision>
uv run zk vault restore-execute <plan-id> <digest> --confirm

uv run zk quarantine resources <agent-id>
uv run zk quarantine plan <agent-id> --resource-index <index> --declaration-digest <listed-declaration-digest>
uv run zk quarantine execute <plan-id> <digest> --confirm
uv run zk quarantine list
uv run zk quarantine restore-plan <entry-id>
uv run zk quarantine restore-execute <plan-id> <digest> --confirm

uv run zk diagnostics plan C:\path\new-diagnostics.json
uv run zk diagnostics execute <plan-id> <digest> --confirm
uv run zk receipt get <receipt-id>
```

`--value-json` accepts one finite JSON scalar within 8192 bytes, not an object, array, SQL statement, or script. `update_field` requires the selected `--field`; `update_metadata` uses `--metadata-key`. Inspect each command's `--help` for its finite payload.

Every execution requires the exact plan ID, digest, and `--confirm`. A successful CLI invocation means a validated receipt was returned, not necessarily that the requested action completed. Check `outcome`, `certainty`, `action_issued`, and `partial_failures`. `verified` with `action_issued=false` can describe an already-completed, idempotently reconciled operation. Preserve recovery evidence for uncertain results.

See [release verification](release-verification.md) for source checks, unsigned builds, clean-machine testing, and signing gates.
