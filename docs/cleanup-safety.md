# Cleanup and Process Safety

Zombie Killer treats every mutation as a capability that expires, not as a button mapped directly to `kill` or `delete`.

## Process stop sequence

1. Scan and select a managed, actionable process instance.
2. Preview a mode (`request`, `terminate`, or `force`) bound to PID, boot identity, creation time, executable/process-instance ID, reviewed descendants, and consequences.
3. Persist the immutable plan with a digest and 30-second expiry.
4. Confirm by plan ID and digest; there is no `force=true` shortcut.
5. Re-fetch and compare the target immediately before every cancellation request or signal.
6. Protect the Zombie Killer process, its parent, system identities, and unrelated same-name siblings.
7. Verify the selected process instance ended and write a receipt. Report partial or uncertain results honestly.

Cooperative SDK cancellation is preferred. Terminate and force modes are deliberately separate. A stopped process may leave application-level work incomplete; the receipt cannot prove a remote provider request stopped or that a service supervisor will not restart it.

CLI action planning requires both `--pid` and `--process-instance-id` from the same reviewed scan. The service compares both fields before creating a plan and revalidates the stored process identity before execution; a restart or PID reuse returns `target_changed` instead of acting on the replacement.

## Ports

The engine may observe ports as context. It does not “close a port” directly. A port belongs to a process/socket; stop the authorized owner and then verify the listener released. Supervisors, sibling processes, or another instance may immediately bind the same number.

## Graveyard quarantine

The cleanup workflow accepts only resources explicitly represented in a reviewed cleanup manifest beneath an approved root. Before moving a file, the engine:

- canonicalizes root and target and rejects the root itself, traversal, siblings, network/device paths, Windows alternate streams, symlinks, junctions, reparse points, and cross-mount ambiguity;
- limits entry count, aggregate bytes, depth, and pinned file descriptors;
- fingerprints the resource at preview and revalidates path components and identity at the mutation boundary;
- uses descriptor-relative/platform-safe operations and refuses when the required primitive is unavailable;
- moves with atomic no-replace semantics into the per-user Graveyard;
- verifies size/hash/identity and journals the entry and receipt.

Restore is bound to the exact entry digest and original destination. It refuses overwrite, changed quarantine content, changed destination authority, expired plan, and ambiguous interrupted state. The engine does not recursively follow links.

Quarantine plans last exactly 30 seconds. The default retained-until metadata is 30 days; the revisioned retention setting applies to newly quarantined entries. This alpha does not purge automatically. `partial` and `interrupted` entries are not advertised as restorable success.

New SDK declarations retain the approved root, resource type, and creation fingerprint alongside the exact registration identity and nonce. The native agent inspector lists declared resources with an opaque digest binding that exact declaration to its index, identity, and nonce; planning revalidates both that digest and the selected process identity. Review and confirm quarantine independently of a process-stop operation. The renderer cannot substitute a cleanup path. A changed resource, declaration, registration, root, or process identity invalidates cleanup authority. Call `track_temp` only after the temporary resource's intended contents exist; later changes require a new declaration.

Legacy path-only declarations remain inspectable but are not granted invented cleanup authority. **Activity → Graveyard** provides an exact-entry restore preview and receipt. Preserved cleanup authority supports restore after the creating agent has exited; an existing original destination is never overwritten.

## What “Kill & Clean” cannot promise

- It cannot identify ownership from a process name or keyword alone.
- It cannot cancel a provider-side request after the local client is gone.
- It cannot guarantee an external supervisor will not restart a workload.
- It cannot repair arbitrary half-written application data.
- It does not delete source code, provider configuration, credentials, memory databases, or unregistered siblings.
- It cannot make a defunct POSIX process exit again; its parent must reap it.

Test important workflows only with synthetic fixtures until the exact platform path and process behavior has passed [release verification](release-verification.md).
