use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;

use serde_json::json;
use sha2::{Digest, Sha256};

#[cfg(unix)]
use crate::resource_manifest::recover_stale_runtime_snapshots;
#[cfg(windows)]
use crate::resource_manifest::{insert_actual_windows_path, normalized_symlink_target_index};
use crate::resource_manifest::{
    validate_symbolic_link_graph, verify_bundle, verify_runtime_bundle,
};

#[test]
fn symbolic_link_graph_accepts_a_multihop_chain() {
    let links = HashMap::from([
        ("entry".to_owned(), "hop".to_owned()),
        ("hop".to_owned(), "payload".to_owned()),
    ]);
    let known = HashSet::from(["entry".to_owned(), "hop".to_owned(), "payload".to_owned()]);

    assert!(validate_symbolic_link_graph(&links, &known, &HashSet::new()).is_ok());
}

#[test]
fn symbolic_link_graph_rejects_cycles_and_missing_terminal_targets() {
    let cycle = HashMap::from([
        ("entry".to_owned(), "hop".to_owned()),
        ("hop".to_owned(), "entry".to_owned()),
    ]);
    let missing = HashMap::from([("entry".to_owned(), "missing".to_owned())]);
    let known = HashSet::from(["entry".to_owned(), "hop".to_owned()]);

    assert!(validate_symbolic_link_graph(&cycle, &known, &HashSet::new()).is_err());
    assert!(validate_symbolic_link_graph(&missing, &known, &HashSet::new()).is_err());
}

#[cfg(windows)]
#[test]
fn symbolic_link_graph_rejects_windows_normalized_path_collisions() {
    let links = HashMap::from([
        (PathBuf::from("Payload"), PathBuf::from("one")),
        (PathBuf::from("payload"), PathBuf::from("two")),
    ]);

    assert!(normalized_symlink_target_index(&links).is_err());
}

#[cfg(windows)]
#[test]
fn actual_windows_inventory_rejects_every_normalized_path_collision() {
    for (first_is_directory, second_is_directory) in
        [(false, false), (true, true), (false, true), (true, false)]
    {
        let mut entries = HashSet::new();
        let mut directories = HashSet::new();
        insert_actual_windows_path(
            &mut entries,
            &mut directories,
            Path::new("Payload"),
            first_is_directory,
        )
        .unwrap();

        assert!(
            insert_actual_windows_path(
                &mut entries,
                &mut directories,
                Path::new("payload"),
                second_is_directory,
            )
            .is_err()
        );
    }
}

fn write_executable(path: &Path, contents: &[u8]) {
    fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn platform() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        value => value,
    }
}

fn manifest(root: &Path, executable: &str) {
    let bytes = fs::read(root.join(executable)).unwrap();
    let value = json!({
        "architecture": std::env::consts::ARCH,
        "entries": [
            {
                "path": executable,
                "sha256": format!("{:x}", Sha256::digest(&bytes)),
                "size": bytes.len(),
                "type": "file"
            }
        ],
        "format": "pyinstaller-onedir",
        "platform": platform(),
        "pyinstaller": "6.18.0",
        "python": "3.12.10",
        "source_date_epoch": "1700000000"
    });
    fs::write(
        root.join("BUILD-MANIFEST.json"),
        serde_json::to_vec_pretty(&value).unwrap(),
    )
    .unwrap();
}

#[cfg(unix)]
fn extend_manifest(root: &Path, entries: impl IntoIterator<Item = serde_json::Value>) -> String {
    let manifest_path = root.join("BUILD-MANIFEST.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    value["entries"].as_array_mut().unwrap().extend(entries);
    let bytes = serde_json::to_vec_pretty(&value).unwrap();
    fs::write(&manifest_path, &bytes).unwrap();
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(unix)]
#[test]
fn release_resource_manifest_accepts_a_verified_multihop_symlink_chain() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let executable = "zombie-killer-engine";
    write_executable(&directory.path().join(executable), b"trusted sidecar");
    fs::write(directory.path().join("payload"), b"payload").unwrap();
    symlink("payload", directory.path().join("hop")).unwrap();
    symlink("hop", directory.path().join("entry")).unwrap();
    manifest(directory.path(), executable);
    let trusted_manifest = extend_manifest(
        directory.path(),
        [
            json!({
                "path": "payload",
                "sha256": format!("{:x}", Sha256::digest(b"payload")),
                "size": b"payload".len(),
                "type": "file"
            }),
            json!({"path": "hop", "target": "payload", "type": "symlink"}),
            json!({"path": "entry", "target": "hop", "type": "symlink"}),
        ],
    );

    assert!(
        verify_bundle(
            directory.path(),
            platform(),
            std::env::consts::ARCH,
            executable
        )
        .is_ok()
    );
    assert!(!trusted_manifest.is_empty());
}

#[cfg(unix)]
#[test]
fn release_resource_manifest_accepts_a_safe_lexical_pullback_after_link_expansion() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let executable = "zombie-killer-engine";
    write_executable(&directory.path().join(executable), b"trusted sidecar");
    fs::create_dir_all(directory.path().join("p/q/deep/deeper")).unwrap();
    fs::write(directory.path().join("payload"), b"payload").unwrap();
    fs::write(directory.path().join("p/q/deep/deeper/keep"), b"keep").unwrap();
    symlink("deep/deeper", directory.path().join("p/q/pull")).unwrap();
    // The raw target is lexically outside the root, but expansion of pull
    // first leaves the terminal payload inside the signed tree.
    symlink(
        "pull/../../../../payload",
        directory.path().join("p/q/entry"),
    )
    .unwrap();
    manifest(directory.path(), executable);
    let trusted_manifest = extend_manifest(
        directory.path(),
        [
            json!({
                "path": "payload",
                "sha256": format!("{:x}", Sha256::digest(b"payload")),
                "size": b"payload".len(),
                "type": "file"
            }),
            json!({
                "path": "p/q/deep/deeper/keep",
                "sha256": format!("{:x}", Sha256::digest(b"keep")),
                "size": b"keep".len(),
                "type": "file"
            }),
            json!({"path": "p/q/pull", "target": "deep/deeper", "type": "symlink"}),
            json!({
                "path": "p/q/entry",
                "target": "pull/../../../../payload",
                "type": "symlink"
            }),
        ],
    );

    assert!(
        verify_bundle(
            directory.path(),
            platform(),
            std::env::consts::ARCH,
            executable
        )
        .is_ok()
    );
    assert!(!trusted_manifest.is_empty());
}

#[cfg(unix)]
#[test]
fn runtime_bundle_allows_repeated_safe_symlink_traversal() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let executable = "zombie-killer-engine";
    write_executable(&directory.path().join(executable), b"trusted sidecar");
    fs::create_dir(directory.path().join("b")).unwrap();
    symlink("b", directory.path().join("a")).unwrap();
    // Resolving b/../a/../a visits a twice with different pending state and
    // terminates at b.
    symlink("../a/../a", directory.path().join("b/entry")).unwrap();
    manifest(directory.path(), executable);
    let trusted_manifest = extend_manifest(
        directory.path(),
        [
            json!({"path": "a", "target": "b", "type": "symlink"}),
            json!({
                "path": "b/entry",
                "target": "../a/../a",
                "type": "symlink"
            }),
        ],
    );

    let verified = verify_runtime_bundle(
        directory.path(),
        platform(),
        std::env::consts::ARCH,
        executable,
        &trusted_manifest,
    )
    .unwrap();
    let snapshot = verified.pinned_current_dir().unwrap();
    assert!(snapshot.join("b/entry").is_dir());
}

#[cfg(unix)]
#[test]
fn runtime_bundle_scopes_nested_directory_requirements_to_each_link_target() {
    use std::os::unix::fs::symlink;

    for hop_target in ["dir/", "dir/."] {
        let directory = tempfile::tempdir().unwrap();
        let executable = "zombie-killer-engine";
        write_executable(&directory.path().join(executable), b"trusted sidecar");
        fs::create_dir(directory.path().join("dir")).unwrap();
        fs::write(directory.path().join("dir/file"), b"payload").unwrap();
        symlink(hop_target, directory.path().join("hop")).unwrap();
        symlink("hop/file", directory.path().join("entry")).unwrap();
        manifest(directory.path(), executable);
        let trusted_manifest = extend_manifest(
            directory.path(),
            [
                json!({
                    "path": "dir/file",
                    "sha256": format!("{:x}", Sha256::digest(b"payload")),
                    "size": b"payload".len(),
                    "type": "file"
                }),
                json!({"path": "hop", "target": hop_target, "type": "symlink"}),
                json!({"path": "entry", "target": "hop/file", "type": "symlink"}),
            ],
        );

        let verified = verify_runtime_bundle(
            directory.path(),
            platform(),
            std::env::consts::ARCH,
            executable,
            &trusted_manifest,
        )
        .unwrap();
        let snapshot = verified.pinned_current_dir().unwrap();
        assert_eq!(fs::read(snapshot.join("entry")).unwrap(), b"payload");
    }
}

#[cfg(unix)]
#[test]
fn runtime_bundle_bounds_a_growing_symlink_cycle() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let executable = "zombie-killer-engine";
    write_executable(&directory.path().join(executable), b"trusted sidecar");
    symlink("a/x", directory.path().join("a")).unwrap();
    manifest(directory.path(), executable);
    let trusted_manifest = extend_manifest(
        directory.path(),
        [json!({"path": "a", "target": "a/x", "type": "symlink"})],
    );

    let error = match verify_runtime_bundle(
        directory.path(),
        platform(),
        std::env::consts::ARCH,
        executable,
        &trusted_manifest,
    ) {
        Ok(_) => panic!("a growing symlink cycle was accepted"),
        Err(error) => error,
    };
    assert!(error.contains("too many symbolic links"));
}

#[cfg(unix)]
#[test]
fn release_resource_manifest_rejects_terminal_file_directory_suffixes_through_multihop_links() {
    use std::os::unix::fs::symlink;

    for (name, target) in [("slash", "hop/"), ("dot", "hop/.")] {
        let directory = tempfile::tempdir().unwrap();
        let executable = "zombie-killer-engine";
        write_executable(&directory.path().join(executable), b"trusted sidecar");
        fs::write(directory.path().join("payload"), b"payload").unwrap();
        symlink("payload", directory.path().join("hop")).unwrap();
        symlink(target, directory.path().join(name)).unwrap();
        manifest(directory.path(), executable);
        let trusted_manifest = extend_manifest(
            directory.path(),
            [
                json!({
                    "path": "payload",
                    "sha256": format!("{:x}", Sha256::digest(b"payload")),
                    "size": b"payload".len(),
                    "type": "file"
                }),
                json!({"path": "hop", "target": "payload", "type": "symlink"}),
                json!({"path": name, "target": target, "type": "symlink"}),
            ],
        );

        assert!(
            verify_runtime_bundle(
                directory.path(),
                platform(),
                std::env::consts::ARCH,
                executable,
                &trusted_manifest,
            )
            .is_err(),
            "{name} should require a directory terminal"
        );
    }
}

#[cfg(unix)]
#[test]
fn release_resource_manifest_rejects_symlink_cycles_and_dangling_chains() {
    use std::os::unix::fs::symlink;

    for (name, first_target, second_target, expected) in [
        ("self-cycle", "entry", None, "cycle"),
        ("two-node-cycle", "hop", Some("entry"), "cycle"),
        ("dangling-chain", "hop", Some("missing"), "missing"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let executable = "zombie-killer-engine";
        write_executable(&directory.path().join(executable), b"trusted sidecar");
        symlink(first_target, directory.path().join("entry")).unwrap();
        if let Some(target) = second_target {
            symlink(target, directory.path().join("hop")).unwrap();
        }
        manifest(directory.path(), executable);
        let mut entries = vec![json!({
            "path": "entry",
            "target": first_target,
            "type": "symlink"
        })];
        if let Some(target) = second_target {
            entries.push(json!({"path": "hop", "target": target, "type": "symlink"}));
        }
        let trusted_manifest = extend_manifest(directory.path(), entries);
        let rejected = verify_runtime_bundle(
            directory.path(),
            platform(),
            std::env::consts::ARCH,
            executable,
            &trusted_manifest,
        )
        .is_err();
        assert!(rejected, "{name} should be rejected ({expected})");
    }
}

#[cfg(unix)]
#[test]
fn release_resource_manifest_rejects_symlink_component_expansion_escape() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("bundle");
    fs::create_dir(&root).unwrap();
    let external = directory.path().join("outside.so");
    fs::write(&external, b"must not be opened").unwrap();
    let executable = "zombie-killer-engine";
    write_executable(&root.join(executable), b"trusted sidecar");
    fs::create_dir_all(root.join("p/q")).unwrap();
    fs::write(root.join("p/outside.so"), b"lexical decoy").unwrap();
    symlink("..", root.join("p/q/hop")).unwrap();
    symlink("hop/../../outside.so", root.join("p/q/escape")).unwrap();
    manifest(&root, executable);
    let trusted_manifest = extend_manifest(
        &root,
        [
            json!({
                "path": "p/outside.so",
                "sha256": format!("{:x}", Sha256::digest(b"lexical decoy")),
                "size": b"lexical decoy".len(),
                "type": "file"
            }),
            json!({"path": "p/q/hop", "target": "..", "type": "symlink"}),
            json!({
                "path": "p/q/escape",
                "target": "hop/../../outside.so",
                "type": "symlink"
            }),
        ],
    );

    assert!(
        verify_runtime_bundle(
            &root,
            platform(),
            std::env::consts::ARCH,
            executable,
            &trusted_manifest,
        )
        .is_err()
    );
    assert_eq!(fs::read(&external).unwrap(), b"must not be opened");
}

#[test]
fn release_resource_manifest_is_complete_and_integrity_checked() {
    let directory = tempfile::tempdir().unwrap();
    let executable = if cfg!(windows) {
        "zombie-killer-engine.exe"
    } else {
        "zombie-killer-engine"
    };
    write_executable(&directory.path().join(executable), b"fixed sidecar");
    manifest(directory.path(), executable);

    assert!(
        verify_bundle(
            directory.path(),
            platform(),
            std::env::consts::ARCH,
            executable
        )
        .is_ok()
    );

    write_executable(&directory.path().join(executable), b"tampered sidecar");
    assert!(
        verify_bundle(
            directory.path(),
            platform(),
            std::env::consts::ARCH,
            executable
        )
        .is_err()
    );

    write_executable(&directory.path().join(executable), b"fixed sidecar");
    manifest(directory.path(), executable);
    fs::write(directory.path().join("unlisted.bin"), b"not inventoried").unwrap();
    assert!(
        verify_bundle(
            directory.path(),
            platform(),
            std::env::consts::ARCH,
            executable
        )
        .is_err()
    );
}

#[test]
fn release_resource_manifest_rejects_unsafe_inventory_paths() {
    let directory = tempfile::tempdir().unwrap();
    let executable = if cfg!(windows) {
        "zombie-killer-engine.exe"
    } else {
        "zombie-killer-engine"
    };
    write_executable(&directory.path().join(executable), b"fixed sidecar");
    manifest(directory.path(), executable);
    let manifest_path = directory.path().join("BUILD-MANIFEST.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    value["entries"][0]["path"] = json!("../zombie-killer-engine");
    fs::write(manifest_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    assert!(
        verify_bundle(
            directory.path(),
            platform(),
            std::env::consts::ARCH,
            executable
        )
        .is_err()
    );
}

#[test]
fn release_resource_manifest_rejects_every_unknown_architecture() {
    let directory = tempfile::tempdir().unwrap();
    let executable = if cfg!(windows) {
        "zombie-killer-engine.exe"
    } else {
        "zombie-killer-engine"
    };
    write_executable(&directory.path().join(executable), b"fixed sidecar");
    manifest(directory.path(), executable);
    let manifest_path = directory.path().join("BUILD-MANIFEST.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    value["architecture"] = json!("mips64");
    fs::write(manifest_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    assert!(
        verify_bundle(directory.path(), platform(), "riscv64", executable).is_err(),
        "two unrelated unknown architectures must never compare equal"
    );
}

#[test]
fn runtime_bundle_requires_the_compiled_manifest_digest_even_after_resigning_payload() {
    let directory = tempfile::tempdir().unwrap();
    let executable = if cfg!(windows) {
        "zombie-killer-engine.exe"
    } else {
        "zombie-killer-engine"
    };
    write_executable(&directory.path().join(executable), b"trusted sidecar");
    manifest(directory.path(), executable);
    let trusted_manifest = format!(
        "{:x}",
        Sha256::digest(fs::read(directory.path().join("BUILD-MANIFEST.json")).unwrap())
    );

    let verified = verify_runtime_bundle(
        directory.path(),
        platform(),
        std::env::consts::ARCH,
        executable,
        &trusted_manifest,
    )
    .unwrap();
    assert_eq!(verified.manifest_sha256(), trusted_manifest);
    drop(verified);

    write_executable(&directory.path().join(executable), b"attacker replacement");
    manifest(directory.path(), executable);
    assert!(
        verify_runtime_bundle(
            directory.path(),
            platform(),
            std::env::consts::ARCH,
            executable,
            &trusted_manifest,
        )
        .is_err(),
        "rewriting both the executable and adjacent manifest bypassed the trust anchor"
    );
}

#[test]
fn runtime_bundle_rejects_uninventoried_empty_directories() {
    let directory = tempfile::tempdir().unwrap();
    let executable = if cfg!(windows) {
        "zombie-killer-engine.exe"
    } else {
        "zombie-killer-engine"
    };
    write_executable(&directory.path().join(executable), b"trusted sidecar");
    manifest(directory.path(), executable);
    let trusted_manifest = format!(
        "{:x}",
        Sha256::digest(fs::read(directory.path().join("BUILD-MANIFEST.json")).unwrap())
    );
    fs::create_dir(directory.path().join("unexpected-empty")).unwrap();

    assert!(
        verify_runtime_bundle(
            directory.path(),
            platform(),
            std::env::consts::ARCH,
            executable,
            &trusted_manifest,
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn runtime_bundle_rejects_a_symlinked_intermediate_directory() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("bundle");
    let outside = directory.path().join("outside");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&outside).unwrap();
    let executable = "zombie-killer-engine";
    write_executable(&root.join(executable), b"trusted sidecar");
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("nested/payload.bin"), b"trusted payload").unwrap();
    manifest(&root, executable);

    let manifest_path = root.join("BUILD-MANIFEST.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    value["entries"].as_array_mut().unwrap().push(json!({
        "path": "nested/payload.bin",
        "sha256": format!("{:x}", Sha256::digest(b"trusted payload")),
        "size": b"trusted payload".len(),
        "type": "file"
    }));
    fs::write(&manifest_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    let trusted_manifest = format!("{:x}", Sha256::digest(fs::read(&manifest_path).unwrap()));

    fs::remove_file(root.join("nested/payload.bin")).unwrap();
    fs::remove_dir(root.join("nested")).unwrap();
    fs::write(outside.join("payload.bin"), b"trusted payload").unwrap();
    symlink(&outside, root.join("nested")).unwrap();

    assert!(
        verify_runtime_bundle(
            &root,
            platform(),
            std::env::consts::ARCH,
            executable,
            &trusted_manifest,
        )
        .is_err(),
        "an intermediate symlink redirected an inventoried file outside the verified root"
    );
}

#[cfg(unix)]
#[test]
fn runtime_bundle_rejects_unlisted_backslash_name_collisions() {
    let directory = tempfile::tempdir().unwrap();
    let executable = "zombie-killer-engine";
    write_executable(&directory.path().join(executable), b"trusted sidecar");
    fs::create_dir(directory.path().join("nested")).unwrap();
    fs::write(
        directory.path().join("nested/payload.bin"),
        b"trusted payload",
    )
    .unwrap();
    manifest(directory.path(), executable);
    let manifest_path = directory.path().join("BUILD-MANIFEST.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    value["entries"].as_array_mut().unwrap().push(json!({
        "path": "nested/payload.bin",
        "sha256": format!("{:x}", Sha256::digest(b"trusted payload")),
        "size": b"trusted payload".len(),
        "type": "file"
    }));
    fs::write(&manifest_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    let trusted_manifest = format!("{:x}", Sha256::digest(fs::read(&manifest_path).unwrap()));
    fs::write(
        directory.path().join("nested\\payload.bin"),
        b"unlisted collision",
    )
    .unwrap();

    assert!(
        verify_runtime_bundle(
            directory.path(),
            platform(),
            std::env::consts::ARCH,
            executable,
            &trusted_manifest,
        )
        .is_err(),
        "a literal Unix backslash name collided with an inventoried separator"
    );
}

#[cfg(unix)]
#[test]
fn runtime_bundle_executes_the_private_snapshot_after_source_path_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let executable = "zombie-killer-engine";
    let executable_path = directory.path().join(executable);
    write_executable(&executable_path, &fs::read("/bin/echo").unwrap());
    manifest(directory.path(), executable);
    let trusted_manifest = format!(
        "{:x}",
        Sha256::digest(fs::read(directory.path().join("BUILD-MANIFEST.json")).unwrap())
    );
    let verified = verify_runtime_bundle(
        directory.path(),
        platform(),
        std::env::consts::ARCH,
        executable,
        &trusted_manifest,
    )
    .unwrap();
    let pinned = verified.pinned_executable_path().unwrap();
    let snapshot_root = verified.pinned_current_dir().unwrap();
    assert_ne!(snapshot_root, directory.path());

    fs::rename(&executable_path, directory.path().join("verified-original")).unwrap();
    write_executable(&executable_path, &fs::read("/usr/bin/false").unwrap());
    let output = std::process::Command::new(pinned)
        .arg("verified-snapshot")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "verified-snapshot"
    );
    drop(verified);
    assert!(
        !snapshot_root.exists(),
        "runtime snapshot was not removed after its guard dropped"
    );
}

#[cfg(unix)]
#[test]
fn runtime_bundle_snapshot_is_unchanged_by_source_inode_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    let executable = "zombie-killer-engine";
    let executable_path = directory.path().join(executable);
    write_executable(&executable_path, &fs::read("/bin/echo").unwrap());
    manifest(directory.path(), executable);
    let trusted_manifest = format!(
        "{:x}",
        Sha256::digest(fs::read(directory.path().join("BUILD-MANIFEST.json")).unwrap())
    );
    let verified = verify_runtime_bundle(
        directory.path(),
        platform(),
        std::env::consts::ARCH,
        executable,
        &trusted_manifest,
    )
    .unwrap();
    let pinned = verified.pinned_executable_path().unwrap();

    write_executable(&executable_path, &fs::read("/usr/bin/false").unwrap());
    let output = std::process::Command::new(pinned)
        .arg("private-snapshot")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "private-snapshot"
    );
}

#[cfg(unix)]
#[test]
fn runtime_bundle_recreates_only_signed_in_tree_symlinks_in_the_snapshot() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let executable = "zombie-killer-engine";
    write_executable(&directory.path().join(executable), b"trusted sidecar");
    fs::write(directory.path().join("payload.bin"), b"trusted payload").unwrap();
    symlink("payload.bin", directory.path().join("payload-hop")).unwrap();
    symlink("payload-hop", directory.path().join("payload-link")).unwrap();
    manifest(directory.path(), executable);
    let manifest_path = directory.path().join("BUILD-MANIFEST.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    value["entries"].as_array_mut().unwrap().extend([
        json!({
            "path": "payload.bin",
            "sha256": format!("{:x}", Sha256::digest(b"trusted payload")),
            "size": b"trusted payload".len(),
            "type": "file"
        }),
        json!({
            "path": "payload-link",
            "target": "payload-hop",
            "type": "symlink"
        }),
        json!({
            "path": "payload-hop",
            "target": "payload.bin",
            "type": "symlink"
        }),
    ]);
    fs::write(&manifest_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    let trusted_manifest = format!("{:x}", Sha256::digest(fs::read(&manifest_path).unwrap()));

    let verified = verify_runtime_bundle(
        directory.path(),
        platform(),
        std::env::consts::ARCH,
        executable,
        &trusted_manifest,
    )
    .unwrap();
    let snapshot = verified.pinned_current_dir().unwrap();

    assert_eq!(
        fs::read_link(snapshot.join("payload-link")).unwrap(),
        Path::new("payload-hop")
    );
    assert_eq!(
        fs::read_link(snapshot.join("payload-hop")).unwrap(),
        Path::new("payload.bin")
    );
    assert_eq!(
        fs::read(snapshot.join("payload-link")).unwrap(),
        b"trusted payload"
    );
}

#[cfg(unix)]
#[test]
fn runtime_bundle_recovers_stale_snapshots_without_sweeping_live_owners() {
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;

    let directory = tempfile::tempdir().unwrap();
    let executable = "zombie-killer-engine";
    write_executable(&directory.path().join(executable), b"trusted sidecar");
    manifest(directory.path(), executable);
    let trusted_manifest = format!(
        "{:x}",
        Sha256::digest(fs::read(directory.path().join("BUILD-MANIFEST.json")).unwrap())
    );
    let live = verify_runtime_bundle(
        directory.path(),
        platform(),
        std::env::consts::ARCH,
        executable,
        &trusted_manifest,
    )
    .unwrap();
    let live_root = live.pinned_current_dir().unwrap();
    let owner_lock = live.owner_lock_descriptor().unwrap();
    // SAFETY: the descriptor belongs to the live verification guard.
    let descriptor_flags = unsafe { libc::fcntl(owner_lock, libc::F_GETFD) };
    assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);
    #[cfg(target_os = "linux")]
    assert!(
        std::process::Command::new("/bin/sh")
            .args(["-c", &format!("test ! -e /proc/self/fd/{owner_lock}"),])
            .status()
            .unwrap()
            .success(),
        "snapshot ownership lock leaked into a child process"
    );
    let parent = live_root.parent().unwrap();
    let reservation = tempfile::Builder::new()
        .prefix("lock-")
        .rand_bytes(6)
        .tempfile_in(parent)
        .unwrap();
    let (mut stale_owner, stale_lock) = reservation.keep().unwrap();
    let token = stale_lock
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("lock-")
        .unwrap();
    let stale_tree = parent.join(format!("tree-{token}"));
    // SAFETY: the temporary reservation owns a live descriptor. Holding the lock until the
    // fixture is complete prevents a parallel materializer from sweeping a half-built tree.
    assert_eq!(
        unsafe { libc::flock(stale_owner.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    stale_owner.write_all(b"ready\n").unwrap();
    stale_owner.flush().unwrap();
    fs::create_dir(&stale_tree).unwrap();
    fs::write(stale_tree.join("payload"), b"stale payload").unwrap();
    drop(stale_owner);

    let second = verify_runtime_bundle(
        directory.path(),
        platform(),
        std::env::consts::ARCH,
        executable,
        &trusted_manifest,
    )
    .unwrap();

    let cleanup_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while (stale_lock.exists() || stale_tree.exists())
        && std::time::Instant::now() < cleanup_deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(!stale_lock.exists());
    assert!(!stale_tree.exists());
    assert!(
        live_root.exists(),
        "recovery swept a snapshot whose owner lock was still live"
    );
    drop(second);
    drop(live);
    assert!(!live_root.exists());
}

#[cfg(unix)]
#[test]
fn runtime_snapshot_recovery_is_safe_across_concurrent_sweepers() {
    use std::sync::{Arc, Barrier};

    const SWEEPERS: usize = 8;
    const SNAPSHOTS: usize = 256;

    let parent = tempfile::tempdir().unwrap();
    for index in 0..SNAPSHOTS {
        let token = format!("{index:06}");
        fs::write(parent.path().join(format!("lock-{token}")), b"ready\n").unwrap();
        let tree = parent.path().join(format!("tree-{token}"));
        fs::create_dir(&tree).unwrap();
        fs::write(tree.join("payload"), b"stale payload").unwrap();
    }
    let root = parent.path();
    let start = Arc::new(Barrier::new(SWEEPERS));

    std::thread::scope(|scope| {
        let mut workers = Vec::with_capacity(SWEEPERS);
        for _ in 0..SWEEPERS {
            let start = Arc::clone(&start);
            workers.push(scope.spawn(move || -> Result<(), String> {
                start.wait();
                recover_stale_runtime_snapshots(root)
            }));
        }

        for worker in workers {
            worker.join().unwrap().unwrap();
        }
    });

    assert!(fs::read_dir(root).unwrap().next().is_none());
}

#[cfg(unix)]
#[test]
#[ignore = "requires ZK_PACKAGED_ENGINE_TEST_ROOT from the pinned PyInstaller sidecar builder"]
fn packaged_pyinstaller_onedir_runs_system_info_from_the_private_snapshot() {
    use std::io::Write as _;
    use std::process::Stdio;

    let root = std::env::var_os("ZK_PACKAGED_ENGINE_TEST_ROOT")
        .map(std::path::PathBuf::from)
        .expect("ZK_PACKAGED_ENGINE_TEST_ROOT is required");
    let executable = "zombie-killer-engine";
    let manifest_path = root.join("BUILD-MANIFEST.json");
    let trusted_manifest = format!("{:x}", Sha256::digest(fs::read(&manifest_path).unwrap()));
    let verified = verify_runtime_bundle(
        &root,
        platform(),
        std::env::consts::ARCH,
        executable,
        &trusted_manifest,
    )
    .unwrap();
    let snapshot = verified.pinned_current_dir().unwrap();
    let snapshot_executable = verified.pinned_executable_path().unwrap();

    fs::rename(
        root.join(executable),
        root.join("source-executable-before-swap"),
    )
    .unwrap();
    write_executable(&root.join(executable), &fs::read("/usr/bin/false").unwrap());
    fs::rename(
        root.join("_internal"),
        root.join("source-internal-before-swap"),
    )
    .unwrap();
    fs::create_dir(root.join("_internal")).unwrap();
    let state = tempfile::tempdir().unwrap();
    let parent_argument = format!("--parent-pid={}", std::process::id());
    let mut child = std::process::Command::new(snapshot_executable)
        .args([
            "protocol-once",
            "--internal-state-root",
            state.path().to_str().unwrap(),
            &parent_argument,
        ])
        .current_dir(&snapshot)
        .env_clear()
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            br#"{"protocol_version":"1.0","request_id":"11111111-1111-4111-8111-111111111111","method":"system.info","payload":{}}
"#,
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "snapshot sidecar failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["ok"], true);
    assert_eq!(response["method"], "system.info");
    assert_eq!(
        response["request_id"],
        "11111111-1111-4111-8111-111111111111"
    );
    assert!(response["result"].is_object());
}

#[cfg(windows)]
#[test]
fn runtime_bundle_guard_prevents_verified_file_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let executable = "zombie-killer-engine.exe";
    let executable_path = directory.path().join(executable);
    write_executable(&executable_path, b"trusted sidecar");
    manifest(directory.path(), executable);
    let trusted_manifest = format!(
        "{:x}",
        Sha256::digest(fs::read(directory.path().join("BUILD-MANIFEST.json")).unwrap())
    );
    let verified = verify_runtime_bundle(
        directory.path(),
        platform(),
        std::env::consts::ARCH,
        executable,
        &trusted_manifest,
    )
    .unwrap();
    let moved = directory.path().join("replaced.exe");

    assert!(
        fs::rename(&executable_path, &moved).is_err(),
        "verified executable could be replaced while the guard was live"
    );
    drop(verified);
    fs::rename(executable_path, moved).unwrap();
}

#[cfg(windows)]
#[test]
fn runtime_bundle_rejects_a_junction_as_the_resource_root() {
    let directory = tempfile::tempdir().unwrap();
    let real = directory.path().join("real");
    let junction = directory.path().join("junction");
    fs::create_dir(&real).unwrap();
    let executable = "zombie-killer-engine.exe";
    write_executable(&real.join(executable), b"trusted sidecar");
    manifest(&real, executable);
    let trusted_manifest = format!(
        "{:x}",
        Sha256::digest(fs::read(real.join("BUILD-MANIFEST.json")).unwrap())
    );
    let output = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&real)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "could not create test junction: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let rejected = verify_runtime_bundle(
        &junction,
        platform(),
        std::env::consts::ARCH,
        executable,
        &trusted_manifest,
    )
    .is_err();
    fs::remove_dir(&junction).unwrap();
    assert!(rejected);
}

#[cfg(target_os = "macos")]
#[test]
fn runtime_bundle_executes_the_verified_macos_fd_after_path_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let executable = "zombie-killer-engine";
    let executable_path = directory.path().join(executable);
    write_executable(&executable_path, &fs::read("/bin/echo").unwrap());
    manifest(directory.path(), executable);
    let trusted_manifest = format!(
        "{:x}",
        Sha256::digest(fs::read(directory.path().join("BUILD-MANIFEST.json")).unwrap())
    );
    let verified = verify_runtime_bundle(
        directory.path(),
        platform(),
        std::env::consts::ARCH,
        executable,
        &trusted_manifest,
    )
    .unwrap();
    let pinned = verified.pinned_executable_path().unwrap();

    fs::rename(&executable_path, directory.path().join("verified-original")).unwrap();
    write_executable(&executable_path, &fs::read("/usr/bin/false").unwrap());
    let output = std::process::Command::new(pinned)
        .arg("verified-fd")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "verified-fd"
    );
}
