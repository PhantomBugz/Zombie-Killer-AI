use flate2::{Compression, write::ZlibEncoder};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::Path};
use zombie_killer_portable::{extract, parse_mode};

// Independently encode the documented wire format; never use production encoder helpers.
fn files() -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<(String, Vec<u8>)> = vec![
        (
            "target/release/zombie-killer.exe".into(),
            b"MZ-native-fixture".to_vec(),
        ),
        (
            "target/release/engine/zombie-killer-engine.exe".into(),
            b"MZ-engine-fixture".to_vec(),
        ),
        ("LICENSE".into(), b"project terms\r\n".to_vec()),
        ("NOTICE".into(), b"PhantomBugz\n".to_vec()),
        ("THIRD_PARTY_NOTICES.md".into(), b"third party\n".to_vec()),
        ("TRADEMARKS.md".into(), b"trademark\n".to_vec()),
        ("LICENSES/CC-BY-4.0.txt".into(), b"asset license\n".to_vec()),
        ("LICENSES/OFL-1.1.txt".into(), b"font license\n".to_vec()),
    ];
    let engine = b"MZ-engine-fixture";
    files.push((
        "target/release/engine/BUILD-MANIFEST.json".into(),
        serde_json::to_vec(&json!({
            "format":"pyinstaller-onedir", "platform":"windows", "architecture":"amd64",
            "entries":[{"path":"zombie-killer-engine.exe", "type":"file", "size":engine.len(),
                        "sha256":format!("{:x}", Sha256::digest(engine))}]
        }))
        .unwrap(),
    ));
    files
}

fn manifest(files: &[(String, Vec<u8>)]) -> Value {
    json!({"format":1, "files":files.iter().map(|(path,data)|json!({
        "path":path,"size":data.len(),"sha256":format!("{:x}",Sha256::digest(data))
    })).collect::<Vec<_>>()})
}

fn pack(manifest: Value, body: &[u8]) -> Vec<u8> {
    let json = serde_json::to_vec(&manifest).unwrap();
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).unwrap();
    let mut payload = b"ZKPORT01".to_vec();
    payload.extend_from_slice(&(json.len() as u32).to_le_bytes());
    payload.extend(json);
    payload.extend(encoder.finish().unwrap());
    payload
}

fn body(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    files.iter().flat_map(|(_, data)| data.clone()).collect()
}

fn digest(payload: &[u8]) -> String {
    format!("{:x}", Sha256::digest(payload))
}

fn rejected(payload: &[u8]) {
    let parent = tempfile::tempdir().unwrap();
    assert!(extract(payload, &digest(payload), parent.path()).is_err());
    assert_eq!(
        fs::read_dir(parent.path()).unwrap().count(),
        0,
        "failure must clean its owned tree"
    );
}

#[test]
fn restores_exact_original_bytes_under_parent_with_spaces_and_removes_only_owned_tree() {
    let parent = tempfile::tempdir().unwrap();
    let spaced = parent.path().join("local application data with spaces");
    fs::create_dir(&spaced).unwrap();
    fs::write(spaced.join("unrelated.keep"), b"keep me").unwrap();
    let files = files();
    let payload = pack(manifest(&files), &body(&files));
    let runtime = extract(&payload, &digest(&payload), &spaced).unwrap();
    let root = runtime.root().to_path_buf();
    for (name, expected) in &files {
        assert_eq!(fs::read(root.join(name)).unwrap(), *expected);
    }
    runtime.close().unwrap();
    assert!(!root.exists());
    assert_eq!(fs::read(spaced.join("unrelated.keep")).unwrap(), b"keep me");
}

#[test]
fn drop_cleans_owned_tree() {
    let parent = tempfile::tempdir().unwrap();
    let files = files();
    let payload = pack(manifest(&files), &body(&files));
    let root;
    {
        let runtime = extract(&payload, &digest(&payload), parent.path()).unwrap();
        root = runtime.root().to_path_buf();
    }
    assert!(!root.exists());
}

#[test]
fn corrupt_embedded_digest_fails_before_creating_files() {
    let parent = tempfile::tempdir().unwrap();
    let files = files();
    let payload = pack(manifest(&files), &body(&files));
    assert!(extract(&payload, &"0".repeat(64), parent.path()).is_err());
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[test]
fn rejects_unsafe_windows_paths() {
    for path in [
        "../escape",
        "/absolute",
        "C:/drive",
        "a\\b",
        "a:b",
        "CON.txt",
        "LPT1",
        "x/NUL",
        "dir/../x",
        "a.",
        "a ",
        "dir//x",
        "é.bin",
    ] {
        let mut files = files();
        files.push((path.into(), b"bad".to_vec()));
        rejected(&pack(manifest(&files), &body(&files)));
    }
}

#[test]
fn rejects_duplicates_case_aliases_and_file_directory_collisions() {
    for path in ["NOTICE", "notice", "notice/subfile", "TARGET"] {
        let mut files = files();
        files.push((path.into(), b"bad".to_vec()));
        rejected(&pack(manifest(&files), &body(&files)));
    }
}

#[test]
fn rejects_wrong_file_hash_and_wrong_size() {
    let files = files();
    let mut changed = manifest(&files);
    changed["files"][0]["sha256"] = json!("0".repeat(64));
    rejected(&pack(changed, &body(&files)));
    let mut changed = manifest(&files);
    changed["files"][0]["size"] = json!(99);
    rejected(&pack(changed, &body(&files)));
}

#[test]
fn rejects_truncated_and_overlong_decompressed_and_compressed_streams() {
    let files = files();
    let bytes = body(&files);
    rejected(&pack(manifest(&files), &bytes[..bytes.len() - 1]));
    let mut extra = bytes.clone();
    extra.push(1);
    rejected(&pack(manifest(&files), &extra));
    let mut compressed = pack(manifest(&files), &bytes);
    compressed.pop();
    rejected(&compressed);
    let mut compressed = pack(manifest(&files), &bytes);
    compressed.push(1);
    rejected(&compressed);
}

#[test]
fn rejects_missing_required_files_and_bad_engine_inventory() {
    for missing in ["LICENSES/OFL-1.1.txt", "target/release/zombie-killer.exe"] {
        let mut files = files();
        files.retain(|(name, _)| name != missing);
        rejected(&pack(manifest(&files), &body(&files)));
    }
    let mut files = files();
    files.last_mut().unwrap().1 = b"{}".to_vec();
    rejected(&pack(manifest(&files), &body(&files)));
}

#[test]
fn rejects_header_manifest_and_size_limits() {
    rejected(b"ZKPORT01");
    let mut bad = b"ZKPORT01".to_vec();
    bad.extend_from_slice(&(4u32 * 1024 * 1024 + 1).to_le_bytes());
    rejected(&bad);
    let files = files();
    let mut changed = manifest(&files);
    changed["files"][0]["size"] = json!(512u64 * 1024 * 1024 + 1);
    rejected(&pack(changed, &[]));
    let mut changed = manifest(&files);
    let item = changed["files"][0].clone();
    changed["files"] = json!(vec![item; 4097]);
    rejected(&pack(changed, &[]));
    let mut changed = manifest(&files);
    changed["format"] = json!(2);
    rejected(&pack(changed, &body(&files)));
    let mut changed = manifest(&files);
    changed["files"][0]["type"] = json!("symlink");
    rejected(&pack(changed, &body(&files)));
}

#[test]
fn accepts_only_no_arguments_or_single_check_and_does_not_offer_overrides() {
    assert!(!parse_mode(&[]).unwrap());
    assert!(parse_mode(&["--check".into()]).unwrap());
    for args in [
        vec!["unknown".into()],
        vec!["--check".into(), "extra".into()],
        vec!["--payload".into(), "C:/other".into()],
    ] {
        assert!(parse_mode(&args).is_err());
    }
}

#[test]
fn parent_must_be_absolute() {
    let files = files();
    let payload = pack(manifest(&files), &body(&files));
    assert!(extract(&payload, &digest(&payload), Path::new("relative")).is_err());
}
