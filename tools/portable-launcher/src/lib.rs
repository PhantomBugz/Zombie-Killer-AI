use flate2::{Decompress, FlushDecompress, Status};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    io::{Read, Write},
    path::Path,
    thread,
    time::Duration,
};
use tempfile::TempDir;

const MAX_MANIFEST: usize = 4 * 1024 * 1024;
const MAX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_FILES: usize = 4096;
const ENGINE: &str = "target/release/engine/";
const REQUIRED: &[&str] = &[
    "target/release/zombie-killer.exe",
    "target/release/engine/BUILD-MANIFEST.json",
    "target/release/engine/zombie-killer-engine.exe",
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
    "TRADEMARKS.md",
    "LICENSES/CC-BY-4.0.txt",
    "LICENSES/OFL-1.1.txt",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u32,
    files: Vec<FileEntry>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Deserialize)]
struct EngineManifest {
    format: String,
    platform: String,
    architecture: String,
    entries: Vec<EngineEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EngineEntry {
    path: String,
    #[serde(rename = "type")]
    kind: String,
    size: u64,
    sha256: String,
}

/// The private TempDir owns the exact cleanup target; callers cannot select a deletion root.
pub struct OwnedRuntime {
    directory: TempDir,
    files: Vec<FileEntry>,
    sha256: String,
    total: u64,
}

// The high-level flate2 Read adapter accepts certain missing stream footers.
// Require an explicit StreamEnd and exact compressed consumption instead.
struct ExactZlib<'a> {
    input: &'a [u8],
    decoder: Decompress,
    finished: bool,
}
impl Read for ExactZlib<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() || self.finished {
            return Ok(0);
        }
        loop {
            let before_in = self.decoder.total_in();
            let before_out = self.decoder.total_out();
            let status = self
                .decoder
                .decompress(
                    &self.input[before_in as usize..],
                    output,
                    FlushDecompress::None,
                )
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            let count = (self.decoder.total_out() - before_out) as usize;
            if status == Status::StreamEnd {
                if self.decoder.total_in() != self.input.len() as u64 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Trailing compressed data",
                    ));
                }
                self.finished = true;
                return Ok(count);
            }
            if count > 0 {
                return Ok(count);
            }
            if self.decoder.total_in() == before_in {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Incomplete zlib stream",
                ));
            }
        }
    }
}

fn io_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn path_key(name: &str) -> Result<String, String> {
    if name.is_empty() || !name.is_ascii() || name.len() > 240 {
        return Err("Unsupported Windows relative filename".into());
    }
    for part in name.split('/') {
        let base = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        let numbered = (base.starts_with("COM") || base.starts_with("LPT"))
            && base.len() == 4
            && (b'1'..=b'9').contains(&base.as_bytes()[3]);
        if part.is_empty()
            || matches!(part, "." | "..")
            || part.ends_with(['.', ' '])
            || part.len() > 255
            || part.bytes().any(|c| c < 32 || b"\\:<>\"|?*".contains(&c))
            || matches!(
                base.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            )
            || numbered
        {
            return Err(format!("Unsafe Windows relative path: {name}"));
        }
    }
    Ok(name.to_ascii_lowercase())
}

fn insert_path(name: &str, seen: &mut HashSet<String>) -> Result<(), String> {
    let key = path_key(name)?;
    if seen.contains(&key)
        || seen.iter().any(|prior| {
            key.starts_with(&(prior.clone() + "/")) || prior.starts_with(&(key.clone() + "/"))
        })
    {
        return Err("Duplicate Windows filename or file/directory collision".into());
    }
    seen.insert(key);
    Ok(())
}

fn verify_engine(runtime: &OwnedRuntime) -> Result<(), String> {
    let marker = "target/release/engine/BUILD-MANIFEST.json";
    let entry = runtime
        .files
        .iter()
        .find(|e| e.path == marker)
        .ok_or("Engine manifest is missing")?;
    if entry.size > MAX_MANIFEST as u64 {
        return Err("Engine manifest exceeds 4 MiB".into());
    }
    let inventory: EngineManifest =
        serde_json::from_slice(&fs::read(runtime.root().join(marker)).map_err(io_error)?)
            .map_err(io_error)?;
    if inventory.format != "pyinstaller-onedir"
        || inventory.platform != "windows"
        || !matches!(inventory.architecture.as_str(), "amd64" | "x86_64")
        || inventory.entries.len() > MAX_FILES
    {
        return Err("Engine inventory must identify Windows x64 onedir".into());
    }
    let mut seen = HashSet::new();
    let mut expected = HashSet::new();
    expected.insert(marker.to_string());
    for entry in inventory.entries {
        insert_path(&entry.path, &mut seen)?;
        let name = format!("{ENGINE}{}", entry.path);
        let file = runtime
            .files
            .iter()
            .find(|f| f.path == name)
            .ok_or("Engine inventory file is missing")?;
        if entry.kind != "file" || entry.size != file.size || entry.sha256 != file.sha256 {
            return Err("Engine inventory type/size/hash mismatch".into());
        }
        expected.insert(name);
    }
    let actual: HashSet<_> = runtime
        .files
        .iter()
        .filter(|e| e.path.starts_with(ENGINE))
        .map(|e| e.path.clone())
        .collect();
    if expected != actual {
        return Err("Engine inventory differs from payload".into());
    }
    Ok(())
}

pub fn extract(payload: &[u8], digest: &str, parent: &Path) -> Result<OwnedRuntime, String> {
    if !parent.is_absolute() || !parent.is_dir() {
        return Err("Runtime parent must be an existing absolute directory".into());
    }
    if payload.len() > MAX_BYTES as usize + MAX_MANIFEST + 1024 * 1024
        || !valid_digest(digest)
        || hash(payload) != digest
    {
        return Err("Portable payload integrity check failed; download a complete copy".into());
    }
    if payload.len() < 12 || &payload[..8] != b"ZKPORT01" {
        return Err("Invalid portable payload header".into());
    }
    let length = u32::from_le_bytes(payload[8..12].try_into().unwrap()) as usize;
    if length > MAX_MANIFEST || length > payload.len() - 12 {
        return Err("Invalid or excessive manifest size".into());
    }
    let manifest: Manifest = serde_json::from_slice(&payload[12..12 + length]).map_err(io_error)?;
    if manifest.format != 1 || manifest.files.is_empty() || manifest.files.len() > MAX_FILES {
        return Err("Unsupported payload format or excessive file count".into());
    }
    let mut total = 0u64;
    let mut seen = HashSet::new();
    for entry in &manifest.files {
        insert_path(&entry.path, &mut seen)?;
        if !valid_digest(&entry.sha256) {
            return Err("Invalid file digest".into());
        }
        total = total
            .checked_add(entry.size)
            .ok_or("Payload size overflow")?;
        if total > MAX_BYTES {
            return Err("Payload exceeds 512 MiB".into());
        }
    }
    for required in REQUIRED {
        if !manifest.files.iter().any(|e| e.path == *required) {
            return Err(format!("Required file is missing: {required}"));
        }
    }
    let directory = tempfile::Builder::new()
        .prefix("ZombieKiller-")
        .tempdir_in(parent)
        .map_err(io_error)?;
    let runtime = OwnedRuntime {
        directory,
        files: manifest.files,
        sha256: digest.into(),
        total,
    };
    let mut decoder = ExactZlib {
        input: &payload[12 + length..],
        decoder: Decompress::new(true),
        finished: false,
    };
    let mut buffer = [0u8; 64 * 1024];
    for entry in &runtime.files {
        let destination = runtime.root().join(&entry.path);
        fs::create_dir_all(destination.parent().ok_or("Invalid file parent")?).map_err(io_error)?;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
            .map_err(io_error)?;
        let mut remaining = entry.size;
        let mut digest = Sha256::new();
        while remaining > 0 {
            let bound = remaining.min(buffer.len() as u64) as usize;
            let length = decoder.read(&mut buffer[..bound]).map_err(io_error)?;
            if length == 0 {
                return Err("Truncated portable file data".into());
            }
            output.write_all(&buffer[..length]).map_err(io_error)?;
            digest.update(&buffer[..length]);
            remaining -= length as u64;
        }
        output.flush().map_err(io_error)?;
        if format!("{:x}", digest.finalize()) != entry.sha256 {
            return Err(format!("File integrity check failed: {}", entry.path));
        }
    }
    if decoder.read(&mut buffer[..1]).map_err(io_error)? != 0 || !decoder.finished {
        return Err("Unexpected trailing portable data".into());
    }
    verify_engine(&runtime)?;
    Ok(runtime)
}

pub fn parse_mode(arguments: &[String]) -> Result<bool, String> {
    match arguments {
        [] => Ok(false),
        [value] if value == "--check" => Ok(true),
        _ => Err("Zombie Killer accepts only --check or no arguments".into()),
    }
}

impl OwnedRuntime {
    pub fn root(&self) -> &Path {
        self.directory.path()
    }
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({"runtime_root":self.root(), "files":self.files.len(),
            "total_bytes":self.total,"payload_sha256":self.sha256})
    }
    pub fn close(self) -> Result<(), String> {
        // Windows may briefly retain DLL mappings after the app exits. The target
        // always comes from this private TempDir, never from arguments or a scan.
        for attempt in 0..20 {
            match fs::remove_dir_all(self.root()) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) if attempt == 19 => {
                    return Err(format!(
                        "Could not remove runtime {}: {error}",
                        self.root().display()
                    ));
                }
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
        unreachable!()
    }
}
