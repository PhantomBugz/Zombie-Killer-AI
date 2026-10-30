use std::collections::{HashMap, HashSet};
#[cfg(unix)]
use std::ffi::{CStr, CString};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read;
#[cfg(unix)]
use std::io::{Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

const MANIFEST_NAME: &str = "BUILD-MANIFEST.json";
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 20_000;
const MAX_DIRECTORY_DEPTH: usize = 128;
const MAX_SYMLINK_EXPANSIONS: usize = MAX_ENTRIES * 8;
const MAX_SYMLINK_FOLLOWS: usize = 64;
const MAX_SYMLINK_PENDING_COMPONENTS: usize = 512;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    platform: String,
    architecture: String,
    python: String,
    pyinstaller: String,
    source_date_epoch: String,
    entries: Vec<InventoryEntry>,
}

pub struct VerifiedBundle {
    manifest_sha256: String,
    _protected_handles: Vec<File>,
    #[allow(dead_code)]
    executable_handle_index: usize,
    #[cfg(unix)]
    runtime_snapshot: Option<RuntimeSnapshot>,
}

#[cfg(unix)]
struct RuntimeSnapshot {
    root: PathBuf,
    executable: PathBuf,
    lock_path: PathBuf,
    _owner_lock: File,
}

#[cfg(unix)]
impl Drop for RuntimeSnapshot {
    fn drop(&mut self) {
        match fs::remove_dir_all(&self.root) {
            Ok(()) => {
                let _ = fs::remove_file(&self.lock_path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let _ = fs::remove_file(&self.lock_path);
            }
            Err(_) => {
                // Leave the ready marker behind. Closing `_owner_lock` makes the exact tree/lock
                // pair eligible for the next materialization's bounded stale sweep.
            }
        }
    }
}

#[cfg(unix)]
struct SnapshotFile {
    relative: PathBuf,
    handle_index: usize,
    size: u64,
    sha256: String,
}

#[cfg(unix)]
struct SnapshotSymlink {
    relative: PathBuf,
    target: OsString,
    resolved_target: PathBuf,
}

impl VerifiedBundle {
    #[allow(dead_code)] // The runtime copy retains handles; the build-script copy reads the digest.
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    #[allow(dead_code)]
    pub fn pinned_executable_path(&self) -> Option<PathBuf> {
        #[cfg(unix)]
        {
            self.runtime_snapshot
                .as_ref()
                .map(|snapshot| snapshot.executable.clone())
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    #[allow(dead_code)]
    pub fn pinned_current_dir(&self) -> Option<PathBuf> {
        #[cfg(unix)]
        {
            self.runtime_snapshot
                .as_ref()
                .map(|snapshot| snapshot.root.clone())
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    #[cfg(all(test, unix))]
    pub fn owner_lock_descriptor(&self) -> Option<i32> {
        self.runtime_snapshot
            .as_ref()
            .map(|snapshot| snapshot._owner_lock.as_raw_fd())
    }

    #[allow(dead_code)]
    pub fn revalidate_executable_identity(&self, path: &Path) -> Result<(), String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;

            let expected = self
                ._protected_handles
                .get(self.executable_handle_index)
                .ok_or_else(|| "verified executable handle is unavailable".to_owned())?
                .metadata()
                .map_err(|_| "verified executable metadata is unavailable")?;
            let actual = open_regular_file(path, "fixed executable")?
                .metadata()
                .map_err(|_| "fixed executable metadata is unavailable")?;
            if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
                return Err("fixed executable identity changed before launch".to_owned());
            }
        }
        #[cfg(not(unix))]
        let _ = path;
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum InventoryEntry {
    #[serde(rename = "file")]
    File {
        path: String,
        sha256: String,
        size: u64,
    },
    #[serde(rename = "symlink")]
    Symlink { path: String, target: String },
}

impl InventoryEntry {
    fn path(&self) -> &str {
        match self {
            Self::File { path, .. } | Self::Symlink { path, .. } => path,
        }
    }
}

pub(crate) fn validate_symbolic_link_graph(
    links: &HashMap<String, String>,
    expected: &HashSet<String>,
    expected_directories: &HashSet<String>,
) -> Result<(), String> {
    for (link, target) in links {
        let mut visited = HashSet::from([link.clone()]);
        let mut current = target;
        while let Some(next) = links.get(current) {
            if !visited.insert(current.clone()) {
                return Err("inventoried symlink graph contains a cycle".to_owned());
            }
            current = next;
        }
        if !expected.contains(current) && !expected_directories.contains(current) {
            return Err("inventoried symlink target is not in the signed inventory".to_owned());
        }
    }
    Ok(())
}

#[allow(dead_code)] // The build-script and test copies call this; the runtime copy uses the anchored variant.
pub fn verify_bundle(
    root: &Path,
    expected_platform: &str,
    expected_architecture: &str,
    executable_name: &str,
) -> Result<VerifiedBundle, String> {
    verify_bundle_inner(
        root,
        expected_platform,
        expected_architecture,
        executable_name,
        None,
    )
}

fn verify_bundle_inner(
    root: &Path,
    expected_platform: &str,
    expected_architecture: &str,
    executable_name: &str,
    trusted_manifest_sha256: Option<&str>,
) -> Result<VerifiedBundle, String> {
    let root_handle = open_directory(root, "resource root")?;
    let mut manifest_file = open_bundle_file(
        root,
        &root_handle,
        Path::new(MANIFEST_NAME),
        "resource manifest",
    )?;
    let manifest_metadata = manifest_file
        .metadata()
        .map_err(|_| "resource manifest metadata is unavailable")?;
    if manifest_metadata.len() == 0 || manifest_metadata.len() > MAX_MANIFEST_BYTES {
        return Err("resource manifest is not a bounded regular file".to_owned());
    }
    let mut bytes = Vec::with_capacity(manifest_metadata.len() as usize);
    manifest_file
        .read_to_end(&mut bytes)
        .map_err(|_| "resource manifest could not be read")?;
    if bytes.len() as u64 != manifest_metadata.len() {
        return Err("resource manifest changed while it was read".to_owned());
    }
    let manifest_sha256 = format!("{:x}", Sha256::digest(&bytes));
    if trusted_manifest_sha256.is_some_and(|trusted| trusted != manifest_sha256) {
        return Err("resource manifest does not match the compiled trust anchor".to_owned());
    }
    let manifest: Manifest =
        serde_json::from_slice(&bytes).map_err(|_| "resource manifest is invalid JSON")?;
    validate_header(&manifest, expected_platform, expected_architecture)?;
    if manifest.entries.is_empty() || manifest.entries.len() > MAX_ENTRIES {
        return Err("resource manifest has an invalid entry count".to_owned());
    }

    let mut expected = HashSet::with_capacity(manifest.entries.len());
    let mut expected_directories = HashSet::new();
    let mut protected_handles = vec![manifest_file];
    let mut has_executable = false;
    let mut executable_handle_index = None;
    #[cfg(unix)]
    let mut snapshot_files = Vec::new();
    #[cfg(unix)]
    let mut snapshot_symlinks = Vec::new();
    let mut symlink_targets = HashMap::new();
    let mut symlink_graph = HashMap::new();
    for entry in &manifest.entries {
        let relative = safe_inventory_path(entry.path())?;
        if !expected.insert(normalized(&relative)) {
            return Err("resource manifest contains duplicate paths".to_owned());
        }
        let mut parent = relative.parent();
        while let Some(directory) = parent.filter(|directory| !directory.as_os_str().is_empty()) {
            expected_directories.insert(normalized(directory));
            parent = directory.parent();
        }
        match entry {
            InventoryEntry::File { sha256, size, .. } => {
                let file = open_bundle_file(root, &root_handle, &relative, "inventoried file")?;
                let file = verify_file(file, *size, sha256)?;
                #[cfg(unix)]
                snapshot_files.push(SnapshotFile {
                    relative: relative.clone(),
                    handle_index: protected_handles.len(),
                    size: *size,
                    sha256: sha256.clone(),
                });
                if entry.path() == executable_name {
                    has_executable = true;
                    executable_handle_index = Some(protected_handles.len());
                    #[cfg(unix)]
                    verify_executable_mode(&file)?;
                }
                protected_handles.push(file);
            }
            InventoryEntry::Symlink { target, .. } => {
                #[cfg(windows)]
                if trusted_manifest_sha256.is_some() {
                    return Err(
                        "runtime resource bundles cannot contain redirected entries".to_owned()
                    );
                }
                #[cfg(windows)]
                {
                    let recorded_target = verify_symlink(&root.join(&relative), target)?;
                    symlink_targets.insert(relative.clone(), recorded_target);
                }
                #[cfg(unix)]
                {
                    let recorded_target = verify_symlink_at(&root_handle, &relative, target)?;
                    symlink_targets.insert(relative.clone(), PathBuf::from(&recorded_target));
                    snapshot_symlinks.push(SnapshotSymlink {
                        relative: relative.clone(),
                        target: recorded_target,
                        resolved_target: PathBuf::new(),
                    });
                }
            }
        }
    }
    if !has_executable {
        return Err("resource manifest does not inventory the fixed executable".to_owned());
    }
    let normalized_symlink_targets = normalized_symlink_target_index(&symlink_targets)?;
    for (relative, target) in &symlink_targets {
        let resolved = resolve_signed_symlink_target(
            relative,
            target,
            &normalized_symlink_targets,
            &expected,
            &expected_directories,
        )?;
        symlink_graph.insert(normalized(relative), normalized(&resolved));
        #[cfg(unix)]
        if let Some(link) = snapshot_symlinks
            .iter_mut()
            .find(|link| link.relative == *relative)
        {
            link.resolved_target = resolved;
        }
    }
    validate_symbolic_link_graph(&symlink_graph, &expected, &expected_directories)?;

    let mut actual = HashSet::new();
    let mut actual_directories = HashSet::new();
    #[cfg(windows)]
    collect_actual_windows(
        root,
        root,
        &mut actual,
        &mut actual_directories,
        &mut protected_handles,
    )?;
    #[cfg(unix)]
    collect_actual_unix(
        &root_handle,
        Path::new(""),
        0,
        &mut actual,
        &mut actual_directories,
        &mut protected_handles,
    )?;
    actual.remove(&normalized(Path::new(MANIFEST_NAME)));
    if actual != expected || actual_directories != expected_directories {
        return Err("resource inventory does not match the staged tree".to_owned());
    }
    #[cfg(unix)]
    let runtime_snapshot = if trusted_manifest_sha256.is_some() {
        let snapshot = materialize_runtime_snapshot(
            &bytes,
            &snapshot_files,
            &snapshot_symlinks,
            &protected_handles,
            &expected,
            &expected_directories,
            executable_name,
        )?;
        let executable = open_regular_file(&snapshot.executable, "runtime snapshot executable")?;
        let snapshot_root = open_directory(&snapshot.root, "runtime snapshot root")?;
        protected_handles.clear();
        executable_handle_index = Some(0);
        protected_handles.push(executable);
        protected_handles.push(snapshot_root);
        Some(snapshot)
    } else {
        protected_handles.push(root_handle);
        None
    };
    #[cfg(windows)]
    protected_handles.push(root_handle);
    Ok(VerifiedBundle {
        manifest_sha256,
        _protected_handles: protected_handles,
        executable_handle_index: executable_handle_index
            .ok_or_else(|| "verified executable handle is unavailable".to_owned())?,
        #[cfg(unix)]
        runtime_snapshot,
    })
}

#[allow(dead_code)] // The build-script copy only emits the digest; the runtime copy calls this.
pub fn verify_runtime_bundle(
    root: &Path,
    expected_platform: &str,
    expected_architecture: &str,
    executable_name: &str,
    trusted_manifest_sha256: &str,
) -> Result<VerifiedBundle, String> {
    if trusted_manifest_sha256.len() != 64
        || !trusted_manifest_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("compiled resource manifest digest is invalid".to_owned());
    }
    verify_bundle_inner(
        root,
        expected_platform,
        expected_architecture,
        executable_name,
        Some(trusted_manifest_sha256),
    )
}

fn validate_header(
    manifest: &Manifest,
    expected_platform: &str,
    expected_architecture: &str,
) -> Result<(), String> {
    let manifest_architecture = normalized_architecture(&manifest.architecture)
        .ok_or_else(|| "resource manifest architecture is unsupported".to_owned())?;
    let expected_architecture = normalized_architecture(expected_architecture)
        .ok_or_else(|| "release target architecture is unsupported".to_owned())?;
    if manifest.format != "pyinstaller-onedir"
        || manifest.pyinstaller != "6.18.0"
        || manifest.source_date_epoch != "1700000000"
        || manifest.platform != expected_platform
        || manifest_architecture != expected_architecture
    {
        return Err("resource manifest target or builder metadata is invalid".to_owned());
    }
    if manifest.python.is_empty()
        || manifest.python.len() > 32
        || !manifest
            .python
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || !manifest.python.bytes().any(|byte| byte == b'.')
    {
        return Err("resource manifest Python version is invalid".to_owned());
    }
    Ok(())
}

fn normalized_architecture(value: &str) -> Option<&'static str> {
    match value.to_ascii_lowercase().as_str() {
        "amd64" | "x64" | "x86_64" => Some("x86_64"),
        "arm64" | "aarch64" => Some("aarch64"),
        _ => None,
    }
}

fn safe_inventory_path(value: &str) -> Result<PathBuf, String> {
    if value.is_empty() || value == MANIFEST_NAME || value.contains('\\') {
        return Err("resource manifest contains an unsafe path".to_owned());
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("resource manifest contains an unsafe path".to_owned());
    }
    Ok(path.to_owned())
}

#[cfg(windows)]
fn open_bundle_file(
    root: &Path,
    _root_handle: &File,
    relative: &Path,
    description: &'static str,
) -> Result<File, String> {
    open_regular_file(&root.join(relative), description)
}

#[cfg(unix)]
fn open_bundle_file(
    _root: &Path,
    root_handle: &File,
    relative: &Path,
    description: &'static str,
) -> Result<File, String> {
    let (parent, name) = open_parent_directory_at(root_handle, relative, description)?;
    let name = c_path_component(&name, description)?;
    // SAFETY: `parent` and `name` are live; flags reject a symlink at the final component.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(format!(
            "{description} could not be opened without following links"
        ));
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(descriptor) };
    validate_regular_handle(file, description)
}

#[cfg(unix)]
fn open_parent_directory_at(
    root_handle: &File,
    relative: &Path,
    description: &'static str,
) -> Result<(File, OsString), String> {
    let mut components = relative.components().peekable();
    let mut directory = root_handle
        .try_clone()
        .map_err(|_| format!("{description} root handle could not be cloned"))?;
    let mut final_name = None;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(format!("{description} contains an unsafe path component"));
        };
        if components.peek().is_none() {
            final_name = Some(name.to_os_string());
            break;
        }
        let name = c_path_component(name, description)?;
        // SAFETY: the current directory descriptor and component are live; O_NOFOLLOW rejects
        // intermediate symlinks and O_DIRECTORY requires a directory at each step.
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(format!(
                "{description} parent could not be opened without following links"
            ));
        }
        // SAFETY: openat returned a new owned descriptor.
        directory = unsafe { File::from_raw_fd(descriptor) };
    }
    final_name
        .map(|name| (directory, name))
        .ok_or_else(|| format!("{description} has no final path component"))
}

#[cfg(unix)]
fn c_path_component(
    value: impl AsRef<std::ffi::OsStr>,
    description: &'static str,
) -> Result<CString, String> {
    CString::new(value.as_ref().as_bytes())
        .map_err(|_| format!("{description} contains an invalid path component"))
}

fn validate_regular_handle(file: File, description: &'static str) -> Result<File, String> {
    let metadata = file
        .metadata()
        .map_err(|_| format!("{description} metadata is unavailable"))?;
    if !metadata.is_file() || metadata_is_redirect(&metadata) {
        return Err(format!("{description} is not a real regular file"));
    }
    Ok(file)
}

fn open_regular_file(path: &Path, description: &'static str) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;

        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|_| format!("{description} could not be opened without following links"))?;
    validate_regular_handle(file, description)
}

fn open_directory(path: &Path, description: &'static str) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;

        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|_| format!("{description} could not be opened without following links"))?;
    let metadata = file
        .metadata()
        .map_err(|_| format!("{description} metadata is unavailable"))?;
    if !metadata.is_dir() || metadata_is_redirect(&metadata) {
        return Err(format!("{description} is not a real directory"));
    }
    Ok(file)
}

#[cfg(windows)]
fn metadata_is_redirect(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_redirect(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn verify_file(mut file: File, expected_size: u64, expected_hash: &str) -> Result<File, String> {
    let metadata = file
        .metadata()
        .map_err(|_| "inventoried file metadata is unavailable")?;
    if metadata.len() != expected_size
        || expected_hash.len() != 64
        || !expected_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("inventoried file metadata is invalid".to_owned());
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| "inventoried file could not be read")?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    if format!("{:x}", digest.finalize()) != expected_hash {
        return Err("inventoried file digest does not match".to_owned());
    }
    Ok(file)
}

#[cfg(unix)]
fn verify_executable_mode(file: &File) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    if file
        .metadata()
        .map_err(|_| "fixed executable metadata is unavailable")?
        .permissions()
        .mode()
        & 0o111
        == 0
    {
        return Err("fixed executable is not executable".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn verify_symlink_at(
    root_handle: &File,
    relative: &Path,
    expected_target: &str,
) -> Result<OsString, String> {
    if expected_target.is_empty()
        || expected_target.as_bytes().contains(&0)
        || Path::new(expected_target).is_absolute()
    {
        return Err("inventoried symlink metadata is invalid".to_owned());
    }
    let (parent, name) = open_parent_directory_at(root_handle, relative, "inventoried symlink")?;
    let name = c_path_component(&name, "inventoried symlink")?;
    let mut buffer = vec![0_u8; 4096];
    // SAFETY: the parent descriptor, name, and writable buffer are live for this call.
    let count = unsafe {
        libc::readlinkat(
            parent.as_raw_fd(),
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    };
    if count <= 0 || count as usize == buffer.len() {
        return Err("inventoried symlink could not be read safely".to_owned());
    }
    buffer.truncate(count as usize);
    if buffer != expected_target.as_bytes() {
        return Err("inventoried symlink target changed".to_owned());
    }
    let target = OsString::from_vec(buffer);
    Ok(target)
}

fn resolve_signed_symlink_target(
    relative: &Path,
    target: &Path,
    normalized_links: &HashMap<String, PathBuf>,
    expected: &HashSet<String>,
    expected_directories: &HashSet<String>,
) -> Result<PathBuf, String> {
    let mut resolved = relative
        .parent()
        .ok_or_else(|| "inventoried symlink has no parent".to_owned())?
        .to_owned();
    let mut pending = signed_target_components(target)?;
    let mut seen_states: HashSet<(PathBuf, Vec<Option<OsString>>)> = HashSet::new();
    let mut symlink_follows = 0_usize;
    for _ in 0..MAX_SYMLINK_EXPANSIONS {
        if pending.len() > MAX_SYMLINK_PENDING_COMPONENTS {
            return Err("inventoried symlink target has too many pending components".to_owned());
        }
        if !seen_states.insert((resolved.clone(), pending.clone())) {
            return Err("inventoried symlink graph contains a cycle".to_owned());
        }
        let Some(component) = pending.first().cloned() else {
            if resolved.as_os_str().is_empty() {
                return Err("inventoried symlink escapes the resource tree".to_owned());
            }
            let key = normalized(&resolved);
            if expected.contains(&key) || expected_directories.contains(&key) {
                return Ok(resolved);
            }
            return Err("inventoried symlink target is not in the signed inventory".to_owned());
        };
        pending.remove(0);
        let Some(component) = component else {
            if resolved.as_os_str().is_empty()
                || !expected_directories.contains(&normalized(&resolved))
            {
                return Err("inventoried symlink target is not a directory".to_owned());
            }
            continue;
        };
        if component.as_os_str() == OsStr::new(".") {
            continue;
        }
        if component.as_os_str() == OsStr::new("..") {
            if !resolved.pop() {
                return Err("inventoried symlink escapes the resource tree".to_owned());
            }
            continue;
        }
        let candidate = resolved.join(&component);
        let candidate_key = normalized(&candidate);
        if let Some(link_target) = normalized_links.get(&candidate_key) {
            symlink_follows += 1;
            if symlink_follows > MAX_SYMLINK_FOLLOWS {
                return Err("inventoried symlink target follows too many symbolic links".to_owned());
            }
            let mut replacement = signed_target_components(link_target)?;
            replacement.extend(pending);
            pending = replacement;
            continue;
        }
        let key = candidate_key;
        let is_directory = expected_directories.contains(&key);
        if !expected.contains(&key) && !is_directory {
            return Err("inventoried symlink target is not in the signed inventory".to_owned());
        }
        if !is_directory && pending.first().is_some_and(Option::is_some) {
            return Err(
                "inventoried symlink target contains a non-directory intermediate".to_owned(),
            );
        }
        resolved.push(component);
        if resolved.components().count() > MAX_DIRECTORY_DEPTH {
            return Err("inventoried symlink target is too deep".to_owned());
        }
    }
    Err("inventoried symlink graph contains too many expansions".to_owned())
}

pub(crate) fn normalized_symlink_target_index(
    links: &HashMap<PathBuf, PathBuf>,
) -> Result<HashMap<String, PathBuf>, String> {
    let mut normalized_links = HashMap::with_capacity(links.len());
    for (link, target) in links {
        if normalized_links
            .insert(normalized(link), target.clone())
            .is_some()
        {
            return Err(
                "inventoried symlink graph contains a normalized path collision".to_owned(),
            );
        }
    }
    Ok(normalized_links)
}

fn target_requires_directory(target: &Path) -> bool {
    let raw = target.to_string_lossy();
    if cfg!(windows) {
        let stripped = raw.trim_end_matches(['/', '\\']);
        raw.ends_with('/')
            || raw.ends_with('\\')
            || stripped.ends_with("/.")
            || stripped.ends_with("\\.")
    } else {
        let stripped = raw.trim_end_matches('/');
        raw.ends_with('/') || stripped.ends_with("/.")
    }
}

fn signed_target_components(path: &Path) -> Result<Vec<Option<OsString>>, String> {
    let mut components = signed_path_components(path)?
        .into_iter()
        .map(Some)
        .collect::<Vec<_>>();
    if target_requires_directory(path) {
        components.push(None);
    }
    Ok(components)
}

fn signed_path_components(path: &Path) -> Result<Vec<OsString>, String> {
    path.components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value.to_os_string()),
            Component::CurDir => Ok(OsString::from(".")),
            Component::ParentDir => Ok(OsString::from("..")),
            Component::RootDir | Component::Prefix(_) => {
                Err("inventoried symlink escapes the resource tree".to_owned())
            }
        })
        .collect()
}

#[cfg(unix)]
fn materialize_runtime_snapshot(
    manifest_bytes: &[u8],
    files: &[SnapshotFile],
    symlinks: &[SnapshotSymlink],
    source_handles: &[File],
    expected: &HashSet<String>,
    expected_directories: &HashSet<String>,
    executable_name: &str,
) -> Result<RuntimeSnapshot, String> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink};

    let snapshot = create_runtime_snapshot(executable_name)?;

    for file in files {
        if let Some(parent) = file.relative.parent() {
            fs::create_dir_all(snapshot.root.join(parent))
                .map_err(|_| "runtime snapshot directory could not be created")?;
        }
    }
    for link in symlinks {
        if let Some(parent) = link.relative.parent() {
            fs::create_dir_all(snapshot.root.join(parent))
                .map_err(|_| "runtime snapshot directory could not be created")?;
        }
    }

    let manifest_path = snapshot.root.join(MANIFEST_NAME);
    let mut manifest_options = OpenOptions::new();
    manifest_options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut manifest = manifest_options
        .open(&manifest_path)
        .map_err(|_| "runtime snapshot manifest could not be created")?;
    manifest
        .write_all(manifest_bytes)
        .and_then(|()| manifest.flush())
        .map_err(|_| "runtime snapshot manifest could not be written")?;
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o400))
        .map_err(|_| "runtime snapshot manifest permissions could not be restricted")?;

    for file in files {
        let source = source_handles
            .get(file.handle_index)
            .ok_or_else(|| "runtime snapshot source handle is unavailable".to_owned())?;
        copy_snapshot_file(
            source,
            &snapshot.root.join(&file.relative),
            file.size,
            &file.sha256,
        )?;
    }
    for link in symlinks {
        symlink(&link.target, snapshot.root.join(&link.relative))
            .map_err(|_| "runtime snapshot symlink could not be created")?;
    }

    let root_handle = open_directory(&snapshot.root, "runtime snapshot root")?;
    let mut snapshot_links = HashMap::new();
    for link in symlinks {
        let expected_target = link
            .target
            .to_str()
            .ok_or_else(|| "runtime snapshot symlink target is not UTF-8".to_owned())?;
        let recorded_target = verify_symlink_at(&root_handle, &link.relative, expected_target)?;
        if recorded_target != link.target {
            return Err("runtime snapshot symlink target changed".to_owned());
        }
        snapshot_links.insert(link.relative.clone(), PathBuf::from(recorded_target));
    }
    let normalized_snapshot_links = normalized_symlink_target_index(&snapshot_links)?;
    let mut snapshot_graph = HashMap::new();
    for link in symlinks {
        let target = snapshot_links.get(&link.relative).ok_or_else(|| {
            "runtime snapshot symlink is missing from the signed graph".to_owned()
        })?;
        let resolved = resolve_signed_symlink_target(
            &link.relative,
            target,
            &normalized_snapshot_links,
            expected,
            expected_directories,
        )?;
        if resolved != link.resolved_target {
            return Err("runtime snapshot symlink graph changed".to_owned());
        }
        snapshot_graph.insert(normalized(&link.relative), normalized(&resolved));
    }
    validate_symbolic_link_graph(&snapshot_graph, expected, expected_directories)?;
    let mut actual = HashSet::new();
    let mut actual_directories = HashSet::new();
    let mut inventory_handles = Vec::new();
    collect_actual_unix(
        &root_handle,
        Path::new(""),
        0,
        &mut actual,
        &mut actual_directories,
        &mut inventory_handles,
    )?;
    actual.remove(&normalized(Path::new(MANIFEST_NAME)));
    if &actual != expected || &actual_directories != expected_directories {
        return Err("runtime snapshot inventory does not match the signed tree".to_owned());
    }
    let executable = open_regular_file(&snapshot.executable, "runtime snapshot executable")?;
    verify_executable_mode(&executable)?;
    Ok(snapshot)
}

#[cfg(unix)]
fn create_runtime_snapshot(executable_name: &str) -> Result<RuntimeSnapshot, String> {
    use std::os::unix::fs::DirBuilderExt as _;

    let parent = runtime_snapshot_parent()?;
    recover_stale_runtime_snapshots(&parent)?;
    let mut template = parent.join("lock-XXXXXX").as_os_str().as_bytes().to_vec();
    template.push(0);
    // SAFETY: the mutable template is NUL terminated and ends with the six required X bytes.
    let descriptor = unsafe { libc::mkstemp(template.as_mut_ptr().cast()) };
    if descriptor < 0 {
        return Err("runtime snapshot reservation could not be created".to_owned());
    }
    // SAFETY: mkstemp returned a new exclusively owned descriptor.
    let mut owner_lock = unsafe { File::from_raw_fd(descriptor) };
    // SAFETY: the descriptor is live. Preserving its existing flags and adding CLOEXEC prevents
    // the engine or its descendants from retaining snapshot ownership after broker death.
    let descriptor_flags = unsafe { libc::fcntl(owner_lock.as_raw_fd(), libc::F_GETFD) };
    if descriptor_flags < 0
        || unsafe {
            libc::fcntl(
                owner_lock.as_raw_fd(),
                libc::F_SETFD,
                descriptor_flags | libc::FD_CLOEXEC,
            )
        } < 0
    {
        return Err("runtime snapshot reservation could not be restricted".to_owned());
    }
    // SAFETY: the live private lock descriptor is exclusively owned by this snapshot.
    if unsafe { libc::flock(owner_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("runtime snapshot reservation could not be locked".to_owned());
    }
    owner_lock
        .write_all(b"ready\n")
        .and_then(|()| owner_lock.flush())
        .map_err(|_| "runtime snapshot reservation could not be marked ready")?;
    let lock_path = PathBuf::from(OsString::from_vec(
        // SAFETY: mkstemp rewrote the live template to a NUL-terminated path.
        unsafe { CStr::from_ptr(template.as_ptr().cast()) }
            .to_bytes()
            .to_vec(),
    ));
    let token = lock_path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("lock-"))
        .filter(|token| token.len() == 6 && token.bytes().all(|byte| byte.is_ascii_alphanumeric()))
        .ok_or_else(|| "runtime snapshot reservation name is invalid".to_owned())?;
    let root = parent.join(format!("tree-{token}"));
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    if builder.create(&root).is_err() {
        let _ = fs::remove_file(&lock_path);
        return Err("runtime snapshot root could not be created".to_owned());
    }
    Ok(RuntimeSnapshot {
        executable: root.join(executable_name),
        root,
        lock_path,
        _owner_lock: owner_lock,
    })
}

#[cfg(unix)]
fn runtime_snapshot_parent() -> Result<PathBuf, String> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};

    // SAFETY: geteuid has no preconditions and returns the effective user identity.
    let effective_user = unsafe { libc::geteuid() };
    let parent =
        std::env::temp_dir().join(format!("zombie-killer-engine-runtime-{effective_user}"));
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(&parent) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err("runtime snapshot parent could not be created".to_owned()),
    }
    let handle = open_directory(&parent, "runtime snapshot parent")?;
    let metadata = handle
        .metadata()
        .map_err(|_| "runtime snapshot parent metadata is unavailable")?;
    if metadata.uid() != effective_user || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err("runtime snapshot parent ownership or permissions are invalid".to_owned());
    }
    Ok(parent)
}

#[cfg(unix)]
pub(crate) fn recover_stale_runtime_snapshots(parent: &Path) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let entries =
        fs::read_dir(parent).map_err(|_| "runtime snapshot parent could not be enumerated")?;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_ENTRIES {
            return Err("runtime snapshot parent contains too many entries".to_owned());
        }
        let entry = entry.map_err(|_| "runtime snapshot entry could not be read")?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(token) = name.strip_prefix("lock-") else {
            continue;
        };
        if token.len() != 6 || !token.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            continue;
        }
        let path = entry.path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err("runtime snapshot lock metadata is unavailable".to_owned()),
        };
        if !metadata.is_file() || metadata_is_redirect(&metadata) {
            continue;
        }
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let lock = match options.open(&path) {
            Ok(lock) => lock,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err(
                    "runtime snapshot lock could not be opened without following links".to_owned(),
                );
            }
        };
        let mut lock = validate_regular_handle(lock, "runtime snapshot lock")?;
        if lock
            .metadata()
            .map_err(|_| "runtime snapshot lock metadata is unavailable")?
            .len()
            != 6
        {
            continue;
        }
        // SAFETY: the descriptor is live. A nonblocking exclusive lock succeeds only when no
        // broker still owns the corresponding execution tree.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            continue;
        }
        let mut marker = Vec::with_capacity(6);
        lock.read_to_end(&mut marker)
            .map_err(|_| "runtime snapshot lock could not be read")?;
        if marker != b"ready\n" {
            continue;
        }
        let tree = parent.join(format!("tree-{token}"));
        match fs::symlink_metadata(&tree) {
            Ok(tree_metadata)
                if tree_metadata.is_dir() && !metadata_is_redirect(&tree_metadata) =>
            {
                match fs::remove_dir_all(&tree) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => {
                        return Err("stale runtime snapshot could not be removed".to_owned());
                    }
                }
            }
            Ok(_) => return Err("stale runtime snapshot has an invalid type".to_owned()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("stale runtime snapshot metadata is unavailable".to_owned()),
        }
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("stale runtime snapshot lock could not be removed".to_owned()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn copy_snapshot_file(
    source: &File,
    destination: &Path,
    expected_size: u64,
    expected_hash: &str,
) -> Result<(), String> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let mut source = source
        .try_clone()
        .map_err(|_| "runtime snapshot source handle could not be cloned")?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| "runtime snapshot source could not be rewound")?;
    let source_mode = source
        .metadata()
        .map_err(|_| "runtime snapshot source metadata is unavailable")?
        .permissions()
        .mode();
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut destination_file = options
        .open(destination)
        .map_err(|_| "runtime snapshot file could not be created")?;
    let copied = std::io::copy(&mut source, &mut destination_file)
        .map_err(|_| "runtime snapshot file could not be copied")?;
    if copied != expected_size {
        return Err("runtime snapshot file size does not match".to_owned());
    }
    destination_file
        .flush()
        .map_err(|_| "runtime snapshot file could not be flushed")?;
    drop(destination_file);
    let destination_file = open_regular_file(destination, "runtime snapshot file")?;
    drop(verify_file(destination_file, expected_size, expected_hash)?);
    let restricted_mode = (source_mode & 0o555) | 0o400;
    fs::set_permissions(destination, fs::Permissions::from_mode(restricted_mode))
        .map_err(|_| "runtime snapshot file permissions could not be restricted")?;
    Ok(())
}

#[cfg(windows)]
fn verify_symlink(path: &Path, target: &str) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "inventoried symlink is missing")?;
    if !metadata.file_type().is_symlink() || target.is_empty() || Path::new(target).is_absolute() {
        return Err("inventoried symlink metadata is invalid".to_owned());
    }
    let recorded = fs::read_link(path).map_err(|_| "inventoried symlink could not be read")?;
    if normalized(&recorded) != normalized(Path::new(target)) {
        return Err("inventoried symlink target changed".to_owned());
    }
    Ok(recorded)
}
#[cfg(windows)]
pub(crate) fn insert_actual_windows_path(
    output: &mut HashSet<String>,
    directories: &mut HashSet<String>,
    relative: &Path,
    is_directory: bool,
) -> Result<(), String> {
    let key = normalized(relative);
    if output.contains(&key) || directories.contains(&key) {
        return Err("resource tree contains a normalized path collision".to_owned());
    }
    if is_directory {
        directories.insert(key);
    } else {
        output.insert(key);
    }
    Ok(())
}

#[cfg(windows)]
fn collect_actual_windows(
    root: &Path,
    directory: &Path,
    output: &mut HashSet<String>,
    directories: &mut HashSet<String>,
    protected_handles: &mut Vec<File>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|_| "resource directory could not be read")? {
        let entry = entry.map_err(|_| "resource directory entry could not be read")?;
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| "resource entry metadata is unavailable")?;
        if metadata_is_redirect(&metadata) {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "resource entry escaped the resource tree")?;
            insert_actual_windows_path(output, directories, relative, false)?;
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "resource entry escaped the resource tree")?;
        if metadata.is_file() {
            insert_actual_windows_path(output, directories, relative, false)?;
        } else if metadata.is_dir() {
            let handle = open_directory(&path, "resource directory")?;
            insert_actual_windows_path(output, directories, relative, true)?;
            collect_actual_windows(root, &path, output, directories, protected_handles)?;
            protected_handles.push(handle);
        } else {
            return Err("resource tree contains an unsupported entry".to_owned());
        }
        if output.len().saturating_add(directories.len()) > MAX_ENTRIES.saturating_mul(2) + 1 {
            return Err("resource tree contains too many entries".to_owned());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn collect_actual_unix(
    directory: &File,
    relative_directory: &Path,
    depth: usize,
    output: &mut HashSet<String>,
    directories: &mut HashSet<String>,
    protected_handles: &mut Vec<File>,
) -> Result<(), String> {
    if depth > MAX_DIRECTORY_DEPTH {
        return Err("resource tree nesting is too deep".to_owned());
    }
    // fdopendir owns and closes its descriptor, so enumerate through a duplicate.
    // SAFETY: `directory` is a live directory descriptor.
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err("resource directory handle could not be duplicated".to_owned());
    }
    // SAFETY: `duplicate` is a newly owned directory descriptor.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        // SAFETY: fdopendir did not take ownership on failure.
        unsafe { libc::close(duplicate) };
        return Err("resource directory could not be enumerated".to_owned());
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: `stream` remains live until closed below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: POSIX dirent d_name is a NUL-terminated array for this live entry.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            if names.len() >= MAX_ENTRIES {
                // SAFETY: fdopendir owns the duplicated descriptor and closedir releases it.
                unsafe { libc::closedir(stream) };
                return Err("resource directory contains too many entries".to_owned());
            }
            names.push(OsString::from_vec(name.to_vec()));
        }
    }
    // SAFETY: fdopendir owns the duplicated descriptor and closedir releases both resources.
    if unsafe { libc::closedir(stream) } != 0 {
        return Err("resource directory could not be closed".to_owned());
    }

    for name in names {
        let name_c = c_path_component(&name, "resource entry")?;
        // SAFETY: directory/name are live and AT_SYMLINK_NOFOLLOW inspects the entry itself.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name_c.as_ptr(),
                std::ptr::addr_of_mut!(stat),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err("resource entry metadata is unavailable".to_owned());
        }
        let relative = relative_directory.join(&name);
        let kind = stat.st_mode & libc::S_IFMT;
        if kind == libc::S_IFREG || kind == libc::S_IFLNK {
            output.insert(normalized(&relative));
        } else if kind == libc::S_IFDIR {
            // SAFETY: the parent/name are live; flags reject redirected intermediate directories.
            let descriptor = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name_c.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                )
            };
            if descriptor < 0 {
                return Err("resource directory could not be opened safely".to_owned());
            }
            // SAFETY: openat returned a new owned descriptor.
            let child = unsafe { File::from_raw_fd(descriptor) };
            directories.insert(normalized(&relative));
            collect_actual_unix(
                &child,
                &relative,
                depth + 1,
                output,
                directories,
                protected_handles,
            )?;
            protected_handles.push(child);
        } else {
            return Err("resource tree contains an unsupported entry".to_owned());
        }
        if output.len().saturating_add(directories.len()) > MAX_ENTRIES.saturating_mul(2) + 1 {
            return Err("resource tree contains too many entries".to_owned());
        }
    }
    Ok(())
}

fn normalized(path: &Path) -> String {
    #[cfg(windows)]
    {
        path.to_string_lossy().replace('\\', "/").to_lowercase()
    }
    #[cfg(unix)]
    {
        use std::fmt::Write as _;

        let bytes = path.as_os_str().as_bytes();
        let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
        }
        encoded
    }
}
