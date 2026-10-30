use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
#[cfg(any(debug_assertions, test))]
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::time::Duration;
#[cfg(unix)]
use std::{os::fd::AsRawFd, os::unix::net::UnixStream};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, oneshot};
use tokio::time::timeout;
use uuid::Uuid;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
#[cfg(windows)]
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, GetProcessIdOfThread, OpenThread, ResumeThread,
    THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
};

use crate::resource_manifest::{VerifiedBundle, verify_runtime_bundle};

const PROTOCOL_VERSION: &str = "1.0";
const MAX_RENDERER_REQUEST_BYTES: usize = 128 * 1024;
const MAX_ENGINE_INPUT_BYTES: usize = 1024 * 1024;
const MAX_ENGINE_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_ENGINE_STDERR_BYTES: usize = 64 * 1024;
const REAP_TIMEOUT: Duration = Duration::from_secs(5);

fn deserialize_non_null_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[cfg(test)]
static TEST_ENGINE_PROCESS_GATE: Mutex<()> = Mutex::const_new(());

#[cfg(all(test, unix))]
static TEST_DELAY_CHILD_TO_CONTAINMENT_DROP: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(all(test, unix))]
struct TestChildToContainmentDropDelay;

#[cfg(all(test, unix))]
impl Drop for TestChildToContainmentDropDelay {
    fn drop(&mut self) {
        if TEST_DELAY_CHILD_TO_CONTAINMENT_DROP.swap(false, std::sync::atomic::Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

#[cfg(all(test, unix))]
pub(crate) fn arm_child_to_containment_drop_delay_for_test() {
    TEST_DELAY_CHILD_TO_CONTAINMENT_DROP.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(windows)]
struct OwnedKernelHandle(HANDLE);

#[cfg(windows)]
impl Drop for OwnedKernelHandle {
    fn drop(&mut self) {
        // SAFETY: this type is constructed only from live, exclusively owned kernel handles.
        unsafe { CloseHandle(self.0) };
    }
}

#[cfg(windows)]
pub(crate) struct ChildContainment(OwnedKernelHandle);

// SAFETY: Windows kernel handles are process-scoped and may be closed from any thread.
#[cfg(windows)]
unsafe impl Send for ChildContainment {}

#[cfg(windows)]
impl Drop for ChildContainment {
    fn drop(&mut self) {
        // `OwnedKernelHandle` closes the job. KILL_ON_JOB_CLOSE terminates every contained process.
    }
}

#[cfg(windows)]
impl ChildContainment {
    pub(crate) fn prepare(command: &mut Command) -> Result<Self, BrokerError> {
        // SAFETY: null security attributes and name request a private job object owned by this process.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(BrokerError::engine_unavailable());
        }
        let job = OwnedKernelHandle(job);
        // SAFETY: the Windows structure is plain data and all-zero is its documented initial state.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `limits` is initialized, sized correctly, and remains alive for the call.
        if unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(limits).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(BrokerError::engine_unavailable());
        }
        command.creation_flags(CREATE_NO_WINDOW | CREATE_SUSPENDED);
        Ok(Self(job))
    }

    pub(crate) fn activate(&self, child: &Child) -> Result<(), BrokerError> {
        let process = child
            .raw_handle()
            .ok_or_else(BrokerError::engine_unavailable)? as HANDLE;
        // SAFETY: both handles are live and remain owned by their respective RAII wrappers.
        if unsafe { AssignProcessToJobObject(self.0.0, process) } == 0 {
            return Err(BrokerError::engine_unavailable());
        }
        let pid = child.id().ok_or_else(BrokerError::engine_unavailable)?;
        resume_initial_thread(pid)
    }
}

#[cfg(windows)]
fn resume_initial_thread(pid: u32) -> Result<(), BrokerError> {
    // SAFETY: the snapshot has no inherited handle and is closed by OwnedKernelHandle.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(BrokerError::engine_unavailable());
    }
    let snapshot = OwnedKernelHandle(snapshot);
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..THREADENTRY32::default()
    };
    let mut thread_id = None;
    // SAFETY: `entry` is initialized with the required size and remains writable for enumeration.
    let mut available = unsafe { Thread32First(snapshot.0, std::ptr::addr_of_mut!(entry)) } != 0;
    while available {
        if entry.th32OwnerProcessID == pid && thread_id.replace(entry.th32ThreadID).is_some() {
            return Err(BrokerError::engine_unavailable());
        }
        // SAFETY: the snapshot and entry remain valid for the duration of enumeration.
        available = unsafe { Thread32Next(snapshot.0, std::ptr::addr_of_mut!(entry)) } != 0;
    }
    let thread_id = thread_id.ok_or_else(BrokerError::engine_unavailable)?;
    // SAFETY: access is limited to identity verification and resuming the selected thread.
    let thread = unsafe {
        OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
            0,
            thread_id,
        )
    };
    if thread.is_null() {
        return Err(BrokerError::engine_unavailable());
    }
    let thread = OwnedKernelHandle(thread);
    // SAFETY: the opened thread handle is live; the PID check prevents thread-id reuse confusion.
    if unsafe { GetProcessIdOfThread(thread.0) } != pid {
        return Err(BrokerError::engine_unavailable());
    }
    // SAFETY: this broker created the process with one CREATE_SUSPENDED count.
    if unsafe { ResumeThread(thread.0) } != 1 {
        return Err(BrokerError::engine_unavailable());
    }
    Ok(())
}

#[cfg(unix)]
const BROKER_LIVENESS_FD: i32 = 198;

#[cfg(unix)]
struct UnixChildContainment {
    reader: Option<UnixStream>,
    writer: Option<UnixStream>,
    process_group: Option<i32>,
}

#[cfg(unix)]
impl UnixChildContainment {
    fn prepare(command: &mut Command) -> Result<Self, BrokerError> {
        let (reader, writer) = UnixStream::pair().map_err(|_| BrokerError::engine_unavailable())?;
        let reader_fd = reader.as_raw_fd();
        command.env("ZK_PARENT_FD", BROKER_LIVENESS_FD.to_string());
        // SAFETY: the closure calls only async-signal-safe libc functions between fork and exec.
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if reader_fd == BROKER_LIVENESS_FD {
                    if libc::fcntl(BROKER_LIVENESS_FD, libc::F_SETFD, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                } else if libc::dup2(reader_fd, BROKER_LIVENESS_FD) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(Self {
            reader: Some(reader),
            writer: Some(writer),
            process_group: None,
        })
    }

    fn spawned(&mut self, child: &Child) -> Result<(), BrokerError> {
        self.reader.take();
        self.process_group = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .filter(|pid| *pid > 0);
        if self.process_group.is_none() {
            return Err(BrokerError::engine_unavailable());
        }
        Ok(())
    }

    fn terminate_group(&mut self) {
        self.writer.take();
        if let Some(process_group) = self.process_group.take() {
            // SAFETY: the child created a private process group whose positive id is still owned
            // by its unreaped leader. Taking the id prevents any later raw-PGID signal.
            unsafe { libc::kill(-process_group, libc::SIGKILL) };
        }
    }
}

#[cfg(unix)]
impl Drop for UnixChildContainment {
    fn drop(&mut self) {
        self.terminate_group();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EngineMethod {
    SystemInfo,
    Doctor,
    ScanList,
    AgentDetail,
    ActionPlan,
    ActionExecute,
    ActivityList,
    ReceiptGet,
    QuarantineList,
    QuarantineResourceList,
    QuarantinePlan,
    QuarantineExecute,
    QuarantineRestorePlan,
    QuarantineRestoreExecute,
    VaultList,
    VaultRegister,
    VaultProbe,
    VaultQuery,
    VaultGet,
    VaultMutationPlan,
    VaultMutationExecute,
    VaultSnapshotList,
    VaultRestorePlan,
    VaultRestoreExecute,
    SettingsGet,
    SettingsUpdate,
    DiagnosticsExportPlan,
    DiagnosticsExportExecute,
}

impl EngineMethod {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SystemInfo => "system.info",
            Self::Doctor => "doctor",
            Self::ScanList => "scan.list",
            Self::AgentDetail => "agent.detail",
            Self::ActionPlan => "action.plan",
            Self::ActionExecute => "action.execute",
            Self::ActivityList => "activity.list",
            Self::ReceiptGet => "receipt.get",
            Self::QuarantineList => "quarantine.list",
            Self::QuarantineResourceList => "quarantine.resource-list",
            Self::QuarantinePlan => "quarantine.plan",
            Self::QuarantineExecute => "quarantine.execute",
            Self::QuarantineRestorePlan => "quarantine.restore-plan",
            Self::QuarantineRestoreExecute => "quarantine.restore-execute",
            Self::VaultList => "vault.list",
            Self::VaultRegister => "vault.register",
            Self::VaultProbe => "vault.probe",
            Self::VaultQuery => "vault.query",
            Self::VaultGet => "vault.get",
            Self::VaultMutationPlan => "vault.mutation.plan",
            Self::VaultMutationExecute => "vault.mutation.execute",
            Self::VaultSnapshotList => "vault.snapshot.list",
            Self::VaultRestorePlan => "vault.restore.plan",
            Self::VaultRestoreExecute => "vault.restore.execute",
            Self::SettingsGet => "settings.get",
            Self::SettingsUpdate => "settings.update",
            Self::DiagnosticsExportPlan => "diagnostics.export-plan",
            Self::DiagnosticsExportExecute => "diagnostics.export-execute",
        }
    }

    pub(crate) fn timeout(self) -> Duration {
        match self {
            Self::ActionExecute
            | Self::VaultMutationExecute
            | Self::VaultRestoreExecute
            | Self::QuarantineExecute
            | Self::QuarantineRestoreExecute
            | Self::DiagnosticsExportExecute => Duration::from_secs(45),
            Self::ActionPlan
            | Self::VaultRegister
            | Self::VaultMutationPlan
            | Self::VaultRestorePlan
            | Self::QuarantinePlan
            | Self::QuarantineRestorePlan
            | Self::DiagnosticsExportPlan
            | Self::SettingsUpdate => Duration::from_secs(15),
            Self::ScanList => Duration::from_secs(45),
            Self::VaultQuery => Duration::from_secs(20),
            _ => Duration::from_secs(10),
        }
    }

    fn mutates(self) -> bool {
        matches!(
            self,
            Self::ActionPlan
                | Self::ActionExecute
                | Self::VaultRegister
                | Self::VaultMutationPlan
                | Self::VaultMutationExecute
                | Self::VaultRestorePlan
                | Self::VaultRestoreExecute
                | Self::QuarantinePlan
                | Self::QuarantineExecute
                | Self::QuarantineRestorePlan
                | Self::QuarantineRestoreExecute
                | Self::DiagnosticsExportPlan
                | Self::DiagnosticsExportExecute
                | Self::SettingsUpdate
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EmptyPayload {}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ScanPayload {
    include_unmanaged: bool,
    limit: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AgentPayload {
    agent_id: String,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    expected_pid: Option<u32>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    expected_process_instance_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ActionMode {
    RequestStop,
    Terminate,
    Kill,
}

impl ActionMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::RequestStop => "request_stop",
            Self::Terminate => "terminate",
            Self::Kill => "kill",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProcessTarget {
    pid: u32,
    process_instance_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ActionPlanPayload {
    agent_id: String,
    mode: ActionMode,
    target: ProcessTarget,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ExecutePayload {
    plan_id: String,
    digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PagePayload {
    limit: u16,
    cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VaultQueryPayload {
    source_id: String,
    namespace: Option<String>,
    text: Option<String>,
    limit: u16,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VaultGetPayload {
    source_id: String,
    record_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReceiptGetPayload {
    receipt_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RestorePlanPayload {
    entry_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VaultPathPayload {
    path: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum MutationOperation {
    UpdateContent,
    UpdateField,
    UpdateMetadata,
    ExcludeFromRetrieval,
    Quarantine,
    RestoreRecord,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(untagged)]
enum ScalarValue {
    Text(String),
    Number(serde_json::Number),
    Boolean(bool),
    #[default]
    Null,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VaultMutationPlanPayload {
    source_id: String,
    expected_revision: String,
    operation: MutationOperation,
    record_id: String,
    #[serde(default)]
    field: Option<String>,
    #[serde(default)]
    metadata_key: Option<String>,
    #[serde(default)]
    value: ScalarValue,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VaultSnapshotListPayload {
    source_id: String,
    limit: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VaultRestorePlanPayload {
    source_id: String,
    snapshot_id: String,
    snapshot_digest: String,
    expected_revision: String,
}

pub(crate) type ResourceListPayload = AgentPayload;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct QuarantinePlanPayload {
    agent_id: String,
    resource_index: u8,
    expected_declaration_digest: String,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    expected_pid: Option<u32>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    expected_process_instance_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DiagnosticsExportPlanPayload {
    destination: String,
    #[serde(default = "default_true")]
    include_receipts: bool,
    #[serde(default = "default_true")]
    include_settings: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SettingsChanges {
    scan_interval_seconds: Option<u16>,
    heartbeat_grace_seconds: Option<u32>,
    retention_days: Option<u16>,
    include_unmanaged_candidates: Option<bool>,
    appearance: Option<String>,
    reduced_motion: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SettingsUpdatePayload {
    expected_revision: u64,
    changes: SettingsChanges,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "method", content = "payload", deny_unknown_fields)]
pub(crate) enum RendererRequest {
    #[serde(rename = "system.info")]
    SystemInfo(EmptyPayload),
    #[serde(rename = "doctor")]
    Doctor(EmptyPayload),
    #[serde(rename = "scan.list")]
    ScanList(ScanPayload),
    #[serde(rename = "agent.detail")]
    AgentDetail(AgentPayload),
    #[serde(rename = "action.plan")]
    ActionPlan(ActionPlanPayload),
    #[serde(rename = "action.execute")]
    ActionExecute(ExecutePayload),
    #[serde(rename = "activity.list")]
    ActivityList(PagePayload),
    #[serde(rename = "receipt.get")]
    ReceiptGet(ReceiptGetPayload),
    #[serde(rename = "quarantine.list")]
    QuarantineList(PagePayload),
    #[serde(rename = "quarantine.resource-list")]
    QuarantineResourceList(ResourceListPayload),
    #[serde(rename = "quarantine.plan")]
    QuarantinePlan(QuarantinePlanPayload),
    #[serde(rename = "quarantine.execute")]
    QuarantineExecute(ExecutePayload),
    #[serde(rename = "quarantine.restore-plan")]
    QuarantineRestorePlan(RestorePlanPayload),
    #[serde(rename = "quarantine.restore-execute")]
    QuarantineRestoreExecute(ExecutePayload),
    #[serde(rename = "vault.list")]
    VaultList(PagePayload),
    #[serde(rename = "vault.register")]
    VaultRegister(VaultPathPayload),
    #[serde(rename = "vault.probe")]
    VaultProbe(VaultPathPayload),
    #[serde(rename = "vault.query")]
    VaultQuery(VaultQueryPayload),
    #[serde(rename = "vault.get")]
    VaultGet(VaultGetPayload),
    #[serde(rename = "vault.mutation.plan")]
    VaultMutationPlan(VaultMutationPlanPayload),
    #[serde(rename = "vault.mutation.execute")]
    VaultMutationExecute(ExecutePayload),
    #[serde(rename = "vault.snapshot.list")]
    VaultSnapshotList(VaultSnapshotListPayload),
    #[serde(rename = "vault.restore.plan")]
    VaultRestorePlan(VaultRestorePlanPayload),
    #[serde(rename = "vault.restore.execute")]
    VaultRestoreExecute(ExecutePayload),
    #[serde(rename = "settings.get")]
    SettingsGet(EmptyPayload),
    #[serde(rename = "settings.update")]
    SettingsUpdate(SettingsUpdatePayload),
    #[serde(rename = "diagnostics.export-plan")]
    DiagnosticsExportPlan(DiagnosticsExportPlanPayload),
    #[serde(rename = "diagnostics.export-execute")]
    DiagnosticsExportExecute(ExecutePayload),
}

impl RendererRequest {
    pub(crate) fn method(&self) -> EngineMethod {
        match self {
            Self::SystemInfo(_) => EngineMethod::SystemInfo,
            Self::Doctor(_) => EngineMethod::Doctor,
            Self::ScanList(_) => EngineMethod::ScanList,
            Self::AgentDetail(_) => EngineMethod::AgentDetail,
            Self::ActionPlan(_) => EngineMethod::ActionPlan,
            Self::ActionExecute(_) => EngineMethod::ActionExecute,
            Self::ActivityList(_) => EngineMethod::ActivityList,
            Self::ReceiptGet(_) => EngineMethod::ReceiptGet,
            Self::QuarantineList(_) => EngineMethod::QuarantineList,
            Self::QuarantineResourceList(_) => EngineMethod::QuarantineResourceList,
            Self::QuarantinePlan(_) => EngineMethod::QuarantinePlan,
            Self::QuarantineExecute(_) => EngineMethod::QuarantineExecute,
            Self::QuarantineRestorePlan(_) => EngineMethod::QuarantineRestorePlan,
            Self::QuarantineRestoreExecute(_) => EngineMethod::QuarantineRestoreExecute,
            Self::VaultList(_) => EngineMethod::VaultList,
            Self::VaultRegister(_) => EngineMethod::VaultRegister,
            Self::VaultProbe(_) => EngineMethod::VaultProbe,
            Self::VaultQuery(_) => EngineMethod::VaultQuery,
            Self::VaultGet(_) => EngineMethod::VaultGet,
            Self::VaultMutationPlan(_) => EngineMethod::VaultMutationPlan,
            Self::VaultMutationExecute(_) => EngineMethod::VaultMutationExecute,
            Self::VaultSnapshotList(_) => EngineMethod::VaultSnapshotList,
            Self::VaultRestorePlan(_) => EngineMethod::VaultRestorePlan,
            Self::VaultRestoreExecute(_) => EngineMethod::VaultRestoreExecute,
            Self::SettingsGet(_) => EngineMethod::SettingsGet,
            Self::SettingsUpdate(_) => EngineMethod::SettingsUpdate,
            Self::DiagnosticsExportPlan(_) => EngineMethod::DiagnosticsExportPlan,
            Self::DiagnosticsExportExecute(_) => EngineMethod::DiagnosticsExportExecute,
        }
    }

    fn execute_payload(&self) -> Option<&ExecutePayload> {
        match self {
            Self::ActionExecute(value)
            | Self::VaultMutationExecute(value)
            | Self::VaultRestoreExecute(value)
            | Self::QuarantineExecute(value)
            | Self::QuarantineRestoreExecute(value)
            | Self::DiagnosticsExportExecute(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), BrokerError> {
        let request_size = serde_json::to_vec(self)
            .map_err(|_| BrokerError::invalid_request())?
            .len();
        if request_size > MAX_RENDERER_REQUEST_BYTES {
            return Err(BrokerError::invalid_request());
        }
        match self {
            Self::ScanList(payload) => validate_limit(payload.limit, 1_000),
            Self::AgentDetail(payload) | Self::QuarantineResourceList(payload) => {
                validate_identifier(&payload.agent_id)?;
                if let Some(pid) = payload.expected_pid
                    && pid == 0
                {
                    return Err(BrokerError::invalid_request());
                }
                if let Some(instance_id) = &payload.expected_process_instance_id {
                    validate_digest(instance_id)?;
                }
                if payload.expected_pid.is_some() != payload.expected_process_instance_id.is_some()
                {
                    return Err(BrokerError::invalid_request());
                }
                Ok(())
            }
            Self::ActionPlan(payload) => {
                validate_identifier(&payload.agent_id)?;
                validate_process_target(&payload.target)
            }
            Self::ActionExecute(payload)
            | Self::VaultMutationExecute(payload)
            | Self::VaultRestoreExecute(payload)
            | Self::QuarantineExecute(payload)
            | Self::QuarantineRestoreExecute(payload)
            | Self::DiagnosticsExportExecute(payload) => {
                validate_identifier(&payload.plan_id)?;
                validate_digest(&payload.digest)
            }
            Self::ActivityList(payload)
            | Self::QuarantineList(payload)
            | Self::VaultList(payload) => {
                validate_limit(payload.limit, 500)?;
                if payload
                    .cursor
                    .as_ref()
                    .is_some_and(|cursor| cursor.chars().count() > 256)
                {
                    return Err(BrokerError::invalid_request());
                }
                Ok(())
            }
            Self::VaultQuery(payload) => {
                validate_identifier(&payload.source_id)?;
                if let Some(namespace) = &payload.namespace {
                    validate_identifier(namespace)?;
                }
                if payload
                    .text
                    .as_ref()
                    .is_some_and(|text| text.chars().count() > 1_024)
                {
                    return Err(BrokerError::invalid_request());
                }
                validate_limit(payload.limit, 500)?;
                if payload
                    .cursor
                    .as_ref()
                    .is_some_and(|cursor| cursor.chars().count() > 256)
                {
                    return Err(BrokerError::invalid_request());
                }
                Ok(())
            }
            Self::VaultGet(payload) => {
                validate_identifier(&payload.source_id)?;
                validate_identifier(&payload.record_id)
            }
            Self::ReceiptGet(payload) => validate_identifier(&payload.receipt_id),
            Self::QuarantinePlan(payload) => {
                validate_identifier(&payload.agent_id)?;
                if payload.resource_index > 63 {
                    return Err(BrokerError::invalid_request());
                }
                validate_digest(&payload.expected_declaration_digest)?;
                if payload.expected_pid == Some(0)
                    || payload.expected_pid.is_some()
                        != payload.expected_process_instance_id.is_some()
                {
                    return Err(BrokerError::invalid_request());
                }
                if let Some(instance_id) = &payload.expected_process_instance_id {
                    validate_digest(instance_id)?;
                }
                Ok(())
            }
            Self::QuarantineRestorePlan(payload) => validate_identifier(&payload.entry_id),
            Self::VaultRegister(payload) | Self::VaultProbe(payload) => {
                validate_path(&payload.path)
            }
            Self::VaultMutationPlan(payload) => {
                validate_identifier(&payload.source_id)?;
                validate_digest(&payload.expected_revision)?;
                validate_identifier(&payload.record_id)?;
                for field in [&payload.field, &payload.metadata_key]
                    .into_iter()
                    .flatten()
                {
                    validate_identifier(field)?;
                }
                if let ScalarValue::Text(value) = &payload.value
                    && value.chars().count() > 65_536
                {
                    return Err(BrokerError::invalid_request());
                }
                Ok(())
            }
            Self::VaultSnapshotList(payload) => {
                validate_identifier(&payload.source_id)?;
                validate_limit(payload.limit, 500)
            }
            Self::VaultRestorePlan(payload) => {
                validate_identifier(&payload.source_id)?;
                validate_identifier(&payload.snapshot_id)?;
                validate_digest(&payload.snapshot_digest)?;
                validate_digest(&payload.expected_revision)
            }
            Self::DiagnosticsExportPlan(payload) => validate_path(&payload.destination),
            Self::SettingsUpdate(payload) => payload.changes.validate(),
            Self::SystemInfo(_) | Self::Doctor(_) | Self::SettingsGet(_) => Ok(()),
        }
    }

    pub(crate) fn engine_envelope(&self, request_id: Uuid) -> Result<Value, BrokerError> {
        self.validate()?;
        let payload = match self {
            Self::SystemInfo(_) | Self::Doctor(_) | Self::SettingsGet(_) => json!({}),
            Self::ScanList(value) => json!({
                "include_unmanaged": value.include_unmanaged,
                "limit": value.limit,
            }),
            Self::AgentDetail(value) | Self::QuarantineResourceList(value) => {
                let mut payload = json!({"agent_id": value.agent_id});
                if let Some(payload) = payload.as_object_mut() {
                    if let Some(pid) = value.expected_pid {
                        payload.insert("expected_pid".to_owned(), json!(pid));
                    }
                    if let Some(instance_id) = &value.expected_process_instance_id {
                        payload.insert(
                            "expected_process_instance_id".to_owned(),
                            json!(instance_id),
                        );
                    }
                }
                payload
            }
            Self::ActionPlan(value) => json!({
                "agent_id": value.agent_id,
                "mode": value.mode.as_str(),
                "target": {
                    "pid": value.target.pid,
                    "process_instance_id": value.target.process_instance_id,
                },
            }),
            Self::ActionExecute(value)
            | Self::VaultMutationExecute(value)
            | Self::VaultRestoreExecute(value)
            | Self::QuarantineExecute(value)
            | Self::QuarantineRestoreExecute(value)
            | Self::DiagnosticsExportExecute(value) => json!({
                "plan_id": value.plan_id,
                "digest": value.digest,
            }),
            Self::ActivityList(value) | Self::QuarantineList(value) | Self::VaultList(value) => {
                let mut payload = json!({"limit": value.limit});
                if let Some(cursor) = &value.cursor
                    && let Some(payload) = payload.as_object_mut()
                {
                    payload.insert("cursor".to_owned(), json!(cursor));
                }
                payload
            }
            Self::VaultQuery(value) => json!({
                "source_id": value.source_id,
                "namespace": value.namespace,
                "text": value.text,
                "limit": value.limit,
                "cursor": value.cursor,
            }),
            Self::VaultGet(value) => json!({
                "source_id": value.source_id,
                "record_id": value.record_id,
            }),
            Self::ReceiptGet(value) => json!({"receipt_id":value.receipt_id}),
            Self::QuarantinePlan(value) => {
                let mut payload = json!({"agent_id":value.agent_id,"resource_index":value.resource_index,"expected_declaration_digest":value.expected_declaration_digest});
                if let Some(payload) = payload.as_object_mut() {
                    if let Some(pid) = value.expected_pid {
                        payload.insert("expected_pid".to_owned(), json!(pid));
                    }
                    if let Some(instance_id) = &value.expected_process_instance_id {
                        payload.insert(
                            "expected_process_instance_id".to_owned(),
                            json!(instance_id),
                        );
                    }
                }
                payload
            }
            Self::QuarantineRestorePlan(value) => json!({"entry_id":value.entry_id}),
            Self::VaultRegister(value) | Self::VaultProbe(value) => json!({"path":value.path}),
            Self::VaultMutationPlan(value) => json!({
                "source_id":value.source_id,"expected_revision":value.expected_revision,
                "operation":value.operation,"record_id":value.record_id,
                "field":value.field,"metadata_key":value.metadata_key,"value":value.value,
            }),
            Self::VaultSnapshotList(value) => {
                json!({"source_id":value.source_id,"limit":value.limit})
            }
            Self::VaultRestorePlan(value) => json!({
                "source_id":value.source_id,"snapshot_id":value.snapshot_id,
                "snapshot_digest":value.snapshot_digest,"expected_revision":value.expected_revision,
            }),
            Self::DiagnosticsExportPlan(value) => json!({
                "destination":value.destination,"include_receipts":value.include_receipts,
                "include_settings":value.include_settings,
            }),
            Self::SettingsUpdate(value) => {
                let mut payload = value.changes.engine_payload();
                if let Some(payload) = payload.as_object_mut() {
                    payload.insert(
                        "expected_revision".to_owned(),
                        json!(value.expected_revision),
                    );
                }
                payload
            }
        };
        Ok(json!({
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request_id,
            "method": self.method().as_str(),
            "payload": payload,
        }))
    }
}

impl SettingsChanges {
    fn validate(&self) -> Result<(), BrokerError> {
        if self.scan_interval_seconds.is_none()
            && self.heartbeat_grace_seconds.is_none()
            && self.retention_days.is_none()
            && self.include_unmanaged_candidates.is_none()
            && self.appearance.is_none()
            && self.reduced_motion.is_none()
        {
            return Err(BrokerError::invalid_request());
        }
        if self
            .scan_interval_seconds
            .is_some_and(|value| !(5..=3_600).contains(&value))
            || self
                .heartbeat_grace_seconds
                .is_some_and(|value| !(10..=86_400).contains(&value))
            || self
                .retention_days
                .is_some_and(|value| !(1..=365).contains(&value))
            || self
                .appearance
                .as_deref()
                .is_some_and(|value| !matches!(value, "system" | "light" | "dark"))
        {
            return Err(BrokerError::invalid_request());
        }
        Ok(())
    }

    fn engine_payload(&self) -> Value {
        let mut payload = Map::new();
        insert_optional(
            &mut payload,
            "scan_interval_seconds",
            self.scan_interval_seconds,
        );
        insert_optional(
            &mut payload,
            "heartbeat_grace_seconds",
            self.heartbeat_grace_seconds,
        );
        insert_optional(&mut payload, "retention_days", self.retention_days);
        insert_optional(
            &mut payload,
            "include_unmanaged_candidates",
            self.include_unmanaged_candidates,
        );
        insert_optional(&mut payload, "appearance", self.appearance.clone());
        insert_optional(&mut payload, "reduced_motion", self.reduced_motion);
        Value::Object(payload)
    }
}

fn insert_optional<T: Serialize>(target: &mut Map<String, Value>, name: &str, value: Option<T>) {
    if let Some(value) = value
        && let Ok(value) = serde_json::to_value(value)
    {
        target.insert(name.to_owned(), value);
    }
}

fn validate_identifier(value: &str) -> Result<(), BrokerError> {
    if value.is_empty() || value.chars().count() > 256 || value.trim() != value {
        return Err(BrokerError::invalid_request());
    }
    Ok(())
}

fn validate_path(value: &str) -> Result<(), BrokerError> {
    if value.is_empty() || value.chars().count() > 4_096 || value.trim() != value {
        return Err(BrokerError::invalid_request());
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), BrokerError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BrokerError::invalid_request());
    }
    Ok(())
}

fn validate_process_target(target: &ProcessTarget) -> Result<(), BrokerError> {
    if target.pid == 0 {
        return Err(BrokerError::invalid_request());
    }
    validate_digest(&target.process_instance_id)
}

fn validate_limit(value: u16, maximum: u16) -> Result<(), BrokerError> {
    if value == 0 || value > maximum {
        return Err(BrokerError::invalid_request());
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct LaunchSpec {
    executable: PathBuf,
    arguments: Vec<String>,
    current_dir: PathBuf,
    environment: Vec<(OsString, OsString)>,
    integrity: Option<BundleIntegrity>,
}

#[derive(Clone, Debug)]
struct BundleIntegrity {
    root: PathBuf,
    trusted_manifest_sha256: String,
}

impl LaunchSpec {
    #[cfg(test)]
    pub(crate) fn executable(&self) -> &Path {
        &self.executable
    }

    #[cfg(test)]
    pub(crate) fn arguments(&self) -> Vec<&str> {
        self.arguments.iter().map(String::as_str).collect()
    }

    #[cfg(any(not(debug_assertions), test))]
    pub(crate) fn bundled(
        root: PathBuf,
        trusted_manifest_sha256: String,
    ) -> Result<Self, BrokerError> {
        if !root.is_absolute() || !valid_digest(&trusted_manifest_sha256) {
            return Err(BrokerError::engine_unavailable());
        }
        let executable = root.join(fixed_executable_name());
        Ok(Self {
            executable,
            arguments: protocol_arguments(Vec::new()),
            current_dir: root.clone(),
            environment: safe_environment(),
            integrity: Some(BundleIntegrity {
                root,
                trusted_manifest_sha256,
            }),
        })
    }

    #[cfg(test)]
    pub(crate) fn test_only(
        executable: PathBuf,
        arguments: Vec<String>,
        current_dir: PathBuf,
        environment: Vec<(OsString, OsString)>,
    ) -> Self {
        Self {
            executable,
            arguments,
            current_dir,
            environment,
            integrity: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_only_with_integrity(
        executable: PathBuf,
        arguments: Vec<String>,
        current_dir: PathBuf,
        environment: Vec<(OsString, OsString)>,
        integrity_root: PathBuf,
        trusted_manifest_sha256: String,
    ) -> Self {
        Self {
            executable,
            arguments,
            current_dir,
            environment,
            integrity: Some(BundleIntegrity {
                root: integrity_root,
                trusted_manifest_sha256,
            }),
        }
    }

    async fn verify_before_spawn(&self) -> Result<Option<VerifiedBundle>, BrokerError> {
        let Some(integrity) = self.integrity.clone() else {
            return Ok(None);
        };
        tokio::task::spawn_blocking(move || {
            verify_runtime_bundle(
                &integrity.root,
                fixed_platform_name()?,
                std::env::consts::ARCH,
                fixed_executable_name(),
                &integrity.trusted_manifest_sha256,
            )
            .map(Some)
            .map_err(|_| BrokerError::engine_unavailable())
        })
        .await
        .map_err(|_| BrokerError::engine_unavailable())?
    }

    fn integrity_binds_executable(&self) -> bool {
        self.integrity.as_ref().is_some_and(|integrity| {
            integrity.root.join(fixed_executable_name()) == self.executable
        })
    }
}

#[cfg(any(not(debug_assertions), test))]
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn fixed_executable_name() -> &'static str {
    if cfg!(windows) {
        "zombie-killer-engine.exe"
    } else {
        "zombie-killer-engine"
    }
}

fn fixed_platform_name() -> Result<&'static str, BrokerError> {
    match std::env::consts::OS {
        "windows" => Ok("windows"),
        "linux" => Ok("linux"),
        "macos" => Ok("darwin"),
        _ => Err(BrokerError::engine_unavailable()),
    }
}

#[cfg(any(debug_assertions, test))]
pub(crate) fn development_launch(manifest_dir: &Path) -> Result<LaunchSpec, BrokerError> {
    let repository = manifest_dir
        .join("../../..")
        .canonicalize()
        .map_err(|_| BrokerError::engine_unavailable())?;
    let executable = if cfg!(windows) {
        repository.join(".venv/Scripts/python.exe")
    } else {
        repository.join(".venv/bin/python")
    };
    if !executable.is_file() {
        return Err(BrokerError::engine_unavailable());
    }
    Ok(LaunchSpec {
        executable,
        arguments: protocol_arguments(vec![
            "-I".to_owned(),
            "-m".to_owned(),
            "zombie_killer_engine".to_owned(),
        ]),
        current_dir: repository,
        environment: safe_environment(),
        integrity: None,
    })
}

fn protocol_arguments(mut prefix: Vec<String>) -> Vec<String> {
    prefix.push("protocol-once".to_owned());
    // Windows process ancestry can be mediated by the desktop host. The Job Object is the
    // authoritative parent-death boundary there; POSIX uses both its liveness descriptor and
    // this identity watcher as independent containment signals.
    #[cfg(unix)]
    prefix.push(format!("--parent-pid={}", std::process::id()));
    prefix
}

fn safe_environment() -> Vec<(OsString, OsString)> {
    const ALLOWED: &[&str] = &[
        "APPDATA",
        "HOME",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
        "XDG_DATA_HOME",
        "XDG_RUNTIME_DIR",
        "XDG_STATE_HOME",
    ];
    let allowlist: HashSet<&str> = ALLOWED.iter().copied().collect();
    let mut environment: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(name, _)| {
            let normalized = name.to_string_lossy().to_ascii_uppercase();
            allowlist.contains(normalized.as_str())
        })
        .collect();
    environment.extend([
        (
            OsString::from("PYTHONDONTWRITEBYTECODE"),
            OsString::from("1"),
        ),
        (OsString::from("PYTHONNOUSERSITE"), OsString::from("1")),
        (OsString::from("PYTHONUTF8"), OsString::from("1")),
    ]);
    environment
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BrokerErrorCode {
    InvalidRequest,
    EngineUnavailable,
    EngineTimeout,
    OutputTooLarge,
    ProtocolViolation,
    OutcomeUncertain,
    NotFound,
    Conflict,
    TargetChanged,
    PermissionDenied,
    Expired,
    Unsupported,
    Partial,
    Internal,
}

impl BrokerErrorCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::EngineUnavailable => "engine_unavailable",
            Self::EngineTimeout => "engine_timeout",
            Self::OutputTooLarge => "output_too_large",
            Self::ProtocolViolation => "protocol_violation",
            Self::OutcomeUncertain => "outcome_uncertain",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::TargetChanged => "target_changed",
            Self::PermissionDenied => "permission_denied",
            Self::Expired => "expired",
            Self::Unsupported => "unsupported",
            Self::Partial => "partial",
            Self::Internal => "internal",
        }
    }
}

#[derive(Debug)]
pub(crate) struct BrokerError {
    code: BrokerErrorCode,
    message: &'static str,
    correlation_id: String,
    reconcile_required: bool,
}

impl BrokerError {
    fn new(code: BrokerErrorCode, message: &'static str) -> Self {
        Self {
            code,
            message,
            correlation_id: Uuid::new_v4().to_string(),
            reconcile_required: false,
        }
    }

    fn invalid_request() -> Self {
        Self::new(
            BrokerErrorCode::InvalidRequest,
            "The native request was rejected by the local broker.",
        )
    }

    fn engine_unavailable() -> Self {
        Self::new(
            BrokerErrorCode::EngineUnavailable,
            "The local engine is unavailable.",
        )
    }

    fn timeout(method: EngineMethod, request_id: Uuid) -> Self {
        if method.mutates() {
            Self::outcome_uncertain(request_id)
        } else {
            Self::new(
                BrokerErrorCode::EngineTimeout,
                "The local engine did not answer before the deadline.",
            )
        }
    }

    fn outcome_uncertain(request_id: Uuid) -> Self {
        let mut error = Self::new(
            BrokerErrorCode::OutcomeUncertain,
            "The engine connection ended after a mutating request was dispatched. The outcome is uncertain; reconcile local state before retrying.",
        );
        error.correlation_id = request_id.to_string();
        error.reconcile_required = true;
        error
    }

    fn after_dispatch(method: EngineMethod, request_id: Uuid, fallback: Self) -> Self {
        if method.mutates() {
            Self::outcome_uncertain(request_id)
        } else {
            fallback
        }
    }

    pub(crate) fn protocol(_untrusted: &str, correlation_id: Option<String>) -> Self {
        let mut error = Self::new(
            BrokerErrorCode::ProtocolViolation,
            "The local engine returned an invalid response.",
        );
        if let Some(correlation_id) = correlation_id.filter(|value| Uuid::parse_str(value).is_ok())
        {
            error.correlation_id = correlation_id;
        }
        error
    }

    fn output_too_large(request_id: Uuid) -> Self {
        Self {
            code: BrokerErrorCode::OutputTooLarge,
            message: "The local engine exceeded a bounded output limit.",
            correlation_id: request_id.to_string(),
            reconcile_required: false,
        }
    }

    fn from_protocol(error: ProtocolErrorBody, fallback: Uuid) -> Self {
        let (code, message) = match error.code.as_str() {
            "invalid_request" => (
                BrokerErrorCode::InvalidRequest,
                "The local engine rejected the request.",
            ),
            "not_found" => (
                BrokerErrorCode::NotFound,
                "The requested local object was not found.",
            ),
            "conflict" => (
                BrokerErrorCode::Conflict,
                "Stored authority changed; create a fresh review.",
            ),
            "target_changed" => (
                BrokerErrorCode::TargetChanged,
                "The target identity changed; no action was taken.",
            ),
            "permission_denied" => (
                BrokerErrorCode::PermissionDenied,
                "The local operation is not permitted.",
            ),
            "expired" => (
                BrokerErrorCode::Expired,
                "The review plan expired; create a fresh review.",
            ),
            "unsupported" => (
                BrokerErrorCode::Unsupported,
                "This operation is unavailable in the local engine.",
            ),
            "partial" => (
                BrokerErrorCode::Partial,
                "The local operation did not produce a complete verified result.",
            ),
            _ => (
                BrokerErrorCode::Internal,
                "The local engine reported an internal error.",
            ),
        };
        Self {
            code,
            message,
            correlation_id: fallback.to_string(),
            reconcile_required: code == BrokerErrorCode::Partial,
        }
    }

    #[cfg(test)]
    pub(crate) fn code(&self) -> BrokerErrorCode {
        self.code
    }

    pub(crate) fn dto(&self) -> BrokerErrorDto {
        BrokerErrorDto {
            code: self.code.as_str().to_owned(),
            message: self.message.to_owned(),
            correlation_id: self.correlation_id.clone(),
            reconcile_required: self.reconcile_required,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BrokerErrorDto {
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) correlation_id: String,
    pub(crate) reconcile_required: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EngineReply {
    request_id: Uuid,
    method: String,
    result: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolResponse {
    protocol_version: String,
    request_id: Uuid,
    method: Option<String>,
    ok: bool,
    result: Option<Value>,
    error: Option<ProtocolErrorBody>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtocolErrorBody {
    code: String,
    message: String,
    retryable: bool,
    details: BTreeMap<String, Value>,
}

pub(crate) enum ValidatedResponse {
    Success(Value),
    Error(ProtocolErrorBody),
}

pub(crate) fn validate_response(
    request_id: Uuid,
    method: EngineMethod,
    bytes: &[u8],
) -> Result<ValidatedResponse, BrokerError> {
    let response: ProtocolResponse = serde_json::from_slice(bytes)
        .map_err(|_| BrokerError::protocol("invalid JSON", Some(request_id.to_string())))?;
    if response.protocol_version != PROTOCOL_VERSION
        || response.request_id != request_id
        || response.method.as_deref() != Some(method.as_str())
    {
        return Err(BrokerError::protocol(
            "correlation mismatch",
            Some(request_id.to_string()),
        ));
    }
    if response.ok {
        if response.error.is_some() {
            return Err(BrokerError::protocol(
                "mixed response",
                Some(request_id.to_string()),
            ));
        }
        let result = response
            .result
            .ok_or_else(|| BrokerError::protocol("missing result", Some(request_id.to_string())))?;
        validate_result_tree(&result, 0, &mut 20_000).map_err(|mut error| {
            error.correlation_id = request_id.to_string();
            error
        })?;
        validate_result(method, &result).map_err(|mut error| {
            error.correlation_id = request_id.to_string();
            error
        })?;
        Ok(ValidatedResponse::Success(result))
    } else {
        if response.result.is_some() {
            return Err(BrokerError::protocol(
                "mixed response",
                Some(request_id.to_string()),
            ));
        }
        let error = response
            .error
            .ok_or_else(|| BrokerError::protocol("missing error", Some(request_id.to_string())))?;
        validate_protocol_error(&error, request_id)?;
        Ok(ValidatedResponse::Error(error))
    }
}

fn validate_result_tree(
    value: &Value,
    depth: usize,
    remaining: &mut usize,
) -> Result<(), BrokerError> {
    if depth > 16 || *remaining == 0 {
        return Err(BrokerError::protocol("result nesting or node limit", None));
    }
    *remaining -= 1;
    match value {
        Value::String(value) if value.chars().count() > 65_536 => {
            Err(BrokerError::protocol("result string limit", None))
        }
        Value::Array(items) => {
            if items.len() > 10_000 {
                return Err(BrokerError::protocol("result collection limit", None));
            }
            for item in items {
                validate_result_tree(item, depth + 1, remaining)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            if object.len() > 10_000 || object.keys().any(|key| key.chars().count() > 128) {
                return Err(BrokerError::protocol("result object limit", None));
            }
            for item in object.values() {
                validate_result_tree(item, depth + 1, remaining)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(crate) fn validate_response_for_request(
    request_id: Uuid,
    request: &RendererRequest,
    bytes: &[u8],
) -> Result<ValidatedResponse, BrokerError> {
    let response = validate_response(request_id, request.method(), bytes)?;
    if let ValidatedResponse::Success(result) = &response {
        let binding = match request {
            RendererRequest::ReceiptGet(expected) => {
                Some(("receipt_id", expected.receipt_id.as_str()))
            }
            RendererRequest::QuarantineResourceList(expected) => {
                Some(("agent_id", expected.agent_id.as_str()))
            }
            _ => None,
        };
        if let Some((field, expected)) = binding
            && result.get(field).and_then(Value::as_str) != Some(expected)
        {
            return Err(BrokerError::protocol(
                "selected object mismatch",
                Some(request_id.to_string()),
            ));
        }
    }
    if let (Some(expected), ValidatedResponse::Success(result)) =
        (request.execute_payload(), &response)
    {
        let actual = result
            .as_object()
            .and_then(|object| object.get("plan_id"))
            .and_then(Value::as_str);
        if actual != Some(expected.plan_id.as_str()) {
            return Err(BrokerError::protocol(
                "execution receipt plan mismatch",
                Some(request_id.to_string()),
            ));
        }
    }
    if let (RendererRequest::ActionPlan(expected), ValidatedResponse::Success(result)) =
        (request, &response)
    {
        let target = result
            .as_object()
            .and_then(|object| object.get("target"))
            .and_then(Value::as_object)
            .ok_or_else(|| {
                BrokerError::protocol(
                    "action plan target is missing",
                    Some(request_id.to_string()),
                )
            })?;
        let pid = target.get("pid").and_then(Value::as_u64);
        let process_instance_id = target.get("process_instance_id").and_then(Value::as_str);
        if pid != Some(u64::from(expected.target.pid))
            || process_instance_id != Some(expected.target.process_instance_id.as_str())
        {
            return Err(BrokerError::protocol(
                "action plan target mismatch",
                Some(request_id.to_string()),
            ));
        }
    }
    if let (RendererRequest::AgentDetail(expected), ValidatedResponse::Success(result)) =
        (request, &response)
        && let (Some(expected_pid), Some(expected_instance)) = (
            expected.expected_pid,
            expected.expected_process_instance_id.as_deref(),
        )
    {
        let object = result.as_object().ok_or_else(|| {
            BrokerError::protocol(
                "agent detail is not an object",
                Some(request_id.to_string()),
            )
        })?;
        let agent_id = object.get("agent_id").and_then(Value::as_str);
        let pid = object.get("pid").and_then(Value::as_u64);
        let instance = object.get("process_instance_id").and_then(Value::as_str);
        if agent_id != Some(expected.agent_id.as_str())
            || pid != Some(u64::from(expected_pid))
            || instance != Some(expected_instance)
        {
            return Err(BrokerError::protocol(
                "agent detail identity mismatch",
                Some(request_id.to_string()),
            ));
        }
    }
    Ok(response)
}

fn validate_protocol_error(error: &ProtocolErrorBody, request_id: Uuid) -> Result<(), BrokerError> {
    const CODES: &[&str] = &[
        "invalid_request",
        "not_found",
        "conflict",
        "target_changed",
        "permission_denied",
        "expired",
        "unsupported",
        "partial",
        "internal",
    ];
    if !CODES.contains(&error.code.as_str())
        || error.message.is_empty()
        || error.message.chars().count() > 512
        || error.details.len() > 16
    {
        return Err(BrokerError::protocol(
            "invalid error",
            Some(request_id.to_string()),
        ));
    }
    for (key, value) in &error.details {
        let approved = matches!(
            key.as_str(),
            "correlation_id" | "field" | "reason" | "supported_version"
        ) || key
            .strip_prefix("redacted_detail_")
            .and_then(|suffix| suffix.parse::<u8>().ok())
            .is_some_and(|index| (1..=16).contains(&index));
        let bounded_scalar = value.is_null()
            || value.is_boolean()
            || value.is_number()
            || value
                .as_str()
                .is_some_and(|text| text.chars().count() <= 256);
        if !approved || !bounded_scalar {
            return Err(BrokerError::protocol(
                "invalid error detail",
                Some(request_id.to_string()),
            ));
        }
    }
    let _retryable = error.retryable;
    Ok(())
}

fn validate_result(method: EngineMethod, value: &Value) -> Result<(), BrokerError> {
    match method {
        EngineMethod::SystemInfo => validate_system_info(value),
        EngineMethod::Doctor => validate_doctor(value),
        EngineMethod::ScanList => validate_scan(value),
        EngineMethod::AgentDetail => validate_agent(value),
        EngineMethod::ActionPlan => validate_plan(value),
        EngineMethod::ActionExecute => {
            validate_receipt(value)?;
            if value.get("certainty").and_then(Value::as_str) == Some("verified")
                && value.get("action_issued").and_then(Value::as_bool) != Some(true)
            {
                return Err(BrokerError::protocol("contradictory action receipt", None));
            }
            Ok(())
        }
        EngineMethod::ReceiptGet
        | EngineMethod::QuarantineExecute
        | EngineMethod::QuarantineRestoreExecute
        | EngineMethod::DiagnosticsExportExecute => validate_receipt(value),
        EngineMethod::QuarantinePlan | EngineMethod::QuarantineRestorePlan => {
            let object = exact_object(value, PLAN_FIELDS)?;
            validate_plan_fields(object)
        }
        EngineMethod::DiagnosticsExportPlan => validate_diagnostics_plan(value),
        EngineMethod::ActivityList => {
            let object = exact_object(value, &["receipts", "next_cursor"])?;
            let receipts = array(object, "receipts")?;
            if receipts.len() > 500 {
                return Err(BrokerError::protocol("too many receipts", None));
            }
            for receipt in receipts {
                validate_receipt(receipt)?;
            }
            nullable_string(object, "next_cursor", 256)
        }
        EngineMethod::QuarantineList => validate_quarantine_list(value),
        EngineMethod::QuarantineResourceList => validate_resource_list(value),
        EngineMethod::VaultList => validate_vault_list(value),
        EngineMethod::VaultRegister | EngineMethod::VaultProbe => validate_vault_probe(value),
        EngineMethod::VaultQuery => validate_vault_query(value),
        EngineMethod::VaultGet => {
            let object = exact_object(value, &["record", "local_only_warning"])?;
            validate_vault_record(required(object, "record")?)?;
            validate_vault_warning(object)
        }
        EngineMethod::SettingsGet | EngineMethod::SettingsUpdate => validate_settings(value),
        EngineMethod::VaultMutationPlan | EngineMethod::VaultRestorePlan => {
            let object = object_with_optional_fields(
                value,
                &[
                    "plan_id",
                    "digest",
                    "expires_at",
                    "consequences",
                    "warnings",
                    "local_only_warning",
                ],
                &[
                    "source_id",
                    "record_id",
                    "snapshot_id",
                    "before_revision",
                    "backup_verified",
                    "diff",
                ],
            )?;
            validate_plan_fields(object)?;
            validate_vault_authority(object)?;
            validate_vault_warning(object)
        }
        EngineMethod::VaultMutationExecute | EngineMethod::VaultRestoreExecute => {
            let object = object_with_optional_fields(
                value,
                &[
                    "receipt_id",
                    "plan_id",
                    "outcome",
                    "certainty",
                    "action_issued",
                    "partial_failures",
                    "created_at",
                    "local_only_warning",
                ],
                &[
                    "kind",
                    "source_id",
                    "record_id",
                    "snapshot_id",
                    "before_revision",
                    "after_revision",
                    "operation",
                ],
            )?;
            validate_receipt_fields(object)?;
            validate_vault_authority(object)?;
            if let Some(operation) = object.get("operation")
                && !operation.is_null()
            {
                let operation = bounded_string_value(operation, 128)?;
                if operation.is_empty() {
                    return Err(BrokerError::protocol("empty memory operation", None));
                }
            }
            validate_vault_warning(object)
        }
        EngineMethod::VaultSnapshotList => validate_vault_snapshots(value),
    }
}

fn validate_system_info(value: &Value) -> Result<(), BrokerError> {
    let object = exact_object(
        value,
        &[
            "engine_version",
            "protocol_version",
            "platform",
            "python",
            "local_only",
            "network_listener",
            "memory_warning",
        ],
    )?;
    string(object, "engine_version", 64)?;
    if string(object, "protocol_version", 8)? != PROTOCOL_VERSION
        || !boolean(object, "local_only")?
        || boolean(object, "network_listener")?
    {
        return Err(BrokerError::protocol("invalid system info", None));
    }
    string(object, "platform", 64)?;
    string(object, "python", 32)?;
    string(object, "memory_warning", 512)?;
    Ok(())
}

fn validate_doctor(value: &Value) -> Result<(), BrokerError> {
    let object = exact_object(value, &["healthy", "checks", "warnings"])?;
    boolean(object, "healthy")?;
    let checks = array(object, "checks")?;
    let warnings = array(object, "warnings")?;
    if checks.len() > 128 || warnings.len() > 128 {
        return Err(BrokerError::protocol("doctor collection limit", None));
    }
    for check in checks {
        let check = exact_object(check, &["name", "ok"])?;
        string(check, "name", 128)?;
        boolean(check, "ok")?;
    }
    for warning in warnings {
        bounded_string_value(warning, 512)?;
    }
    Ok(())
}

fn validate_scan(value: &Value) -> Result<(), BrokerError> {
    let object = exact_object(value, &["agents", "coverage", "returned", "total"])?;
    let agents = array(object, "agents")?;
    if agents.len() > 1_000 {
        return Err(BrokerError::protocol("too many agents", None));
    }
    for agent in agents {
        validate_agent(agent)?;
    }
    validate_coverage(required(object, "coverage")?)?;
    let returned = unsigned(object, "returned")?;
    let total = unsigned(object, "total")?;
    if returned != agents.len() as u64 || total < returned {
        return Err(BrokerError::protocol("invalid scan counts", None));
    }
    Ok(())
}

fn validate_agent(value: &Value) -> Result<(), BrokerError> {
    let object = exact_object(
        value,
        &[
            "agent_id",
            "provider",
            "project",
            "role",
            "state",
            "evidence_grade",
            "confidence",
            "reason_codes",
            "explanation",
            "evidence",
            "actionable",
            "managed",
            "pid",
            "process_instance_id",
            "process_name",
            "os_status",
            "usage_cost",
        ],
    )?;
    for field in ["agent_id", "provider", "project", "role", "process_name"] {
        nullable_string(object, field, 256)?;
    }
    nullable_string(object, "os_status", 64)?;
    if !matches!(
        string(object, "state", 32)?,
        "healthy"
            | "idle"
            | "stale"
            | "orphaned"
            | "unresponsive"
            | "unmanaged"
            | "interrupted"
            | "defunct"
            | "completed"
            | "failed"
            | "cancelled"
            | "unknown"
    ) {
        return Err(BrokerError::protocol("invalid agent state", None));
    }
    if !valid_evidence_grade(string(object, "evidence_grade", 32)?) {
        return Err(BrokerError::protocol("invalid evidence grade", None));
    }
    let confidence = number(object, "confidence")?;
    if !(0.0..=1.0).contains(&confidence) {
        return Err(BrokerError::protocol("invalid confidence", None));
    }
    let reasons = array(object, "reason_codes")?;
    let evidence_items = array(object, "evidence")?;
    if reasons.is_empty()
        || reasons.len() > 128
        || evidence_items.is_empty()
        || evidence_items.len() > 128
    {
        return Err(BrokerError::protocol(
            "invalid agent evidence collection",
            None,
        ));
    }
    for reason in reasons {
        bounded_string_value(reason, 128)?;
    }
    string(object, "explanation", 2_048)?;
    for evidence in evidence_items {
        let evidence = exact_object(evidence, &["code", "grade", "observed_at", "detail"])?;
        string(evidence, "code", 128)?;
        if !valid_evidence_grade(string(evidence, "grade", 32)?) {
            return Err(BrokerError::protocol("invalid evidence grade", None));
        }
        string(evidence, "observed_at", 64)?;
        string(evidence, "detail", 2_048)?;
    }
    let actionable = boolean(object, "actionable")?;
    let managed = boolean(object, "managed")?;
    nullable_unsigned(object, "pid")?;
    nullable_digest(object, "process_instance_id")?;
    let has_agent_id = required(object, "agent_id")?.as_str().is_some();
    let has_pid = required(object, "pid")?.as_u64().is_some();
    let has_process_instance = required(object, "process_instance_id")?.as_str().is_some();
    if (actionable && (!managed || !has_agent_id || !has_pid || !has_process_instance))
        || (has_process_instance && !has_pid)
    {
        return Err(BrokerError::protocol("invalid actionability", None));
    }
    let usage = exact_object(
        required(object, "usage_cost")?,
        &["availability", "amount_usd", "note"],
    )?;
    let availability = string(usage, "availability", 16)?;
    let amount = usage.get("amount_usd").and_then(Value::as_f64);
    if !matches!(availability, "known" | "unknown")
        || (availability == "known") != amount.is_some()
        || amount.is_some_and(|value| value < 0.0)
    {
        return Err(BrokerError::protocol("invalid usage cost", None));
    }
    string(usage, "note", 512)?;
    Ok(())
}

fn validate_coverage(value: &Value) -> Result<(), BrokerError> {
    let object = exact_object(
        value,
        &[
            "inspected_count",
            "denied_count",
            "vanished_count",
            "malformed_lease_count",
            "lease_file_count",
            "skipped_lease_count",
            "other_user_count",
            "unknown_owner_count",
            "identity_denied_count",
            "complete",
            "captured_at",
            "current_boot_id",
            "warnings",
        ],
    )?;
    for field in [
        "inspected_count",
        "denied_count",
        "vanished_count",
        "malformed_lease_count",
        "lease_file_count",
        "skipped_lease_count",
        "other_user_count",
        "unknown_owner_count",
        "identity_denied_count",
    ] {
        unsigned(object, field)?;
    }
    boolean(object, "complete")?;
    string(object, "captured_at", 64)?;
    string(object, "current_boot_id", 256)?;
    let warnings = array(object, "warnings")?;
    if warnings.len() > 128 {
        return Err(BrokerError::protocol("too many coverage warnings", None));
    }
    for warning in warnings {
        let warning = exact_object(warning, &["code", "message"])?;
        string(warning, "code", 128)?;
        string(warning, "message", 512)?;
    }
    Ok(())
}

fn validate_plan(value: &Value) -> Result<(), BrokerError> {
    let object = exact_object(
        value,
        &[
            "plan_id",
            "digest",
            "expires_at",
            "consequences",
            "warnings",
            "target",
        ],
    )?;
    validate_plan_fields(object)?;
    let target = exact_object(
        required(object, "target")?,
        &["pid", "process_instance_id", "state"],
    )?;
    if unsigned(target, "pid")? == 0 {
        return Err(BrokerError::protocol("invalid process target", None));
    }
    validate_digest(string(target, "process_instance_id", 64)?)
        .map_err(|_| BrokerError::protocol("invalid process instance identity", None))?;
    if !matches!(
        string(target, "state", 32)?,
        "healthy"
            | "idle"
            | "stale"
            | "unresponsive"
            | "orphaned"
            | "unmanaged"
            | "interrupted"
            | "defunct"
            | "completed"
            | "failed"
            | "cancelled"
            | "unknown"
    ) {
        return Err(BrokerError::protocol("invalid action target state", None));
    }
    Ok(())
}

const PLAN_FIELDS: &[&str] = &[
    "plan_id",
    "digest",
    "expires_at",
    "consequences",
    "warnings",
];

fn validate_plan_fields(object: &Map<String, Value>) -> Result<(), BrokerError> {
    validate_identifier(string(object, "plan_id", 256)?)?;
    validate_digest(string(object, "digest", 64)?)?;
    string(object, "expires_at", 64)?;
    for field in ["consequences", "warnings"] {
        let items = array(object, field)?;
        if items.len() > 64 || (field == "consequences" && items.is_empty()) {
            return Err(BrokerError::protocol("invalid plan messages", None));
        }
        for item in items {
            bounded_string_value(item, 2_048)?;
        }
    }
    Ok(())
}

fn validate_diagnostics_plan(value: &Value) -> Result<(), BrokerError> {
    let object = exact_object(
        value,
        &[
            "plan_id",
            "digest",
            "expires_at",
            "consequences",
            "warnings",
            "excluded_by_default",
        ],
    )?;
    validate_plan_fields(object)?;
    let exclusions = array(object, "excluded_by_default")?;
    if exclusions.len() != 4 {
        return Err(BrokerError::protocol(
            "invalid diagnostics exclusions",
            None,
        ));
    }
    for exclusion in exclusions {
        if !matches!(
            exclusion.as_str(),
            Some("command_lines" | "memory_contents" | "paths" | "secrets")
        ) {
            return Err(BrokerError::protocol("invalid diagnostics exclusion", None));
        }
    }
    Ok(())
}

fn validate_receipt(value: &Value) -> Result<(), BrokerError> {
    let object = object_with_optional_fields(
        value,
        &[
            "receipt_id",
            "plan_id",
            "outcome",
            "certainty",
            "action_issued",
            "partial_failures",
            "created_at",
        ],
        &["kind"],
    )?;
    validate_receipt_fields(object)
}

fn validate_receipt_fields(object: &Map<String, Value>) -> Result<(), BrokerError> {
    if let Some(kind) = object.get("kind")
        && !matches!(
            kind.as_str(),
            Some("process" | "memory" | "quarantine" | "diagnostics")
        )
    {
        return Err(BrokerError::protocol("invalid receipt kind", None));
    }
    validate_identifier(string(object, "receipt_id", 256)?)?;
    validate_identifier(string(object, "plan_id", 256)?)?;
    string(object, "outcome", 128)?;
    let certainty = string(object, "certainty", 32)?;
    if !matches!(certainty, "verified" | "failed_before_issue" | "uncertain") {
        return Err(BrokerError::protocol("invalid certainty", None));
    }
    let issued = required(object, "action_issued")?;
    if !issued.is_null() && issued.as_bool().is_none() {
        return Err(BrokerError::protocol("invalid action issuance", None));
    }
    let consistent = matches!(
        (certainty, issued.as_bool()),
        ("verified", Some(_)) | ("failed_before_issue", Some(false)) | ("uncertain", None)
    );
    if !consistent {
        return Err(BrokerError::protocol("contradictory action receipt", None));
    }
    let partial_failures = array(object, "partial_failures")?;
    if partial_failures.len() > 64 {
        return Err(BrokerError::protocol("too many partial failures", None));
    }
    for failure in partial_failures {
        let failure = bounded_string_value(failure, 2_048)?;
        if failure.is_empty() {
            return Err(BrokerError::protocol("empty partial failure", None));
        }
    }
    string(object, "created_at", 64)?;
    Ok(())
}

fn validate_resource_list(value: &Value) -> Result<(), BrokerError> {
    let object = exact_object(value, &["agent_id", "resources", "returned"])?;
    validate_identifier(string(object, "agent_id", 256)?)?;
    let resources = array(object, "resources")?;
    if resources.len() > 64 || unsigned(object, "returned")? != resources.len() as u64 {
        return Err(BrokerError::protocol("invalid resource count", None));
    }
    let mut indices = HashSet::new();
    for resource in resources {
        let resource = exact_object(
            resource,
            &[
                "resource_index",
                "kind",
                "resource_type",
                "cleanup_available",
                "reason",
                "declaration_digest",
            ],
        )?;
        let index = unsigned(resource, "resource_index")?;
        if index > 63
            || !indices.insert(index)
            || string(resource, "kind", 16)? != "temporary"
            || !matches!(
                string(resource, "resource_type", 16)?,
                "file" | "directory" | "unknown"
            )
        {
            return Err(BrokerError::protocol("invalid declared resource", None));
        }
        let cleanup_available = boolean(resource, "cleanup_available")?;
        string(resource, "reason", 512)?;
        nullable_digest(resource, "declaration_digest")?;
        if cleanup_available && required(resource, "declaration_digest")?.is_null() {
            return Err(BrokerError::protocol(
                "missing cleanup review authority",
                None,
            ));
        }
    }
    Ok(())
}

fn validate_vault_probe(value: &Value) -> Result<(), BrokerError> {
    let object = exact_object(
        value,
        &[
            "format",
            "recognized",
            "capabilities",
            "reason",
            "read_only",
            "selected_locally",
            "local_only_warning",
        ],
    )?;
    validate_vault_format(object)?;
    boolean(object, "recognized")?;
    validate_vault_capabilities(required(object, "capabilities")?)?;
    nullable_string(object, "reason", 512)?;
    if !boolean(object, "read_only")? || !boolean(object, "selected_locally")? {
        return Err(BrokerError::protocol("invalid vault probe scope", None));
    }
    validate_vault_warning(object)
}

fn validate_vault_snapshots(value: &Value) -> Result<(), BrokerError> {
    let object = exact_object(value, &["snapshots", "local_only_warning"])?;
    let snapshots = array(object, "snapshots")?;
    if snapshots.len() > 500 {
        return Err(BrokerError::protocol("too many snapshots", None));
    }
    for snapshot in snapshots {
        let snapshot = exact_object(
            snapshot,
            &[
                "snapshot_id",
                "source_id",
                "source_revision",
                "digest",
                "size",
                "status",
                "created_at",
            ],
        )?;
        validate_identifier(string(snapshot, "snapshot_id", 256)?)?;
        validate_identifier(string(snapshot, "source_id", 256)?)?;
        validate_digest(string(snapshot, "source_revision", 64)?)?;
        validate_digest(string(snapshot, "digest", 64)?)?;
        unsigned(snapshot, "size")?;
        if !matches!(
            string(snapshot, "status", 16)?,
            "verified" | "restored" | "invalid"
        ) {
            return Err(BrokerError::protocol("invalid snapshot status", None));
        }
        string(snapshot, "created_at", 64)?;
    }
    validate_vault_warning(object)
}

fn validate_vault_format(object: &Map<String, Value>) -> Result<(), BrokerError> {
    if !matches!(
        string(object, "format", 32)?,
        "json" | "jsonl" | "sqlite" | "chroma" | "faiss" | "unsupported"
    ) {
        return Err(BrokerError::protocol("invalid vault format", None));
    }
    Ok(())
}

fn validate_quarantine_list(value: &Value) -> Result<(), BrokerError> {
    let object = exact_object(value, &["entries", "next_cursor"])?;
    let entries = array(object, "entries")?;
    if entries.len() > 500 {
        return Err(BrokerError::protocol("too many quarantine entries", None));
    }
    for entry in entries {
        let entry = exact_object(
            entry,
            &[
                "entry_id",
                "agent_id",
                "resource_type",
                "state",
                "restorable",
                "created_at",
                "updated_at",
            ],
        )?;
        string(entry, "entry_id", 256)?;
        string(entry, "agent_id", 256)?;
        if !matches!(string(entry, "resource_type", 16)?, "file" | "directory") {
            return Err(BrokerError::protocol("invalid quarantine resource", None));
        }
        let state = string(entry, "state", 32)?;
        if !matches!(
            state,
            "quarantined" | "restoring" | "restored" | "interrupted" | "partial"
        ) {
            return Err(BrokerError::protocol("invalid quarantine state", None));
        }
        if boolean(entry, "restorable")? && state != "quarantined" {
            return Err(BrokerError::protocol(
                "contradictory quarantine restorability",
                None,
            ));
        }
        string(entry, "created_at", 64)?;
        string(entry, "updated_at", 64)?;
    }
    nullable_string(object, "next_cursor", 256)
}

fn validate_vault_list(value: &Value) -> Result<(), BrokerError> {
    let object = exact_object(value, &["sources", "next_cursor", "local_only_warning"])?;
    let sources = array(object, "sources")?;
    if sources.len() > 500 {
        return Err(BrokerError::protocol("too many vault sources", None));
    }
    for source in sources {
        let source = exact_object(source, &["source_id", "format", "capabilities", "revision"])?;
        string(source, "source_id", 256)?;
        if !matches!(
            string(source, "format", 32)?,
            "json" | "jsonl" | "sqlite" | "chroma" | "faiss" | "unsupported"
        ) {
            return Err(BrokerError::protocol("invalid vault format", None));
        }
        validate_vault_capabilities(required(source, "capabilities")?)?;
        validate_digest(string(source, "revision", 64)?)?;
    }
    nullable_string(object, "next_cursor", 256)?;
    validate_vault_warning(object)
}

fn validate_vault_query(value: &Value) -> Result<(), BrokerError> {
    let object = exact_object(
        value,
        &["records", "next_cursor", "total", "local_only_warning"],
    )?;
    let records = array(object, "records")?;
    if records.len() > 500 {
        return Err(BrokerError::protocol("too many vault records", None));
    }
    for record in records {
        validate_vault_record(record)?;
    }
    nullable_string(object, "next_cursor", 256)?;
    unsigned(object, "total")?;
    validate_vault_warning(object)
}

fn validate_vault_record(value: &Value) -> Result<(), BrokerError> {
    let object = object_with_optional_fields(
        value,
        &[
            "record_id",
            "namespace",
            "content",
            "metadata",
            "embedding_present",
            "source_revision",
        ],
        &["editable_fields"],
    )?;
    string(object, "record_id", 256)?;
    string(object, "namespace", 256)?;
    bounded_string_value(required(object, "content")?, 65_536)?;
    let metadata = required(object, "metadata")?
        .as_object()
        .ok_or_else(|| BrokerError::protocol("invalid metadata", None))?;
    if metadata.len() > 256 {
        return Err(BrokerError::protocol("metadata limit", None));
    }
    boolean(object, "embedding_present")?;
    validate_digest(string(object, "source_revision", 64)?)?;
    if object.contains_key("editable_fields") {
        let fields = array(object, "editable_fields")?;
        if fields.len() > 128 {
            return Err(BrokerError::protocol("too many editable fields", None));
        }
        for field in fields {
            let field = exact_object(field, &["field", "kind", "value_type", "value"])?;
            string(field, "field", 128)?;
            if !matches!(
                string(field, "kind", 32)?,
                "update_content" | "update_field" | "update_metadata"
            ) {
                return Err(BrokerError::protocol("invalid editable operation", None));
            }
            let value = required(field, "value")?;
            let value_matches_type = match string(field, "value_type", 16)? {
                "string" => value
                    .as_str()
                    .is_some_and(|value| value.chars().count() <= 65_536),
                "number" => value.is_number(),
                "boolean" => value.is_boolean(),
                "null" => value.is_null(),
                _ => false,
            };
            if !value_matches_type {
                return Err(BrokerError::protocol("editable scalar type mismatch", None));
            }
        }
    }
    Ok(())
}

fn validate_vault_authority(object: &Map<String, Value>) -> Result<(), BrokerError> {
    for field in ["source_id", "record_id", "snapshot_id"] {
        if let Some(value) = object.get(field)
            && !value.is_null()
        {
            validate_identifier(bounded_string_value(value, 256)?)?;
        }
    }
    for field in ["before_revision", "after_revision"] {
        if object.contains_key(field) {
            nullable_digest(object, field)?;
        }
    }
    if object.contains_key("backup_verified") {
        boolean(object, "backup_verified")?;
    }
    if object.contains_key("diff") {
        let diffs = array(object, "diff")?;
        if diffs.len() > 8 {
            return Err(BrokerError::protocol("too many memory diffs", None));
        }
        for diff in diffs {
            let diff = exact_object(
                diff,
                &[
                    "field_name",
                    "old_hash",
                    "new_hash",
                    "old_preview",
                    "new_preview",
                ],
            )?;
            string(diff, "field_name", 128)?;
            validate_digest(string(diff, "old_hash", 64)?)?;
            validate_digest(string(diff, "new_hash", 64)?)?;
            for field in ["old_preview", "new_preview"] {
                if string(diff, field, 32)? != "[REDACTED]" {
                    return Err(BrokerError::protocol("unredacted memory diff", None));
                }
            }
        }
    }
    Ok(())
}

fn validate_vault_capabilities(value: &Value) -> Result<(), BrokerError> {
    let object = exact_object(
        value,
        &[
            "readable",
            "queryable",
            "editable",
            "snapshot",
            "restore",
            "reason",
        ],
    )?;
    for field in ["readable", "queryable", "editable", "snapshot", "restore"] {
        boolean(object, field)?;
    }
    nullable_string(object, "reason", 512)
}

fn validate_vault_warning(object: &Map<String, Value>) -> Result<(), BrokerError> {
    let warning = string(object, "local_only_warning", 512)?;
    if warning
        != "Changes affect only local user-controlled memory; they do not change provider safety, rate limits, account state, or guarantee continuation."
    {
        return Err(BrokerError::protocol("invalid vault warning", None));
    }
    Ok(())
}

fn valid_evidence_grade(value: &str) -> bool {
    matches!(
        value,
        "confirmed" | "strong" | "partial" | "signature_only" | "insufficient"
    )
}

fn validate_settings(value: &Value) -> Result<(), BrokerError> {
    let result = exact_object(value, &["settings", "revision"])?;
    unsigned(result, "revision")?;
    let object = exact_object(
        required(result, "settings")?,
        &[
            "scan_interval_seconds",
            "heartbeat_grace_seconds",
            "retention_days",
            "include_unmanaged_candidates",
            "appearance",
            "reduced_motion",
        ],
    )?;
    let scan = unsigned(object, "scan_interval_seconds")?;
    let heartbeat = unsigned(object, "heartbeat_grace_seconds")?;
    let retention = unsigned(object, "retention_days")?;
    if !(5..=3_600).contains(&scan)
        || !(10..=86_400).contains(&heartbeat)
        || !(1..=365).contains(&retention)
    {
        return Err(BrokerError::protocol("invalid settings range", None));
    }
    boolean(object, "include_unmanaged_candidates")?;
    if !matches!(
        string(object, "appearance", 16)?,
        "system" | "light" | "dark"
    ) {
        return Err(BrokerError::protocol("invalid appearance", None));
    }
    boolean(object, "reduced_motion")?;
    Ok(())
}

fn exact_object<'a>(
    value: &'a Value,
    fields: &[&str],
) -> Result<&'a Map<String, Value>, BrokerError> {
    let object = value
        .as_object()
        .ok_or_else(|| BrokerError::protocol("expected object", None))?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(BrokerError::protocol("unexpected result fields", None));
    }
    Ok(object)
}

fn object_with_optional_fields<'a>(
    value: &'a Value,
    required_fields: &[&str],
    optional_fields: &[&str],
) -> Result<&'a Map<String, Value>, BrokerError> {
    let object = value
        .as_object()
        .ok_or_else(|| BrokerError::protocol("expected object", None))?;
    if required_fields
        .iter()
        .any(|field| !object.contains_key(*field))
        || object.keys().any(|field| {
            !required_fields.contains(&field.as_str()) && !optional_fields.contains(&field.as_str())
        })
    {
        return Err(BrokerError::protocol("unexpected result fields", None));
    }
    Ok(object)
}

fn required<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a Value, BrokerError> {
    object
        .get(field)
        .ok_or_else(|| BrokerError::protocol("missing result field", None))
}

fn array<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a Vec<Value>, BrokerError> {
    required(object, field)?
        .as_array()
        .ok_or_else(|| BrokerError::protocol("expected array", None))
}

fn string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    maximum: usize,
) -> Result<&'a str, BrokerError> {
    let value = required(object, field)?
        .as_str()
        .ok_or_else(|| BrokerError::protocol("expected string", None))?;
    if value.is_empty() || value.chars().count() > maximum {
        return Err(BrokerError::protocol("string limit", None));
    }
    Ok(value)
}

fn nullable_string(
    object: &Map<String, Value>,
    field: &str,
    maximum: usize,
) -> Result<(), BrokerError> {
    let value = required(object, field)?;
    if value.is_null() {
        return Ok(());
    }
    bounded_string_value(value, maximum).map(|_| ())
}

fn bounded_string_value(value: &Value, maximum: usize) -> Result<&str, BrokerError> {
    let value = value
        .as_str()
        .ok_or_else(|| BrokerError::protocol("expected string", None))?;
    if value.chars().count() > maximum {
        return Err(BrokerError::protocol("string limit", None));
    }
    Ok(value)
}

fn boolean(object: &Map<String, Value>, field: &str) -> Result<bool, BrokerError> {
    required(object, field)?
        .as_bool()
        .ok_or_else(|| BrokerError::protocol("expected boolean", None))
}

fn unsigned(object: &Map<String, Value>, field: &str) -> Result<u64, BrokerError> {
    required(object, field)?
        .as_u64()
        .ok_or_else(|| BrokerError::protocol("expected unsigned integer", None))
}

fn nullable_unsigned(object: &Map<String, Value>, field: &str) -> Result<(), BrokerError> {
    let value = required(object, field)?;
    if value.is_null() || value.as_u64().is_some_and(|number| number > 0) {
        Ok(())
    } else {
        Err(BrokerError::protocol(
            "expected nullable unsigned integer",
            None,
        ))
    }
}

fn nullable_digest(object: &Map<String, Value>, field: &str) -> Result<(), BrokerError> {
    let value = required(object, field)?;
    if value.is_null() {
        return Ok(());
    }
    let digest = value
        .as_str()
        .ok_or_else(|| BrokerError::protocol("expected nullable digest", None))?;
    validate_digest(digest).map_err(|_| BrokerError::protocol("invalid digest", None))
}

fn number(object: &Map<String, Value>, field: &str) -> Result<f64, BrokerError> {
    required(object, field)?
        .as_f64()
        .filter(|value| value.is_finite())
        .ok_or_else(|| BrokerError::protocol("expected finite number", None))
}

pub(crate) struct BrokerState {
    gate: Mutex<()>,
}

impl Default for BrokerState {
    fn default() -> Self {
        Self {
            gate: Mutex::new(()),
        }
    }
}

impl BrokerState {
    pub(crate) async fn request(
        &self,
        launch: &LaunchSpec,
        request: RendererRequest,
    ) -> Result<EngineReply, BrokerError> {
        self.request_inner(launch, request, None, None).await
    }

    async fn request_inner(
        &self,
        launch: &LaunchSpec,
        request: RendererRequest,
        queued_observer: Option<oneshot::Sender<()>>,
        spawn_observer: Option<oneshot::Sender<u32>>,
    ) -> Result<EngineReply, BrokerError> {
        request.validate()?;
        if let Some(observer) = queued_observer {
            let _ = observer.send(());
        }
        let _guard = self.gate.lock().await;
        invoke_launch(launch, &request, None, spawn_observer).await
    }

    #[cfg(test)]
    pub(crate) async fn request_with_observers_for_test(
        &self,
        launch: &LaunchSpec,
        request: RendererRequest,
        queued_observer: oneshot::Sender<()>,
        spawn_observer: oneshot::Sender<u32>,
    ) -> Result<EngineReply, BrokerError> {
        self.request_inner(launch, request, Some(queued_observer), Some(spawn_observer))
            .await
    }
}

async fn invoke_launch(
    launch: &LaunchSpec,
    request: &RendererRequest,
    timeout_override: Option<Duration>,
    spawn_observer: Option<oneshot::Sender<u32>>,
) -> Result<EngineReply, BrokerError> {
    let request_id = Uuid::new_v4();
    let method = request.method();
    let envelope = request.engine_envelope(request_id)?;
    let mut frame = serde_json::to_vec(&envelope).map_err(|_| BrokerError::invalid_request())?;
    if frame.is_empty() || frame.len() > MAX_ENGINE_INPUT_BYTES {
        return Err(BrokerError::invalid_request());
    }
    frame.push(b'\n');

    // Hold the authenticated resource handles through process creation and execution. On Windows
    // their no-write/no-delete sharing prevents a verified file from being replaced before launch.
    let verified_bundle = launch.verify_before_spawn().await?;
    let binds_verified_executable = launch.integrity_binds_executable();
    let command_executable = if binds_verified_executable {
        verified_bundle
            .as_ref()
            .and_then(VerifiedBundle::pinned_executable_path)
            .unwrap_or_else(|| launch.executable.clone())
    } else {
        launch.executable.clone()
    };
    let command_current_dir = if binds_verified_executable {
        verified_bundle
            .as_ref()
            .and_then(VerifiedBundle::pinned_current_dir)
            .unwrap_or_else(|| launch.current_dir.clone())
    } else {
        launch.current_dir.clone()
    };
    let mut command = Command::new(command_executable);
    command
        .args(&launch.arguments)
        .current_dir(command_current_dir)
        .env_clear()
        .envs(launch.environment.iter().cloned())
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(windows)]
    let windows_containment = ChildContainment::prepare(&mut command)?;
    #[cfg(unix)]
    let mut prepared_unix_containment = UnixChildContainment::prepare(&mut command)?;
    if binds_verified_executable
        && verified_bundle
            .as_ref()
            .is_some_and(|verified| verified.pinned_executable_path().is_none())
    {
        verified_bundle
            .as_ref()
            .ok_or_else(BrokerError::engine_unavailable)?
            .revalidate_executable_identity(&launch.executable)
            .map_err(|_| BrokerError::engine_unavailable())?;
    }
    #[cfg(all(test, unix))]
    let _child_to_containment_drop_delay = TestChildToContainmentDropDelay;
    let mut child = command
        .spawn()
        .map_err(|_| BrokerError::engine_unavailable())?;
    #[cfg(unix)]
    if let Err(error) = prepared_unix_containment.spawned(&child) {
        kill_and_reap(
            &mut child,
            #[cfg(unix)]
            &mut prepared_unix_containment,
        )
        .await;
        return Err(error);
    }
    // This post-spawn binding must be declared after `child`: cancellation drops it first, so the
    // private PGID is consumed and signalled before Tokio's Child drop guard can reap the leader.
    #[cfg(unix)]
    let mut unix_containment = prepared_unix_containment;
    #[cfg(windows)]
    let _containment = match windows_containment.activate(&child) {
        Ok(()) => windows_containment,
        Err(error) => {
            kill_and_reap(
                &mut child,
                #[cfg(unix)]
                &mut unix_containment,
            )
            .await;
            return Err(error);
        }
    };
    if let Some(observer) = spawn_observer {
        let pid = child.id().ok_or_else(BrokerError::engine_unavailable)?;
        let _ = observer.send(pid);
    }
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(BrokerError::engine_unavailable)?;
    if stdin.write_all(&frame).await.is_err() || stdin.shutdown().await.is_err() {
        kill_and_reap(
            &mut child,
            #[cfg(unix)]
            &mut unix_containment,
        )
        .await;
        return Err(BrokerError::after_dispatch(
            method,
            request_id,
            BrokerError::engine_unavailable(),
        ));
    }
    drop(stdin);
    let Some(stdout) = child.stdout.take() else {
        kill_and_reap(
            &mut child,
            #[cfg(unix)]
            &mut unix_containment,
        )
        .await;
        return Err(BrokerError::after_dispatch(
            method,
            request_id,
            BrokerError::engine_unavailable(),
        ));
    };
    let Some(stderr) = child.stderr.take() else {
        kill_and_reap(
            &mut child,
            #[cfg(unix)]
            &mut unix_containment,
        )
        .await;
        return Err(BrokerError::after_dispatch(
            method,
            request_id,
            BrokerError::engine_unavailable(),
        ));
    };
    let collection = timeout(
        timeout_override.unwrap_or_else(|| method.timeout()),
        collect_child(
            &mut child,
            stdout,
            stderr,
            #[cfg(unix)]
            &mut unix_containment,
        ),
    )
    .await;
    let (status, stdout, _stderr) = match collection {
        Err(_) => {
            kill_and_reap(
                &mut child,
                #[cfg(unix)]
                &mut unix_containment,
            )
            .await;
            return Err(BrokerError::timeout(method, request_id));
        }
        Ok(Err(CollectError::Limit)) => {
            kill_and_reap(
                &mut child,
                #[cfg(unix)]
                &mut unix_containment,
            )
            .await;
            return Err(BrokerError::after_dispatch(
                method,
                request_id,
                BrokerError::output_too_large(request_id),
            ));
        }
        Ok(Err(CollectError::Io)) => {
            kill_and_reap(
                &mut child,
                #[cfg(unix)]
                &mut unix_containment,
            )
            .await;
            return Err(BrokerError::after_dispatch(
                method,
                request_id,
                BrokerError::engine_unavailable(),
            ));
        }
        Ok(Ok(outcome)) => outcome,
    };
    drop(verified_bundle);
    let response = validate_response_for_request(request_id, request, &stdout)
        .map_err(|error| BrokerError::after_dispatch(method, request_id, error))?;
    match response {
        ValidatedResponse::Error(error) => {
            let mut error = BrokerError::from_protocol(error, request_id);
            if method.mutates()
                && matches!(
                    error.code,
                    BrokerErrorCode::Partial | BrokerErrorCode::Internal
                )
            {
                error.reconcile_required = true;
            }
            Err(error)
        }
        ValidatedResponse::Success(result) => {
            if !status.success() {
                return Err(BrokerError::after_dispatch(
                    method,
                    request_id,
                    BrokerError::engine_unavailable(),
                ));
            }
            Ok(EngineReply {
                request_id,
                method: method.as_str().to_owned(),
                result,
            })
        }
    }
}

#[cfg(test)]
pub(crate) async fn serialize_test_engine_processes() -> tokio::sync::MutexGuard<'static, ()> {
    TEST_ENGINE_PROCESS_GATE.lock().await
}

#[derive(Debug)]
enum CollectError {
    Io,
    Limit,
}

async fn collect_child(
    child: &mut Child,
    stdout: impl AsyncRead + Unpin,
    stderr: impl AsyncRead + Unpin,
    #[cfg(unix)] containment: &mut UnixChildContainment,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), CollectError> {
    #[cfg(unix)]
    {
        let process_group = containment.process_group.ok_or(CollectError::Io)?;
        let exited = wait_for_child_exit_without_reaping(process_group);
        let output = async {
            tokio::try_join!(
                read_bounded(stdout, MAX_ENGINE_OUTPUT_BYTES),
                read_bounded(stderr, MAX_ENGINE_STDERR_BYTES),
            )
        };
        tokio::pin!(exited);
        tokio::pin!(output);
        let mut completed_output = None;
        loop {
            tokio::select! {
                result = &mut exited => {
                    result?;
                    break;
                }
                result = &mut output, if completed_output.is_none() => {
                    completed_output = Some(result?);
                }
            }
        }

        // `waitid(..., WNOWAIT)` left the original group leader waitable, so its PID cannot have
        // been reused. Terminate descendants while that identity proof is still retained, then reap.
        containment.terminate_group();
        let (stdout, stderr) = match completed_output {
            Some(output) => output,
            None => output.await?,
        };
        let status = child.wait().await.map_err(|_| CollectError::Io)?;
        Ok((status, stdout, stderr))
    }

    #[cfg(not(unix))]
    {
        let wait = async { child.wait().await.map_err(|_| CollectError::Io) };
        let output = async {
            tokio::try_join!(
                read_bounded(stdout, MAX_ENGINE_OUTPUT_BYTES),
                read_bounded(stderr, MAX_ENGINE_STDERR_BYTES),
            )
        };
        let (status, (stdout, stderr)) = tokio::try_join!(wait, output)?;
        Ok((status, stdout, stderr))
    }
}

#[cfg(unix)]
async fn wait_for_child_exit_without_reaping(pid: i32) -> Result<(), CollectError> {
    loop {
        // POSIX requires a zeroed result for WNOHANG when no child status is available. WNOWAIT
        // observes termination without consuming it, retaining the original PID as an identity token.
        let mut information: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `information` is writable for the call, `pid` is the positive child PID captured
        // after spawn, and WNOWAIT guarantees this observation does not reap the child.
        let outcome = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                std::ptr::addr_of_mut!(information),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if outcome == 0 {
            // SAFETY: waitid initialized the siginfo payload; a zero PID means WNOHANG saw no exit.
            if unsafe { information.si_pid() } == pid {
                return Ok(());
            }
        } else if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(CollectError::Io);
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn read_bounded(
    mut reader: impl AsyncRead + Unpin,
    maximum: usize,
) -> Result<Vec<u8>, CollectError> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .await
            .map_err(|_| CollectError::Io)?;
        if count == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(count) > maximum {
            return Err(CollectError::Limit);
        }
        output.extend_from_slice(&buffer[..count]);
    }
}

async fn kill_and_reap(child: &mut Child, #[cfg(unix)] containment: &mut UnixChildContainment) {
    #[cfg(unix)]
    containment.terminate_group();
    let _ = child.start_kill();
    let _ = timeout(REAP_TIMEOUT, child.wait()).await;
}

#[cfg(test)]
pub(crate) async fn invoke_launch_for_test(
    launch: &LaunchSpec,
    request: &RendererRequest,
    duration: Duration,
) -> Result<EngineReply, BrokerError> {
    invoke_launch(launch, request, Some(duration), None).await
}

#[cfg(test)]
pub(crate) async fn invoke_launch_for_test_with_spawn_observer(
    launch: &LaunchSpec,
    request: &RendererRequest,
    duration: Duration,
    observer: oneshot::Sender<u32>,
) -> Result<EngineReply, BrokerError> {
    invoke_launch(launch, request, Some(duration), Some(observer)).await
}
