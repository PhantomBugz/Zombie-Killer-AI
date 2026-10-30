use std::ffi::OsString;
use std::path::Path;
use std::process::Command as StandardCommand;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[cfg(windows)]
use crate::engine::ChildContainment;
use crate::engine::serialize_test_engine_processes;
use crate::engine::{
    BrokerErrorCode, BrokerState, EngineMethod, LaunchSpec, RendererRequest, development_launch,
    invoke_launch_for_test, invoke_launch_for_test_with_spawn_observer, validate_response,
    validate_response_for_request,
};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject};

// Non-timeout integration assertions use the longest production method budget. The dedicated
// 250 ms timeout test below remains the behavioral deadline check; these tests should not measure
// unrelated debug-interpreter scheduling on a loaded or freshly built host.
const PROCESS_INTEGRATION_TIMEOUT: Duration = Duration::from_secs(45);
const PROCESS_EVENT_TIMEOUT: Duration = Duration::from_secs(15);

fn system_info_request() -> RendererRequest {
    serde_json::from_value(json!({"method": "system.info", "payload": {}})).unwrap()
}

fn doctor_request() -> RendererRequest {
    serde_json::from_value(json!({"method": "doctor", "payload": {}})).unwrap()
}

fn scan_request() -> RendererRequest {
    serde_json::from_value(json!({
        "method": "scan.list",
        "payload": {"includeUnmanaged": false, "limit": 1}
    }))
    .unwrap()
}

fn action_execute_request() -> RendererRequest {
    serde_json::from_value(json!({
        "method": "action.execute",
        "payload": {"planId": "plan-1", "digest": "a".repeat(64)}
    }))
    .unwrap()
}

fn action_plan_request() -> RendererRequest {
    serde_json::from_value(json!({
        "method": "action.plan",
        "payload": {
            "agentId": "agent-1",
            "mode": "kill",
            "target": {
                "pid": 4242,
                "processInstanceId": "b".repeat(64)
            }
        }
    }))
    .unwrap()
}

fn settings_update_request() -> RendererRequest {
    serde_json::from_value(json!({
        "method": "settings.update",
        "payload": {
            "expectedRevision": 7,
            "changes": {"appearance": "dark", "reducedMotion": true}
        }
    }))
    .unwrap()
}

fn python_launch(script: &str, directory: &Path) -> LaunchSpec {
    let development = development_launch(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    let environment = vec![
        (
            OsString::from("PYTHONDONTWRITEBYTECODE"),
            OsString::from("1"),
        ),
        (OsString::from("PYTHONNOUSERSITE"), OsString::from("1")),
        (OsString::from("PYTHONUTF8"), OsString::from("1")),
    ];
    // Match the production allowlist: Windows asyncio needs the OS root to initialize Winsock.
    #[cfg(windows)]
    let environment = {
        let mut environment = environment;
        for key in ["SYSTEMROOT", "WINDIR"] {
            if let Some(value) = std::env::var_os(key) {
                environment.push((OsString::from(key), value));
            }
        }
        environment
    };
    LaunchSpec::test_only(
        development.executable().to_path_buf(),
        vec!["-I".into(), "-c".into(), script.into()],
        directory.to_path_buf(),
        environment,
    )
}

fn integrity_fixture(root: &Path) -> (String, std::path::PathBuf) {
    let executable_name = if cfg!(windows) {
        "zombie-killer-engine.exe"
    } else {
        "zombie-killer-engine"
    };
    let executable = root.join(executable_name);
    std::fs::write(&executable, b"fixed runtime resource").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let platform = match std::env::consts::OS {
        "macos" => "darwin",
        value => value,
    };
    let bytes = std::fs::read(&executable).unwrap();
    let manifest = json!({
        "architecture": std::env::consts::ARCH,
        "entries": [{
            "path": executable_name,
            "sha256": format!("{:x}", Sha256::digest(&bytes)),
            "size": bytes.len(),
            "type": "file"
        }],
        "format": "pyinstaller-onedir",
        "platform": platform,
        "pyinstaller": "6.18.0",
        "python": "3.12.10",
        "source_date_epoch": "1700000000"
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    std::fs::write(root.join("BUILD-MANIFEST.json"), &manifest_bytes).unwrap();
    (format!("{:x}", Sha256::digest(&manifest_bytes)), executable)
}

fn success_script(delay_seconds: f32, stderr: &str, exit_code: i32) -> String {
    format!(
        r#"import json,sys,time
r=json.loads(sys.stdin.readline())
time.sleep({delay_seconds})
sys.stderr.write({stderr:?})
o={{'protocol_version':'1.0','request_id':r['request_id'],'method':r['method'],'ok':True,'result':{{'engine_version':'0.1.0-alpha.1','protocol_version':'1.0','platform':'test','python':'3.12','local_only':True,'network_listener':False,'memory_warning':'Local only.'}},'error':None}}
sys.stdout.write(json.dumps(o,separators=(',',':')))
sys.exit({exit_code})"#,
    )
}

#[test]
fn request_enum_rejects_unknown_variants_and_authority_fields() {
    let unknown = serde_json::from_value::<RendererRequest>(json!({
        "method": "shell.run", "payload": {"executable": "powershell"}
    }));
    let injected = serde_json::from_value::<RendererRequest>(json!({
        "method": "scan.list", "payload": {"includeUnmanaged": true, "limit": 10, "executable": "python"}
    }));
    let outer_injected = serde_json::from_value::<RendererRequest>(json!({
        "method": "system.info", "payload": {}, "context": {"authority": "renderer"}
    }));

    assert!(unknown.is_err());
    assert!(injected.is_err());
    assert!(outer_injected.is_err());
}

#[test]
fn completion_requests_forward_typed_payloads_in_engine_case() {
    let cases = [
        (
            "receipt.get",
            json!({"receiptId":"receipt-1"}),
            json!({"receipt_id":"receipt-1"}),
        ),
        (
            "vault.register",
            json!({"path":"C:/fixtures/store.json"}),
            json!({"path":"C:/fixtures/store.json"}),
        ),
        (
            "vault.probe",
            json!({"path":"C:/fixtures/store.json"}),
            json!({"path":"C:/fixtures/store.json"}),
        ),
        (
            "vault.mutation.plan",
            json!({"sourceId":"source-1","expectedRevision":"a".repeat(64),"operation":"update_field","recordId":"record-1","field":"score","metadataKey":null,"value":42}),
            json!({"source_id":"source-1","expected_revision":"a".repeat(64),"operation":"update_field","record_id":"record-1","field":"score","metadata_key":null,"value":42}),
        ),
        (
            "vault.snapshot.list",
            json!({"sourceId":"source-1","limit":100}),
            json!({"source_id":"source-1","limit":100}),
        ),
        (
            "vault.restore.plan",
            json!({"sourceId":"source-1","snapshotId":"snapshot-1","snapshotDigest":"b".repeat(64),"expectedRevision":"a".repeat(64)}),
            json!({"source_id":"source-1","snapshot_id":"snapshot-1","snapshot_digest":"b".repeat(64),"expected_revision":"a".repeat(64)}),
        ),
        (
            "quarantine.resource-list",
            json!({"agentId":"agent-1","expectedPid":4242,"expectedProcessInstanceId":"c".repeat(64)}),
            json!({"agent_id":"agent-1","expected_pid":4242,"expected_process_instance_id":"c".repeat(64)}),
        ),
        (
            "quarantine.plan",
            json!({"agentId":"agent-1","resourceIndex":63,"expectedDeclarationDigest":"d".repeat(64),"expectedPid":4242,"expectedProcessInstanceId":"c".repeat(64)}),
            json!({"agent_id":"agent-1","resource_index":63,"expected_declaration_digest":"d".repeat(64),"expected_pid":4242,"expected_process_instance_id":"c".repeat(64)}),
        ),
        (
            "quarantine.restore-plan",
            json!({"entryId":"entry-1"}),
            json!({"entry_id":"entry-1"}),
        ),
        (
            "diagnostics.export-plan",
            json!({"destination":"C:/fixtures/diagnostics.json","includeReceipts":true,"includeSettings":false}),
            json!({"destination":"C:/fixtures/diagnostics.json","include_receipts":true,"include_settings":false}),
        ),
        (
            "vault.mutation.execute",
            json!({"planId":"plan-1","digest":"a".repeat(64)}),
            json!({"plan_id":"plan-1","digest":"a".repeat(64)}),
        ),
        (
            "vault.restore.execute",
            json!({"planId":"plan-1","digest":"a".repeat(64)}),
            json!({"plan_id":"plan-1","digest":"a".repeat(64)}),
        ),
        (
            "quarantine.execute",
            json!({"planId":"plan-1","digest":"a".repeat(64)}),
            json!({"plan_id":"plan-1","digest":"a".repeat(64)}),
        ),
        (
            "quarantine.restore-execute",
            json!({"planId":"plan-1","digest":"a".repeat(64)}),
            json!({"plan_id":"plan-1","digest":"a".repeat(64)}),
        ),
        (
            "diagnostics.export-execute",
            json!({"planId":"plan-1","digest":"a".repeat(64)}),
            json!({"plan_id":"plan-1","digest":"a".repeat(64)}),
        ),
    ];
    for (method, payload, expected) in cases {
        let request: RendererRequest =
            serde_json::from_value(json!({"method":method,"payload":payload}))
                .unwrap_or_else(|error| panic!("{method} was rejected: {error}"));
        let envelope = request.engine_envelope(Uuid::new_v4()).unwrap();
        assert_eq!(envelope["method"], method);
        assert_eq!(envelope["payload"], expected, "{method} payload mismatch");
    }
}

#[test]
fn completion_cleanup_review_requires_exact_declaration_and_paired_process_identity() {
    let valid: RendererRequest = serde_json::from_value(json!({"method":"quarantine.plan","payload":{"agentId":"agent-1","resourceIndex":0,"expectedDeclarationDigest":"d".repeat(64)}})).unwrap();
    assert_eq!(
        valid.engine_envelope(Uuid::new_v4()).unwrap()["payload"],
        json!({"agent_id":"agent-1","resource_index":0,"expected_declaration_digest":"d".repeat(64)})
    );
    for method in ["quarantine.resource-list", "quarantine.plan"] {
        for binding in [
            json!({"expectedPid":4242}),
            json!({"expectedProcessInstanceId":"c".repeat(64)}),
            json!({"expectedPid":null,"expectedProcessInstanceId":null}),
            json!({"expectedPid":0,"expectedProcessInstanceId":"c".repeat(64)}),
            json!({"expectedPid":4242,"expectedProcessInstanceId":"invalid"}),
        ] {
            let mut payload = json!({"agentId":"agent-1"});
            if method == "quarantine.plan" {
                payload["resourceIndex"] = json!(0);
                payload["expectedDeclarationDigest"] = json!("d".repeat(64));
            }
            payload
                .as_object_mut()
                .unwrap()
                .extend(binding.as_object().unwrap().clone());
            assert!(
                serde_json::from_value::<RendererRequest>(
                    json!({"method":method,"payload":payload})
                )
                .map_or(true, |request| request.validate().is_err()),
                "accepted invalid cleanup binding"
            );
        }
    }
    for digest in [None, Some(json!(null)), Some(json!("invalid"))] {
        let mut payload = json!({"agentId":"agent-1","resourceIndex":0});
        if let Some(digest) = digest {
            payload["expectedDeclarationDigest"] = digest;
        }
        assert!(
            serde_json::from_value::<RendererRequest>(
                json!({"method":"quarantine.plan","payload":payload})
            )
            .map_or(true, |request| request.validate().is_err())
        );
    }
}

#[test]
fn completion_cleanup_resource_results_preserve_bounded_review_digests() {
    let request: RendererRequest = serde_json::from_value(
        json!({"method":"quarantine.resource-list","payload":{"agentId":"agent-1"}}),
    )
    .unwrap();
    let request_id = Uuid::new_v4();
    let resource = json!({"resource_index":0,"kind":"temporary","resource_type":"file","cleanup_available":true,"reason":"Available for review.","declaration_digest":"d".repeat(64)});
    let result = json!({"agent_id":"agent-1","resources":[resource],"returned":1});
    let valid = workflow_response(request_id, "quarantine.resource-list", result);
    assert!(
        validate_response_for_request(request_id, &request, valid.to_string().as_bytes()).is_ok()
    );
    for digest in [json!(null), json!("d".repeat(64))] {
        let mut unavailable = valid.clone();
        unavailable["result"]["resources"][0]["cleanup_available"] = json!(false);
        unavailable["result"]["resources"][0]["declaration_digest"] = digest;
        assert!(
            validate_response_for_request(request_id, &request, unavailable.to_string().as_bytes())
                .is_ok()
        );
    }
    let mut missing_authority = valid.clone();
    missing_authority["result"]["resources"][0]["declaration_digest"] = json!(null);
    assert!(
        validate_response_for_request(
            request_id,
            &request,
            missing_authority.to_string().as_bytes()
        )
        .is_err()
    );
    let mut malformed = valid;
    malformed["result"]["resources"][0]["declaration_digest"] = json!("invalid");
    assert!(
        validate_response_for_request(request_id, &request, malformed.to_string().as_bytes())
            .is_err()
    );
}

#[test]
fn completion_requests_reject_unbounded_paths_non_scalar_edits_and_resource_paths() {
    let invalid = [
        json!({"method":"vault.register","payload":{"path":"x".repeat(4097)}}),
        json!({"method":"vault.probe","payload":{"path":" "}}),
        json!({"method":"diagnostics.export-plan","payload":{"destination":"x".repeat(4097),"includeReceipts":true,"includeSettings":true}}),
        json!({"method":"vault.mutation.plan","payload":{"sourceId":"source-1","expectedRevision":"invalid","operation":"update_content","recordId":"record-1","value":"edit"}}),
        json!({"method":"vault.mutation.plan","payload":{"sourceId":"source-1","expectedRevision":"a".repeat(64),"operation":"update_content","recordId":"record-1","value":{"nested":"edit"}}}),
        json!({"method":"vault.mutation.plan","payload":{"sourceId":"source-1","expectedRevision":"a".repeat(64),"operation":"raw_sql","recordId":"record-1","value":"edit"}}),
        json!({"method":"vault.snapshot.list","payload":{"sourceId":"source-1","limit":501}}),
        json!({"method":"quarantine.plan","payload":{"agentId":"agent-1","resourceIndex":64,"expectedDeclarationDigest":"d".repeat(64)}}),
        json!({"method":"quarantine.plan","payload":{"agentId":"agent-1","resourceIndex":0,"expectedDeclarationDigest":"d".repeat(64),"path":"C:/fixtures/delete"}}),
    ];
    for value in invalid {
        let rejected = match serde_json::from_value::<RendererRequest>(value.clone()) {
            Ok(request) => request.validate().is_err(),
            Err(_) => true,
        };
        assert!(rejected, "invalid completion request was accepted: {value}");
    }
}

const VAULT_WARNING: &str = "Changes affect only local user-controlled memory; they do not change provider safety, rate limits, account state, or guarantee continuation.";

fn workflow_response(request_id: Uuid, method: &str, result: Value) -> Value {
    json!({"protocol_version":"1.0","request_id":request_id,"method":method,"ok":true,"result":result,"error":null})
}

fn workflow_receipt() -> Value {
    json!({"receipt_id":"receipt-1","plan_id":"plan-1","outcome":"completed","certainty":"verified","action_issued":true,"partial_failures":[],"created_at":"2026-10-02T12:00:00Z"})
}

fn real_service_launch(directory: &Path) -> LaunchSpec {
    let root = serde_json::to_string(&directory.to_string_lossy()).unwrap();
    let script = format!(
        r#"import json,sys
from pathlib import Path
from zombie_killer_engine.paths import AppPaths
from zombie_killer_engine.service import Capability,RequestContext,RequestEnvelope,build_default_service
root=Path({root})
paths=AppPaths(data_dir=root/'data',state_dir=root/'state',runtime_dir=root/'runtime',backups_dir=root/'backups',graveyard_dir=root/'graveyard')
assert not paths.ensure()
request=RequestEnvelope.model_validate_json(sys.stdin.readline())
with build_default_service(paths=paths) as service:
 response=service.dispatch(request,context=RequestContext(capability=Capability.EXECUTION,local_control=True))
sys.stdout.write(response.model_dump_json())"#
    );
    python_launch(&script, directory)
}

async fn call_real_service(launch: &LaunchSpec, method: &str, payload: Value) -> Value {
    let request: RendererRequest =
        serde_json::from_value(json!({"method":method,"payload":payload})).unwrap();
    let reply = invoke_launch_for_test(launch, &request, PROCESS_INTEGRATION_TIMEOUT)
        .await
        .unwrap_or_else(|error| panic!("real {method} failed: {:?}", error.dto()));
    serde_json::to_value(reply).unwrap()["result"].clone()
}

async fn real_service_error(launch: &LaunchSpec, method: &str, payload: Value) -> BrokerErrorCode {
    let request: RendererRequest =
        serde_json::from_value(json!({"method":method,"payload":payload})).unwrap();
    invoke_launch_for_test(launch, &request, PROCESS_INTEGRATION_TIMEOUT)
        .await
        .unwrap_err()
        .code()
}

#[tokio::test]
async fn completion_real_service_mutation_restore_and_export_survive_one_shot_launches() {
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("store.json");
    let original = br#"[{"id":"record-1","content":"before"}]"#;
    std::fs::write(&source, original).unwrap();
    let launch = real_service_launch(directory.path());
    let path = source.to_string_lossy();
    let probe = call_real_service(&launch, "vault.probe", json!({"path":path})).await;
    assert_eq!(probe["format"], "json");
    assert_eq!(probe["read_only"], true);
    let registered = call_real_service(&launch, "vault.register", json!({"path":path})).await;
    assert_eq!(registered["recognized"], true);
    let sources =
        call_real_service(&launch, "vault.list", json!({"limit":100,"cursor":null})).await;
    let source_id = sources["sources"][0]["source_id"].as_str().unwrap();
    let query = call_real_service(
        &launch,
        "vault.query",
        json!({"sourceId":source_id,"namespace":null,"text":null,"limit":100}),
    )
    .await;
    let record_id = query["records"][0]["record_id"].as_str().unwrap();
    let revision = query["records"][0]["source_revision"].as_str().unwrap();
    let read = call_real_service(
        &launch,
        "vault.get",
        json!({"sourceId":source_id,"recordId":record_id}),
    )
    .await;
    assert_eq!(read["record"]["content"], "before");
    assert!(
        read["record"]["editable_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field["kind"] == "update_content" && field["field"] == "content")
    );
    let plan = call_real_service(&launch, "vault.mutation.plan", json!({"sourceId":source_id,"expectedRevision":revision,"operation":"update_content","recordId":record_id,"value":"after"})).await;
    assert_eq!(plan["source_id"], source_id);
    assert_eq!(plan["before_revision"], revision);
    let executed = call_real_service(
        &launch,
        "vault.mutation.execute",
        json!({"planId":plan["plan_id"],"digest":plan["digest"]}),
    )
    .await;
    assert_eq!(executed["plan_id"], plan["plan_id"]);
    assert_eq!(executed["source_id"], source_id);
    assert_eq!(executed["record_id"], record_id);
    assert_eq!(executed["before_revision"], revision);
    assert_ne!(executed["after_revision"], executed["before_revision"]);
    let changed: Value = serde_json::from_slice(&std::fs::read(&source).unwrap()).unwrap();
    assert_eq!(changed[0]["content"], "after");
    assert_eq!(
        real_service_error(
            &launch,
            "vault.mutation.execute",
            json!({"planId":plan["plan_id"],"digest":plan["digest"]})
        )
        .await,
        BrokerErrorCode::Conflict
    );
    let receipt = call_real_service(
        &launch,
        "receipt.get",
        json!({"receiptId":executed["receipt_id"]}),
    )
    .await;
    assert_eq!(receipt["receipt_id"], executed["receipt_id"]);
    assert_eq!(receipt["kind"], "memory");
    let snapshots = call_real_service(
        &launch,
        "vault.snapshot.list",
        json!({"sourceId":source_id,"limit":100}),
    )
    .await;
    let snapshot = &snapshots["snapshots"][0];
    let current = call_real_service(
        &launch,
        "vault.get",
        json!({"sourceId":source_id,"recordId":record_id}),
    )
    .await;
    let restore = call_real_service(&launch, "vault.restore.plan", json!({"sourceId":source_id,"snapshotId":snapshot["snapshot_id"],"snapshotDigest":snapshot["digest"],"expectedRevision":current["record"]["source_revision"]})).await;
    let restored = call_real_service(
        &launch,
        "vault.restore.execute",
        json!({"planId":restore["plan_id"],"digest":restore["digest"]}),
    )
    .await;
    assert_eq!(restored["plan_id"], restore["plan_id"]);
    assert_eq!(restored["source_id"], source_id);
    assert!(restored["record_id"].is_null());
    assert_eq!(std::fs::read(&source).unwrap(), original);
    let initial_settings = call_real_service(&launch, "settings.get", json!({})).await;
    let updated_settings = call_real_service(&launch, "settings.update", json!({"expectedRevision":initial_settings["revision"],"changes":{"retentionDays":7,"includeUnmanagedCandidates":false}})).await;
    assert_eq!(updated_settings["settings"]["retention_days"], 7);
    let persisted_settings = call_real_service(&launch, "settings.get", json!({})).await;
    assert_eq!(persisted_settings["revision"], updated_settings["revision"]);
    assert_eq!(
        persisted_settings["settings"]["include_unmanaged_candidates"],
        false
    );
    let destination = directory.path().join("data/diagnostics.json");
    let export = call_real_service(&launch, "diagnostics.export-plan", json!({"destination":destination.to_string_lossy(),"includeReceipts":true,"includeSettings":true})).await;
    let exported = call_real_service(
        &launch,
        "diagnostics.export-execute",
        json!({"planId":export["plan_id"],"digest":export["digest"]}),
    )
    .await;
    assert_eq!(exported["plan_id"], export["plan_id"]);
    let export_receipt = call_real_service(
        &launch,
        "receipt.get",
        json!({"receiptId":exported["receipt_id"]}),
    )
    .await;
    assert_eq!(export_receipt["plan_id"], export["plan_id"]);
    assert_eq!(export_receipt["kind"], "diagnostics");
    let exported_bytes = std::fs::read(&destination).unwrap();
    let diagnostics: Value = serde_json::from_slice(&exported_bytes).unwrap();
    assert!(diagnostics.is_object());
    assert_eq!(real_service_error(&launch, "diagnostics.export-plan", json!({"destination":destination.to_string_lossy(),"includeReceipts":true,"includeSettings":true})).await, BrokerErrorCode::Conflict);
    assert_eq!(std::fs::read(&destination).unwrap(), exported_bytes);
}

#[tokio::test]
async fn completion_real_service_declared_file_and_directory_quarantine_restore() {
    let _process_guard = serialize_test_engine_processes().await;
    for directory_resource in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let root = serde_json::to_string(&directory.path().to_string_lossy()).unwrap();
        let is_directory = if directory_resource { "True" } else { "False" };
        let script = format!(
            r#"import json,os,sys
from datetime import UTC,datetime
from pathlib import Path
from zombie_killer.lease import current_process_identity,validate_temp_resource
from zombie_killer_engine.actions import process_instance_id
from zombie_killer_engine.models import ProcessIdentity
from zombie_killer_engine.paths import AppPaths,PosixPermissionBackend,WindowsPermissionBackend
from zombie_killer_engine.service import Capability,RequestContext,RequestEnvelope,build_default_service
root=Path({root})
paths=AppPaths(data_dir=root/'data',state_dir=root/'state',runtime_dir=root/'runtime',backups_dir=root/'backups',graveyard_dir=root/'graveyard')
assert not paths.ensure()
approved=root/'approved'
if not approved.exists():
 approved.mkdir(mode=0o700)
 (WindowsPermissionBackend() if os.name=='nt' else PosixPermissionBackend()).restrict(approved)
 target=approved/('tree' if {is_directory} else 'artifact.bin')
 if {is_directory}:
  (target/'nested').mkdir(parents=True)
  (target/'nested'/'artifact.bin').write_bytes(b'declared broker fixture bytes')
 else: target.write_bytes(b'declared broker fixture bytes')
 lease={{'protocol_version':1,'agent_id':'broker-resource-fixture','registration_nonce':'broker-resource-generation','identity':current_process_identity().as_dict(),'heartbeat_at':datetime.now(UTC).isoformat(),'heartbeat_timeout_seconds':120.0,'resources':[validate_temp_resource(target,root=approved)]}}
 (paths.leases_dir/'broker-resource-fixture.json').write_text(json.dumps(lease),encoding='utf-8')
 identity=ProcessIdentity.model_validate_json(json.dumps(lease['identity']))
 (root/'reviewed-process.json').write_text(json.dumps({{'pid':identity.pid,'process_instance_id':process_instance_id(identity)}}),encoding='utf-8')
request=RequestEnvelope.model_validate_json(sys.stdin.readline())
with build_default_service(paths=paths) as service:
 response=service.dispatch(request,context=RequestContext(capability=Capability.EXECUTION,local_control=True))
sys.stdout.write(response.model_dump_json())"#
        );
        let launch = python_launch(&script, directory.path());
        let target = directory
            .path()
            .join("approved")
            .join(if directory_resource {
                "tree"
            } else {
                "artifact.bin"
            });
        let listed = call_real_service(
            &launch,
            "quarantine.resource-list",
            json!({"agentId":"broker-resource-fixture"}),
        )
        .await;
        assert_eq!(listed["returned"], 1);
        assert_eq!(listed["resources"][0]["cleanup_available"], true);
        let reviewed_process: Value = serde_json::from_slice(
            &std::fs::read(directory.path().join("reviewed-process.json")).unwrap(),
        )
        .unwrap();
        let rebound = call_real_service(&launch,"quarantine.resource-list",json!({"agentId":"broker-resource-fixture","expectedPid":reviewed_process["pid"],"expectedProcessInstanceId":reviewed_process["process_instance_id"]})).await;
        assert_eq!(
            rebound["resources"][0]["declaration_digest"],
            listed["resources"][0]["declaration_digest"]
        );
        let plan = call_real_service(
            &launch,
            "quarantine.plan",
            json!({"agentId":"broker-resource-fixture","resourceIndex":0,"expectedDeclarationDigest":listed["resources"][0]["declaration_digest"],"expectedPid":reviewed_process["pid"],"expectedProcessInstanceId":reviewed_process["process_instance_id"]}),
        )
        .await;
        let quarantined = call_real_service(
            &launch,
            "quarantine.execute",
            json!({"planId":plan["plan_id"],"digest":plan["digest"]}),
        )
        .await;
        assert_eq!(quarantined["outcome"], "quarantined");
        assert!(!target.exists());
        let entries = call_real_service(
            &launch,
            "quarantine.list",
            json!({"limit":100,"cursor":null}),
        )
        .await;
        assert_eq!(entries["entries"][0]["restorable"], true);
        let restore = call_real_service(
            &launch,
            "quarantine.restore-plan",
            json!({"entryId":entries["entries"][0]["entry_id"]}),
        )
        .await;
        let restored = call_real_service(
            &launch,
            "quarantine.restore-execute",
            json!({"planId":restore["plan_id"],"digest":restore["digest"]}),
        )
        .await;
        assert_eq!(restored["outcome"], "restored");
        let actual = if directory_resource {
            target.join("nested/artifact.bin")
        } else {
            target
        };
        assert_eq!(
            std::fs::read(actual).unwrap(),
            b"declared broker fixture bytes"
        );
        let receipt = call_real_service(
            &launch,
            "receipt.get",
            json!({"receiptId":restored["receipt_id"]}),
        )
        .await;
        assert_eq!(receipt["plan_id"], restore["plan_id"]);
        assert_eq!(receipt["kind"], "quarantine");
    }
}

#[test]
fn completion_execute_responses_bind_every_receipt_to_the_submitted_plan() {
    for method in [
        "action.execute",
        "vault.mutation.execute",
        "vault.restore.execute",
        "quarantine.execute",
        "quarantine.restore-execute",
        "diagnostics.export-execute",
    ] {
        let request: RendererRequest = serde_json::from_value(
            json!({"method":method,"payload":{"planId":"plan-1","digest":"a".repeat(64)}}),
        )
        .unwrap();
        let request_id = Uuid::new_v4();
        let mut receipt = workflow_receipt();
        if method.starts_with("vault.") {
            receipt["local_only_warning"] = json!(VAULT_WARNING);
        }
        let valid = workflow_response(request_id, method, receipt);
        assert!(
            validate_response_for_request(request_id, &request, valid.to_string().as_bytes())
                .is_ok(),
            "{method} rejected its receipt"
        );
        let mut mismatched = valid;
        mismatched["result"]["plan_id"] = json!("another-plan");
        assert!(
            validate_response_for_request(request_id, &request, mismatched.to_string().as_bytes())
                .is_err(),
            "{method} accepted another plan's receipt"
        );
    }
}

#[test]
fn completion_verified_restore_noop_receipts_preserve_false_issuance() {
    let request_id = Uuid::new_v4();
    let mut receipt = workflow_receipt();
    receipt["outcome"] = json!("already_restored");
    receipt["action_issued"] = json!(false);
    for method in ["quarantine.restore-execute", "receipt.get", "activity.list"] {
        let result = if method == "activity.list" {
            json!({"receipts":[receipt.clone()],"next_cursor":null})
        } else {
            receipt.clone()
        };
        let payload = if method == "receipt.get" {
            json!({"receiptId":"receipt-1"})
        } else if method == "activity.list" {
            json!({"limit":100,"cursor":null})
        } else {
            json!({"planId":"plan-1","digest":"a".repeat(64)})
        };
        let request: RendererRequest =
            serde_json::from_value(json!({"method":method,"payload":payload})).unwrap();
        let response = workflow_response(request_id, method, result);
        assert!(
            validate_response_for_request(request_id, &request, response.to_string().as_bytes())
                .is_ok(),
            "{method} rejected a verified restore with no fresh rename"
        );
    }
}

#[test]
fn completion_lookup_responses_cannot_replace_the_selected_object() {
    let cases = [
        (
            "receipt.get",
            json!({"receiptId":"receipt-1"}),
            workflow_receipt(),
            "receipt_id",
            json!("other-receipt"),
        ),
        (
            "quarantine.resource-list",
            json!({"agentId":"agent-1"}),
            json!({"agent_id":"agent-1","resources":[],"returned":0}),
            "agent_id",
            json!("other-agent"),
        ),
    ];
    for (method, payload, result, key, replacement) in cases {
        let request: RendererRequest =
            serde_json::from_value(json!({"method":method,"payload":payload})).unwrap();
        let request_id = Uuid::new_v4();
        let valid = workflow_response(request_id, method, result);
        assert!(
            validate_response_for_request(request_id, &request, valid.to_string().as_bytes())
                .is_ok()
        );
        let mut mismatched = valid;
        mismatched["result"][key] = replacement;
        assert!(
            validate_response_for_request(request_id, &request, mismatched.to_string().as_bytes())
                .is_err(),
            "{method} accepted a different selected object"
        );
    }
}

#[test]
fn completion_vault_metadata_obeys_the_services_recursive_result_limits() {
    let request: RendererRequest = serde_json::from_value(
        json!({"method":"vault.get","payload":{"sourceId":"source-1","recordId":"record-1"}}),
    )
    .unwrap();
    let request_id = Uuid::new_v4();
    let valid = workflow_response(
        request_id,
        "vault.get",
        json!({"record":{"record_id":"record-1","namespace":"default","content":"","metadata":{"field":"value"},"embedding_present":false,"source_revision":"a".repeat(64)},"local_only_warning":VAULT_WARNING}),
    );
    assert!(
        validate_response_for_request(request_id, &request, valid.to_string().as_bytes()).is_ok()
    );
    let mut deep = json!(null);
    for _ in 0..17 {
        deep = json!({"nested":deep});
    }
    for metadata in [
        json!({"field":"x".repeat(65_537)}),
        json!({"x".repeat(129):"value"}),
        json!({"field":deep}),
        json!({"field":vec![Value::Null; 10_001]}),
    ] {
        let mut invalid = valid.clone();
        invalid["result"]["record"]["metadata"] = metadata;
        assert!(
            validate_response_for_request(request_id, &request, invalid.to_string().as_bytes())
                .is_err(),
            "unbounded metadata escaped result validation"
        );
    }
}

#[test]
fn completion_text_limits_match_service_unicode_character_counts() {
    let request: RendererRequest = serde_json::from_value(
        json!({"method":"vault.get","payload":{"sourceId":"界".repeat(100),"recordId":"record-1"}}),
    )
    .unwrap();
    assert!(
        request.validate().is_ok(),
        "service-bounded Unicode identifier was rejected"
    );
    let request_id = Uuid::new_v4();
    let response = workflow_response(
        request_id,
        "vault.get",
        json!({"record":{"record_id":"record-1","namespace":"default","content":"界".repeat(30_000),"metadata":{},"embedding_present":false,"source_revision":"a".repeat(64)},"local_only_warning":VAULT_WARNING}),
    );
    assert!(
        validate_response_for_request(request_id, &request, response.to_string().as_bytes())
            .is_ok(),
        "service-bounded Unicode content was rejected"
    );
}

#[test]
fn completion_structured_vault_results_preserve_edit_and_receipt_authority() {
    let plan = json!({"plan_id":"plan-1","digest":"a".repeat(64),"expires_at":"2026-10-02T12:00:30Z","consequences":["Update the selected local field."],"warnings":[],"source_id":"source-1","record_id":"record-1","snapshot_id":null,"before_revision":"b".repeat(64),"backup_verified":false,"diff":[{"field_name":"content","old_hash":"c".repeat(64),"new_hash":"d".repeat(64),"old_preview":"[REDACTED]","new_preview":"[REDACTED]"}],"local_only_warning":VAULT_WARNING});
    let mut receipt = workflow_receipt();
    for (key, value) in [
        ("kind", json!("memory")),
        ("source_id", json!("source-1")),
        ("record_id", json!("record-1")),
        ("snapshot_id", json!("snapshot-1")),
        ("before_revision", json!("b".repeat(64))),
        ("after_revision", json!("e".repeat(64))),
        ("operation", json!("update_content")),
        ("local_only_warning", json!(VAULT_WARNING)),
    ] {
        receipt[key] = value;
    }
    let cases = [
        (
            "vault.get",
            json!({"sourceId":"source-1","recordId":"record-1"}),
            json!({"record":{"record_id":"record-1","namespace":"default","content":"before","metadata":{},"embedding_present":false,"source_revision":"b".repeat(64),"editable_fields":[{"field":"content","kind":"update_content","value_type":"string","value":"before"}]},"local_only_warning":VAULT_WARNING}),
        ),
        (
            "vault.mutation.plan",
            json!({"sourceId":"source-1","recordId":"record-1","expectedRevision":"b".repeat(64),"operation":"update_content","value":"after"}),
            plan,
        ),
        (
            "vault.mutation.execute",
            json!({"planId":"plan-1","digest":"a".repeat(64)}),
            receipt,
        ),
        ("receipt.get", json!({"receiptId":"receipt-1"}), {
            let mut value = workflow_receipt();
            value["kind"] = json!("memory");
            value
        }),
    ];
    for (method, payload, result) in cases {
        let request: RendererRequest =
            serde_json::from_value(json!({"method":method,"payload":payload})).unwrap();
        let request_id = Uuid::new_v4();
        let response = workflow_response(request_id, method, result);
        assert!(
            validate_response_for_request(request_id, &request, response.to_string().as_bytes())
                .is_ok(),
            "{method} rejected structured local authority"
        );
    }
}

#[test]
fn completion_structured_vault_results_reject_scalar_type_and_digest_tampering() {
    let request: RendererRequest = serde_json::from_value(
        json!({"method":"vault.get","payload":{"sourceId":"source-1","recordId":"record-1"}}),
    )
    .unwrap();
    let request_id = Uuid::new_v4();
    let valid = workflow_response(
        request_id,
        "vault.get",
        json!({"record":{"record_id":"record-1","namespace":"default","content":"before","metadata":{},"embedding_present":false,"source_revision":"a".repeat(64),"editable_fields":[{"field":"content","kind":"update_content","value_type":"string","value":"before"}]},"local_only_warning":VAULT_WARNING}),
    );
    for (field, value) in [
        ("value_type", json!("number")),
        ("value", json!({"raw":"object"})),
        ("kind", json!("raw_sql")),
        ("field", json!("x".repeat(129))),
    ] {
        let mut invalid = valid.clone();
        invalid["result"]["record"]["editable_fields"][0][field] = value;
        assert!(
            validate_response_for_request(request_id, &request, invalid.to_string().as_bytes())
                .is_err()
        );
    }
    let execute: RendererRequest = serde_json::from_value(json!({"method":"vault.restore.execute","payload":{"planId":"plan-1","digest":"a".repeat(64)}})).unwrap();
    let mut receipt = workflow_receipt();
    receipt["before_revision"] = json!("not-a-revision");
    receipt["local_only_warning"] = json!(VAULT_WARNING);
    let invalid = workflow_response(request_id, "vault.restore.execute", receipt);
    assert!(
        validate_response_for_request(request_id, &execute, invalid.to_string().as_bytes())
            .is_err()
    );
}

#[test]
fn completion_defaulted_receipt_kind_cannot_be_explicitly_null() {
    let request: RendererRequest =
        serde_json::from_value(json!({"method":"receipt.get","payload":{"receiptId":"receipt-1"}}))
            .unwrap();
    let request_id = Uuid::new_v4();
    let mut receipt = workflow_receipt();
    receipt["kind"] = Value::Null;
    let response = workflow_response(request_id, "receipt.get", receipt);
    assert!(
        validate_response_for_request(request_id, &request, response.to_string().as_bytes())
            .is_err()
    );
}

#[tokio::test]
async fn settings_transport_interruption_requires_reconciliation_after_dispatch() {
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let script = "import json,sys\njson.loads(sys.stdin.readline())\nsys.exit(1)";
    let error = invoke_launch_for_test(
        &python_launch(script, directory.path()),
        &settings_update_request(),
        PROCESS_INTEGRATION_TIMEOUT,
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), BrokerErrorCode::OutcomeUncertain);
    assert!(error.dto().reconcile_required);
}

#[tokio::test]
async fn completion_mutating_methods_classify_lost_responses_as_uncertain() {
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let script = "import json,sys\njson.loads(sys.stdin.readline())\nsys.exit(1)";
    for (method, payload) in [
        (
            "action.plan",
            json!({"agentId":"agent-1","mode":"kill","target":{"pid":4242,"processInstanceId":"c".repeat(64)}}),
        ),
        ("vault.register", json!({"path":"C:/fixtures/store.json"})),
        (
            "vault.mutation.plan",
            json!({"sourceId":"source-1","expectedRevision":"a".repeat(64),"operation":"update_content","recordId":"record-1","value":"edit"}),
        ),
        (
            "vault.restore.plan",
            json!({"sourceId":"source-1","snapshotId":"snapshot-1","snapshotDigest":"b".repeat(64),"expectedRevision":"a".repeat(64)}),
        ),
        (
            "quarantine.plan",
            json!({"agentId":"agent-1","resourceIndex":0,"expectedDeclarationDigest":"d".repeat(64)}),
        ),
        ("quarantine.restore-plan", json!({"entryId":"entry-1"})),
        (
            "diagnostics.export-plan",
            json!({"destination":"C:/fixtures/diagnostics.json","includeReceipts":true,"includeSettings":true}),
        ),
        (
            "vault.mutation.execute",
            json!({"planId":"plan-1","digest":"a".repeat(64)}),
        ),
        (
            "vault.restore.execute",
            json!({"planId":"plan-1","digest":"a".repeat(64)}),
        ),
        (
            "quarantine.execute",
            json!({"planId":"plan-1","digest":"a".repeat(64)}),
        ),
        (
            "quarantine.restore-execute",
            json!({"planId":"plan-1","digest":"a".repeat(64)}),
        ),
        (
            "diagnostics.export-execute",
            json!({"planId":"plan-1","digest":"a".repeat(64)}),
        ),
    ] {
        let request: RendererRequest =
            serde_json::from_value(json!({"method":method,"payload":payload})).unwrap();
        let error = invoke_launch_for_test(
            &python_launch(script, directory.path()),
            &request,
            PROCESS_INTEGRATION_TIMEOUT,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.code(),
            BrokerErrorCode::OutcomeUncertain,
            "{method} lost its uncertain outcome"
        );
        assert!(error.dto().reconcile_required);
    }
}

#[test]
fn packaged_and_development_csp_forbid_inline_script_and_style() {
    let config: Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
    for field in ["csp", "devCsp"] {
        let policy = config["app"]["security"][field].as_str().unwrap();
        assert!(
            !policy.contains("'unsafe-inline'"),
            "{field} permits inline content"
        );
        assert!(policy.contains("style-src 'self'"));
        assert!(policy.contains("script-src 'self'"));
    }
}

#[test]
fn request_validation_enforces_bounds_and_digest_shape() {
    let oversized = serde_json::from_value::<RendererRequest>(json!({
        "method": "agent.detail", "payload": {"agentId": "x".repeat(257)}
    }))
    .expect("typed request");
    let bad_digest = serde_json::from_value::<RendererRequest>(json!({
        "method": "action.execute", "payload": {"planId": "plan", "digest": "not-a-digest"}
    }))
    .expect("typed request");

    assert_eq!(
        oversized.validate().unwrap_err().code(),
        BrokerErrorCode::InvalidRequest
    );
    assert_eq!(
        bad_digest.validate().unwrap_err().code(),
        BrokerErrorCode::InvalidRequest
    );
}

#[test]
fn engine_envelope_is_broker_owned_and_versioned() {
    let request = serde_json::from_value::<RendererRequest>(json!({
        "method": "scan.list", "payload": {"includeUnmanaged": true, "limit": 10}
    }))
    .unwrap();
    let request_id = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
    let envelope = request.engine_envelope(request_id).unwrap();

    assert_eq!(envelope["protocol_version"], "1.0");
    assert_eq!(envelope["request_id"], request_id.to_string());
    assert_eq!(envelope["method"], "scan.list");
    assert_eq!(
        envelope["payload"],
        json!({"include_unmanaged": true, "limit": 10})
    );
    assert!(envelope.get("context").is_none());
    assert!(envelope.get("executable").is_none());
}

#[test]
fn bound_agent_detail_forwards_the_exact_identity_in_engine_case() {
    let instance = "c".repeat(64);
    let request = serde_json::from_value::<RendererRequest>(json!({
        "method": "agent.detail",
        "payload": {
            "agentId": "agent-1",
            "expectedPid": 4242,
            "expectedProcessInstanceId": instance,
        }
    }))
    .unwrap();
    let request_id = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();

    assert_eq!(
        request.engine_envelope(request_id).unwrap()["payload"],
        json!({
            "agent_id": "agent-1",
            "expected_pid": 4242,
            "expected_process_instance_id": "c".repeat(64),
        })
    );
}

#[test]
fn agent_detail_accepts_only_an_omitted_or_complete_non_null_identity_binding() {
    let valid = [
        json!({"method": "agent.detail", "payload": {"agentId": "agent-1"}}),
        json!({
            "method": "agent.detail",
            "payload": {
                "agentId": "agent-1",
                "expectedPid": 4242,
                "expectedProcessInstanceId": "c".repeat(64),
            }
        }),
    ];
    for value in valid {
        let request = serde_json::from_value::<RendererRequest>(value).expect("valid request");
        assert!(request.validate().is_ok());
    }

    let unbound = serde_json::from_value::<RendererRequest>(json!({
        "method": "agent.detail",
        "payload": {"agentId": "agent-1"},
    }))
    .expect("valid unbound request");
    assert_eq!(
        serde_json::to_value(unbound).expect("serializable request"),
        json!({"method": "agent.detail", "payload": {"agentId": "agent-1"}})
    );

    let invalid = [
        json!({"method": "agent.detail", "payload": {"agentId": "agent-1", "expectedPid": 4242}}),
        json!({"method": "agent.detail", "payload": {"agentId": "agent-1", "expectedProcessInstanceId": "c".repeat(64)}}),
        json!({"method": "agent.detail", "payload": {"agentId": "agent-1", "expectedPid": null}}),
        json!({"method": "agent.detail", "payload": {"agentId": "agent-1", "expectedProcessInstanceId": null}}),
        json!({"method": "agent.detail", "payload": {"agentId": "agent-1", "expectedPid": null, "expectedProcessInstanceId": null}}),
        json!({"method": "agent.detail", "payload": {"agentId": "agent-1", "expectedPid": 4242, "expectedProcessInstanceId": null}}),
        json!({"method": "agent.detail", "payload": {"agentId": "agent-1", "expectedPid": null, "expectedProcessInstanceId": "c".repeat(64)}}),
    ];
    for value in invalid {
        let rejected = match serde_json::from_value::<RendererRequest>(value) {
            Ok(request) => request.validate().is_err(),
            Err(_) => true,
        };
        assert!(rejected, "partial or null identity binding was accepted");
    }
}

#[test]
fn action_plan_request_requires_and_forwards_the_reviewed_process_instance() {
    let request = action_plan_request();
    let request_id = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();

    assert_eq!(
        request.engine_envelope(request_id).unwrap()["payload"],
        json!({
            "agent_id": "agent-1",
            "mode": "kill",
            "target": {
                "pid": 4242,
                "process_instance_id": "b".repeat(64)
            }
        })
    );
    assert!(
        serde_json::from_value::<RendererRequest>(json!({
            "method": "action.plan",
            "payload": {"agentId": "agent-1", "mode": "kill"}
        }))
        .is_err()
    );
}

#[test]
fn settings_update_forwards_the_engine_revision_in_the_atomic_payload() {
    let request = settings_update_request();
    let request_id = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();

    assert_eq!(
        request.engine_envelope(request_id).unwrap()["payload"],
        json!({"expected_revision": 7, "appearance": "dark", "reduced_motion": true})
    );
    assert!(
        serde_json::from_value::<RendererRequest>(json!({
            "method": "settings.update",
            "payload": {"changes": {"appearance": "dark"}}
        }))
        .is_err()
    );
}

#[test]
fn paged_renderer_requests_forward_the_activity_and_quarantine_cursor() {
    for method in ["activity.list", "quarantine.list"] {
        let request = serde_json::from_value::<RendererRequest>(json!({
            "method": method,
            "payload": {"limit": 25, "cursor": "cursor-2"}
        }))
        .unwrap();
        let request_id = Uuid::new_v4();

        assert_eq!(
            request.engine_envelope(request_id).unwrap()["payload"],
            json!({"limit": 25, "cursor": "cursor-2"})
        );
    }
}

#[test]
fn paged_renderer_requests_forward_the_vault_query_cursor() {
    let request = serde_json::from_value::<RendererRequest>(json!({
        "method": "vault.query",
        "payload": {"sourceId": "source-1", "namespace": null, "text": "needle", "limit": 25, "cursor": "v1.context.25"}
    }))
    .unwrap();
    let request_id = Uuid::new_v4();

    assert_eq!(
        request.engine_envelope(request_id).unwrap()["payload"],
        json!({"source_id": "source-1", "namespace": null, "text": "needle", "limit": 25, "cursor": "v1.context.25"})
    );
}

#[test]
fn vault_query_rejects_an_oversized_cursor() {
    let request = serde_json::from_value::<RendererRequest>(json!({
        "method": "vault.query",
        "payload": {"sourceId": "source-1", "namespace": null, "text": null, "limit": 25, "cursor": "x".repeat(257)}
    }))
    .unwrap();

    assert!(request.validate().is_err());
}

#[test]
fn response_validation_rejects_protocol_correlation_method_and_shape_tampering() {
    let request_id = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
    let valid = json!({
        "protocol_version": "1.0", "request_id": request_id, "method": "system.info", "ok": true,
        "result": {"engine_version":"0.1.0-alpha.1","protocol_version":"1.0","platform":"win32","python":"3.12","local_only":true,"network_listener":false,"memory_warning":"Local only."},
        "error": null
    });
    assert!(
        validate_response(
            request_id,
            EngineMethod::SystemInfo,
            valid.to_string().as_bytes()
        )
        .is_ok()
    );

    for tampered in [
        {
            let mut value = valid.clone();
            value["protocol_version"] = json!("9");
            value
        },
        {
            let mut value = valid.clone();
            value["request_id"] = json!(Uuid::new_v4());
            value
        },
        {
            let mut value = valid.clone();
            value["method"] = json!("doctor");
            value
        },
        {
            let mut value = valid.clone();
            value["result"]["local_only"] = json!(false);
            value
        },
    ] {
        assert!(
            validate_response(
                request_id,
                EngineMethod::SystemInfo,
                tampered.to_string().as_bytes()
            )
            .is_err()
        );
    }
}

#[test]
fn response_validation_rejects_action_plan_target_replacement() {
    let request_id = Uuid::new_v4();
    let requested_instance = "a".repeat(64);
    let request = serde_json::from_value::<RendererRequest>(json!({
        "method": "action.plan",
        "payload": {
            "agentId": "managed-agent",
            "mode": "kill",
            "target": {"pid": 4112, "processInstanceId": requested_instance}
        }
    }))
    .unwrap();
    let response = json!({
        "protocol_version": "1.0", "request_id": request_id, "method": "action.plan", "ok": true,
        "result": {
            "plan_id": "plan-1", "digest": "b".repeat(64), "expires_at": "2026-08-12T22:00:00Z",
            "consequences": ["The exact process identity will be revalidated."], "warnings": [],
            "target": {"pid": 4112, "process_instance_id": "c".repeat(64), "state": "stale"}
        }, "error": null
    });

    assert!(
        validate_response_for_request(request_id, &request, response.to_string().as_bytes())
            .is_err()
    );
}

#[test]
fn response_validation_rejects_bound_agent_detail_replacement() {
    let request_id = Uuid::new_v4();
    let requested_instance = "a".repeat(64);
    let request = serde_json::from_value::<RendererRequest>(json!({
        "method": "agent.detail",
        "payload": {"agentId": "managed-agent", "expectedPid": 4112, "expectedProcessInstanceId": requested_instance}
    }))
    .unwrap();
    let response = json!({
        "protocol_version": "1.0", "request_id": request_id, "method": "agent.detail", "ok": true,
        "result": {
            "agent_id": "managed-agent", "provider": null, "project": "Local", "role": "Worker", "state": "stale",
            "evidence_grade": "confirmed", "confidence": 1.0, "reason_codes": ["lease_stale"], "explanation": "Stale.",
            "evidence": [], "actionable": true, "managed": true, "pid": 4112, "process_name": "python",
            "process_instance_id": "b".repeat(64), "os_status": "running", "usage_cost": {"availability": "unknown", "amount_usd": null, "note": "Unknown."}
        }, "error": null
    });

    assert!(
        validate_response_for_request(request_id, &request, response.to_string().as_bytes())
            .is_err()
    );
}

#[test]
fn response_validation_enforces_agent_and_collection_semantics() {
    let request_id = Uuid::new_v4();
    let agent = json!({
        "agent_id": null, "provider": null, "project": null, "role": null,
        "state": "healthy", "evidence_grade": "confirmed", "confidence": 1.0,
        "reason_codes": ["heartbeat_current"], "explanation": "Observed.",
        "evidence": [{"code":"heartbeat_current","grade":"confirmed","observed_at":"2026-08-12T00:00:00Z","detail":"Observed."}],
        "actionable": true, "managed": false, "pid": null, "process_name": "python",
        "os_status": null, "usage_cost": {"availability":"unknown","amount_usd":null,"note":"Not reported."}
    });
    let response = json!({
        "protocol_version":"1.0", "request_id":request_id, "method":"agent.detail", "ok":true,
        "result":agent, "error":null
    });
    assert!(
        validate_response(
            request_id,
            EngineMethod::AgentDetail,
            response.to_string().as_bytes()
        )
        .is_err()
    );

    let request_id = Uuid::new_v4();
    let response = json!({
        "protocol_version":"1.0", "request_id":request_id, "method":"quarantine.list", "ok":true,
        "result":{"entries": (0..501).map(|index| json!({
            "entry_id":format!("entry-{index}"), "agent_id":"agent", "resource_type":"file",
            "state":"quarantined", "restorable":true, "created_at":"2026-08-12T00:00:00Z",
            "updated_at":"2026-08-12T00:00:00Z"
        })).collect::<Vec<_>>(), "next_cursor":null}, "error":null
    });
    assert!(
        validate_response(
            request_id,
            EngineMethod::QuarantineList,
            response.to_string().as_bytes()
        )
        .is_err()
    );
}

#[test]
fn response_validation_binds_actionable_agents_to_a_process_instance() {
    let request_id = Uuid::new_v4();
    let valid_agent = json!({
        "agent_id": "agent-1", "provider": "provider", "project": "project", "role": "worker",
        "state": "healthy", "evidence_grade": "confirmed", "confidence": 1.0,
        "reason_codes": ["heartbeat_current"], "explanation": "Observed.",
        "evidence": [{"code":"heartbeat_current","grade":"confirmed","observed_at":"2026-08-12T00:00:00Z","detail":"Observed."}],
        "actionable": true, "managed": true, "pid": 4242,
        "process_instance_id": "c".repeat(64), "process_name": "python",
        "os_status": null, "usage_cost": {"availability":"unknown","amount_usd":null,"note":"Not reported."}
    });
    let response = json!({
        "protocol_version":"1.0", "request_id":request_id, "method":"agent.detail", "ok":true,
        "result":valid_agent, "error":null
    });

    assert!(
        validate_response(
            request_id,
            EngineMethod::AgentDetail,
            response.to_string().as_bytes()
        )
        .is_ok()
    );

    let mut missing_identity = response;
    missing_identity["result"]["process_instance_id"] = Value::Null;
    assert!(
        validate_response(
            request_id,
            EngineMethod::AgentDetail,
            missing_identity.to_string().as_bytes()
        )
        .is_err()
    );
}

#[test]
fn partial_or_interrupted_quarantine_entries_can_never_claim_restorability() {
    let request_id = Uuid::new_v4();
    for state in ["partial", "interrupted", "restoring", "restored"] {
        let valid = json!({
            "protocol_version":"1.0", "request_id":request_id, "method":"quarantine.list", "ok":true,
            "result":{"entries":[{
                "entry_id":"entry-1", "agent_id":"agent-1", "resource_type":"file",
                "state":state, "restorable":false,
                "created_at":"2026-08-12T00:00:00Z", "updated_at":"2026-08-12T00:00:00Z"
            }], "next_cursor":null},
            "error":null
        });
        assert!(
            validate_response(
                request_id,
                EngineMethod::QuarantineList,
                valid.to_string().as_bytes()
            )
            .is_ok(),
            "safe {state} quarantine entry was rejected"
        );

        let mut contradictory = valid;
        contradictory["result"]["entries"][0]["restorable"] = json!(true);
        assert!(
            validate_response(
                request_id,
                EngineMethod::QuarantineList,
                contradictory.to_string().as_bytes()
            )
            .is_err(),
            "unsafe {state} quarantine entry was accepted"
        );
    }
}

#[test]
fn response_validation_requires_an_authoritative_target_on_action_plans() {
    let request_id = Uuid::new_v4();
    let valid = json!({
        "protocol_version":"1.0", "request_id":request_id, "method":"action.plan", "ok":true,
        "result":{
            "plan_id":"plan-1", "digest":"a".repeat(64),
            "expires_at":"2026-08-12T00:05:00Z", "consequences":["Stops the process."],
            "warnings":[],
            "target":{"pid":4242,"process_instance_id":"b".repeat(64),"state":"unresponsive"}
        },
        "error":null
    });

    for state in [
        "healthy",
        "idle",
        "stale",
        "orphaned",
        "unresponsive",
        "unmanaged",
        "interrupted",
        "defunct",
        "completed",
        "failed",
        "cancelled",
        "unknown",
    ] {
        let mut state_response = valid.clone();
        state_response["result"]["target"]["state"] = json!(state);
        assert!(
            validate_response(
                request_id,
                EngineMethod::ActionPlan,
                state_response.to_string().as_bytes()
            )
            .is_ok(),
            "authoritative target state {state} was rejected"
        );
    }

    for invalid in [
        {
            let mut value = valid.clone();
            value["result"].as_object_mut().unwrap().remove("target");
            value
        },
        {
            let mut value = valid.clone();
            value["result"]["target"]["process_instance_id"] = json!("not-a-digest");
            value
        },
        {
            let mut value = valid.clone();
            value["result"]["target"]["state"] = json!("stalled");
            value
        },
        {
            let mut value = valid.clone();
            value["result"]["target"]["state"] = json!("zombie");
            value
        },
    ] {
        assert!(
            validate_response(
                request_id,
                EngineMethod::ActionPlan,
                invalid.to_string().as_bytes()
            )
            .is_err()
        );
    }
}

#[test]
fn response_validation_rejects_contradictory_receipts_and_accepts_empty_vault_content() {
    let request_id = Uuid::new_v4();
    let contradictory = json!({
        "protocol_version":"1.0", "request_id":request_id, "method":"action.execute", "ok":true,
        "result":{"receipt_id":"receipt-1","plan_id":"plan-1","outcome":"completed",
            "certainty":"verified","action_issued":null,"partial_failures":[],"created_at":"2026-08-12T00:00:00Z"},
        "error":null
    });
    assert!(
        validate_response(
            request_id,
            EngineMethod::ActionExecute,
            contradictory.to_string().as_bytes()
        )
        .is_err()
    );

    let request_id = Uuid::new_v4();
    let vault = json!({
        "protocol_version":"1.0", "request_id":request_id, "method":"vault.get", "ok":true,
        "result":{"record":{"record_id":"record-1","namespace":"default","content":"","metadata":{},
            "embedding_present":false,"source_revision":"b".repeat(64)},
            "local_only_warning":"Changes affect only local user-controlled memory; they do not change provider safety, rate limits, account state, or guarantee continuation."},
        "error":null
    });
    assert!(
        validate_response(
            request_id,
            EngineMethod::VaultGet,
            vault.to_string().as_bytes()
        )
        .is_ok()
    );
}

#[test]
fn response_validation_requires_bounded_partial_failures_for_action_and_activity_receipts() {
    let action_request_id = Uuid::new_v4();
    let receipt = json!({
        "receipt_id":"receipt-1", "plan_id":"plan-1", "outcome":"completed",
        "certainty":"verified", "action_issued":true,
        "partial_failures":["Cleanup verification failed."],
        "created_at":"2026-08-12T00:00:00Z"
    });
    let action = json!({
        "protocol_version":"1.0", "request_id":action_request_id,
        "method":"action.execute", "ok":true, "result":receipt, "error":null
    });
    assert!(
        validate_response(
            action_request_id,
            EngineMethod::ActionExecute,
            action.to_string().as_bytes()
        )
        .is_ok()
    );

    let activity_request_id = Uuid::new_v4();
    let activity = json!({
        "protocol_version":"1.0", "request_id":activity_request_id,
        "method":"activity.list", "ok":true,
        "result":{"receipts":[action["result"].clone()],"next_cursor":null},
        "error":null
    });
    assert!(
        validate_response(
            activity_request_id,
            EngineMethod::ActivityList,
            activity.to_string().as_bytes()
        )
        .is_ok()
    );

    let invalid_failures = [
        Value::Null,
        json!(vec!["bounded"; 65]),
        json!(["x".repeat(2_049)]),
        json!([""]),
    ];
    for failures in invalid_failures {
        let mut invalid = action.clone();
        if failures.is_null() {
            invalid["result"]
                .as_object_mut()
                .unwrap()
                .remove("partial_failures");
        } else {
            invalid["result"]["partial_failures"] = failures;
        }
        assert!(
            validate_response(
                action_request_id,
                EngineMethod::ActionExecute,
                invalid.to_string().as_bytes()
            )
            .is_err()
        );
    }

    let mut unexpected = action;
    unexpected["result"]["unexpected"] = json!(true);
    assert!(
        validate_response(
            action_request_id,
            EngineMethod::ActionExecute,
            unexpected.to_string().as_bytes()
        )
        .is_err()
    );
}

#[test]
fn settings_results_require_authoritative_settings_and_numeric_revision() {
    for method in [EngineMethod::SettingsGet, EngineMethod::SettingsUpdate] {
        let request_id = Uuid::new_v4();
        let valid = json!({
            "protocol_version":"1.0", "request_id":request_id, "method":method.as_str(), "ok":true,
            "result":{
                "settings":{
                    "scan_interval_seconds":30,
                    "heartbeat_grace_seconds":120,
                    "retention_days":30,
                    "include_unmanaged_candidates":false,
                    "appearance":"dark",
                    "reduced_motion":true
                },
                "revision":8
            },
            "error":null
        });

        assert!(
            validate_response(request_id, method, valid.to_string().as_bytes()).is_ok(),
            "{} wrapper was rejected",
            method.as_str()
        );

        let mut invalid = valid;
        invalid["result"]["revision"] = json!(-1);
        assert!(validate_response(request_id, method, invalid.to_string().as_bytes()).is_err());
    }
}

#[test]
fn development_launch_is_repo_relative_and_has_fixed_authority() {
    let launch = development_launch(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    let executable = launch.executable().to_string_lossy().replace('\\', "/");

    assert!(
        executable.ends_with("/.venv/Scripts/python.exe")
            || executable.ends_with("/.venv/bin/python")
    );
    let parent = format!("--parent-pid={}", std::process::id());
    let expected = if cfg!(unix) {
        vec!["-I", "-m", "zombie_killer_engine", "protocol-once", &parent]
    } else {
        vec!["-I", "-m", "zombie_killer_engine", "protocol-once"]
    };
    assert_eq!(launch.arguments(), expected);
    assert!(
        !launch
            .arguments()
            .iter()
            .any(|argument| argument.contains("--command"))
    );
}

#[test]
fn bundled_launch_accepts_only_a_fixed_absolute_resource() {
    let directory = tempfile::tempdir().unwrap();
    let (trusted_manifest, executable) = integrity_fixture(directory.path());
    let root = directory.path().canonicalize().unwrap();
    let launch = LaunchSpec::bundled(root.clone(), trusted_manifest.clone()).unwrap();

    assert_eq!(launch.executable(), executable.canonicalize().unwrap());
    let parent = format!("--parent-pid={}", std::process::id());
    let expected = if cfg!(unix) {
        vec!["protocol-once", &parent]
    } else {
        vec!["protocol-once"]
    };
    assert_eq!(launch.arguments(), expected);
    assert!(LaunchSpec::bundled(Path::new("relative-engine").into(), trusted_manifest).is_err());
    assert!(LaunchSpec::bundled(root, "not-a-digest".to_owned()).is_err());
}

#[test]
fn broker_errors_are_bounded_redacted_and_correlated() {
    let error = crate::engine::BrokerError::protocol(
        "Bearer synthetic-broker-fixture C:/private/vault",
        None,
    );
    let dto = error.dto();
    assert!(!dto.message.contains("secret-token"));
    assert!(!dto.message.contains("C:/private"));
    assert!(dto.message.len() <= 512);
    assert!(!dto.correlation_id.is_empty());
}

#[test]
fn protocol_error_details_reject_unapproved_secret_fields() {
    let request_id = Uuid::new_v4();
    let response = json!({
        "protocol_version": "1.0", "request_id": request_id, "method": "system.info", "ok": false,
        "result": null,
        "error": {"code":"internal","message":"Internal.","retryable":false,"details":{"api_key":"must-not-cross"}}
    });

    assert!(
        validate_response(
            request_id,
            EngineMethod::SystemInfo,
            response.to_string().as_bytes()
        )
        .is_err()
    );
}

#[tokio::test]
async fn valid_protocol_error_survives_engine_exit_two() {
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let script = r#"import json,sys
r=json.loads(sys.stdin.readline())
o={'protocol_version':'1.0','request_id':r['request_id'],'method':r['method'],'ok':False,'result':None,'error':{'code':'not_found','message':'The requested object was not found.','retryable':False,'details':{}}}
sys.stdout.write(json.dumps(o,separators=(',',':')))
sys.exit(2)"#;
    let error = invoke_launch_for_test(
        &python_launch(script, directory.path()),
        &system_info_request(),
        PROCESS_INTEGRATION_TIMEOUT,
    )
    .await
    .unwrap_err();

    assert_eq!(error.code(), BrokerErrorCode::NotFound);
}

#[tokio::test]
async fn engine_error_detail_uuid_cannot_replace_the_broker_request_uuid() {
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let captured = directory.path().join("request-id.txt");
    let captured_literal = serde_json::to_string(&captured.to_string_lossy()).unwrap();
    let attacker_id = "22222222-2222-4222-8222-222222222222";
    let script = format!(
        r#"import json,sys
r=json.loads(sys.stdin.readline())
open({captured_literal},'w',encoding='utf-8').write(r['request_id'])
o={{'protocol_version':'1.0','request_id':r['request_id'],'method':r['method'],'ok':False,'result':None,'error':{{'code':'internal','message':'Internal.','retryable':False,'details':{{'correlation_id':'{attacker_id}'}}}}}}
sys.stdout.write(json.dumps(o,separators=(',',':')))"#
    );

    let error = invoke_launch_for_test(
        &python_launch(&script, directory.path()),
        &system_info_request(),
        PROCESS_INTEGRATION_TIMEOUT,
    )
    .await
    .unwrap_err();
    let broker_request_id = std::fs::read_to_string(captured).unwrap();

    assert_eq!(error.dto().correlation_id, broker_request_id);
    assert_ne!(error.dto().correlation_id, attacker_id);
}

#[tokio::test]
async fn valid_action_protocol_error_survives_engine_exit_two() {
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let script = r#"import json,sys
r=json.loads(sys.stdin.readline())
o={'protocol_version':'1.0','request_id':r['request_id'],'method':r['method'],'ok':False,'result':None,'error':{'code':'target_changed','message':'Target changed.','retryable':False,'details':{}}}
sys.stdout.write(json.dumps(o,separators=(',',':')))
sys.exit(2)"#;
    let error = invoke_launch_for_test(
        &python_launch(script, directory.path()),
        &action_execute_request(),
        PROCESS_INTEGRATION_TIMEOUT,
    )
    .await
    .unwrap_err();

    assert_eq!(error.code(), BrokerErrorCode::TargetChanged);
    assert!(!error.dto().reconcile_required);
}

#[tokio::test]
async fn ambiguous_action_protocol_error_requires_reconciliation() {
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let script = r#"import json,sys
r=json.loads(sys.stdin.readline())
o={'protocol_version':'1.0','request_id':r['request_id'],'method':r['method'],'ok':False,'result':None,'error':{'code':'internal','message':'Internal.','retryable':False,'details':{}}}
sys.stdout.write(json.dumps(o,separators=(',',':')))
sys.exit(2)"#;
    let error = invoke_launch_for_test(
        &python_launch(script, directory.path()),
        &action_execute_request(),
        PROCESS_INTEGRATION_TIMEOUT,
    )
    .await
    .unwrap_err();

    assert_eq!(error.code(), BrokerErrorCode::Internal);
    assert!(error.dto().reconcile_required);
}

#[tokio::test]
async fn post_dispatch_action_failures_are_uncertain_and_require_reconciliation() {
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let scripts = [
        "import json,sys\njson.loads(sys.stdin.readline())\nsys.stdout.write('{malformed')",
        "import json,sys\nr=json.loads(sys.stdin.readline())\no={'protocol_version':'1.0','request_id':r['request_id'],'method':r['method'],'ok':True,'result':{'receipt_id':'receipt-1','plan_id':'plan-1','outcome':'completed','certainty':'verified','action_issued':True,'partial_failures':[],'created_at':'2026-08-12T00:00:00Z'},'error':None}\nsys.stdout.write(json.dumps(o,separators=(',',':')))\nsys.exit(7)",
        "import json,sys\njson.loads(sys.stdin.readline())\nsys.stdout.write('x'*(4*1024*1024+1))",
    ];

    for script in scripts {
        let error = invoke_launch_for_test(
            &python_launch(script, directory.path()),
            &action_execute_request(),
            PROCESS_INTEGRATION_TIMEOUT,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), BrokerErrorCode::OutcomeUncertain);
        assert!(error.dto().reconcile_required);
    }
}

#[tokio::test]
async fn mismatched_execute_receipt_plan_is_uncertain_and_requires_reconciliation() {
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let captured = directory.path().join("request-id.txt");
    let captured_literal = serde_json::to_string(&captured.to_string_lossy()).unwrap();
    let script = format!(
        "import json,sys\nr=json.loads(sys.stdin.readline())\nopen({captured_literal},'w',encoding='utf-8').write(r['request_id'])\no={{'protocol_version':'1.0','request_id':r['request_id'],'method':r['method'],'ok':True,'result':{{'receipt_id':'receipt-1','plan_id':'different-plan','outcome':'completed','certainty':'verified','action_issued':True,'partial_failures':[],'created_at':'2026-08-12T00:00:00Z'}},'error':None}}\nsys.stdout.write(json.dumps(o,separators=(',',':')))"
    );

    let error = invoke_launch_for_test(
        &python_launch(&script, directory.path()),
        &action_execute_request(),
        PROCESS_INTEGRATION_TIMEOUT,
    )
    .await
    .unwrap_err();

    assert_eq!(error.code(), BrokerErrorCode::OutcomeUncertain);
    let dto = error.dto();
    assert!(dto.reconcile_required);
    assert_eq!(
        dto.correlation_id,
        std::fs::read_to_string(captured).unwrap()
    );
}

#[tokio::test]
async fn timeout_kills_and_reaps_the_exact_child() {
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let launch = python_launch(
        "import json,sys,time\njson.loads(sys.stdin.readline())\ntime.sleep(30)",
        directory.path(),
    );
    let request = system_info_request();
    let (spawned_tx, spawned_rx) = tokio::sync::oneshot::channel();
    let (result, spawned) = tokio::join!(
        invoke_launch_for_test_with_spawn_observer(
            &launch,
            &request,
            Duration::from_millis(250),
            spawned_tx,
        ),
        spawned_rx
    );
    let error = result.unwrap_err();

    assert_eq!(error.code(), BrokerErrorCode::EngineTimeout);
    let pid = spawned.expect("spawn observer was not notified");
    assert!(
        !process_exists(pid),
        "timed-out engine child {pid} is still alive"
    );
}

#[cfg(windows)]
#[tokio::test]
async fn windows_child_cannot_execute_before_job_assignment() {
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("started.txt");
    let marker_literal = serde_json::to_string(&marker.to_string_lossy()).unwrap();
    let launch = development_launch(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    let mut command = tokio::process::Command::new(launch.executable());
    command
        .args([
            "-I",
            "-c",
            &format!("open({marker_literal},'w',encoding='utf-8').write('started')"),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let containment = ChildContainment::prepare(&mut command).unwrap();
    let mut child = command.spawn().unwrap();

    assert!(
        !marker.exists(),
        "suspended child executed before assignment"
    );
    containment.activate(&child).unwrap();
    child.wait().await.unwrap();
    assert_eq!(std::fs::read_to_string(marker).unwrap(), "started");
}

#[cfg(windows)]
#[tokio::test]
async fn closing_the_broker_job_kills_the_engine_child() {
    let _process_guard = serialize_test_engine_processes().await;
    let launch = development_launch(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    let mut command = tokio::process::Command::new(launch.executable());
    command
        .args(["-I", "-c", "import time; time.sleep(30)"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let containment = ChildContainment::prepare(&mut command).unwrap();
    let mut child = command.spawn().unwrap();
    let pid = child.id().unwrap();
    containment.activate(&child).unwrap();

    drop(containment);
    tokio::time::timeout(PROCESS_EVENT_TIMEOUT, child.wait())
        .await
        .expect("job close did not terminate child")
        .unwrap();
    assert!(!process_exists(pid));
}

#[cfg(windows)]
#[tokio::test]
async fn immediate_engine_exit_or_crash_cannot_leave_a_descendant_outside_the_job() {
    let _process_guard = serialize_test_engine_processes().await;
    for termination in ["os._exit(23)", "os.abort()"] {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("descendant.pid");
        let marker_literal = serde_json::to_string(&marker.to_string_lossy()).unwrap();
        let script = format!(
            r#"import json,os,subprocess,sys
json.loads(sys.stdin.readline())
p=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(30)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)
with open({marker_literal},'w',encoding='utf-8') as f:
 f.write(str(p.pid)); f.flush(); os.fsync(f.fileno())
{termination}"#
        );

        let result = tokio::time::timeout(
            PROCESS_INTEGRATION_TIMEOUT,
            invoke_launch_for_test(
                &python_launch(&script, directory.path()),
                &system_info_request(),
                PROCESS_INTEGRATION_TIMEOUT,
            ),
        )
        .await
        .expect("engine termination did not complete");
        assert!(result.is_err());
        let descendant: u32 = std::fs::read_to_string(marker).unwrap().parse().unwrap();
        assert!(
            wait_for_process_exit(descendant, PROCESS_EVENT_TIMEOUT),
            "descendant {descendant} survived engine {termination}"
        );
    }
}

#[cfg(windows)]
fn process_exists(pid: u32) -> bool {
    let output = StandardCommand::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).contains(&format!("\"{pid}\""))
}

#[cfg(windows)]
fn wait_for_process_exit(pid: u32, deadline: Duration) -> bool {
    const SYNCHRONIZE: u32 = 0x0010_0000;
    // SAFETY: the requested access only waits for process termination and the handle is closed below.
    let process = unsafe { OpenProcess(SYNCHRONIZE, 0, pid) };
    if process.is_null() {
        return true;
    }
    let milliseconds = u32::try_from(deadline.as_millis()).unwrap_or(u32::MAX - 1);
    // SAFETY: `process` is a live waitable kernel handle.
    let outcome = unsafe { WaitForSingleObject(process, milliseconds) };
    // SAFETY: this function exclusively owns the handle returned by OpenProcess.
    unsafe { CloseHandle(process) };
    outcome == WAIT_OBJECT_0
}

#[cfg(not(windows))]
fn process_exists(pid: u32) -> bool {
    StandardCommand::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .is_ok_and(|status| status.success())
}

#[tokio::test]
async fn oversized_stdout_is_rejected_and_stderr_is_never_exposed() {
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let captured = directory.path().join("request-id.txt");
    let captured_literal = serde_json::to_string(&captured.to_string_lossy()).unwrap();
    let oversized = format!(
        "import json,sys\nr=json.loads(sys.stdin.readline())\nopen({captured_literal},'w',encoding='utf-8').write(r['request_id'])\nsys.stdout.write('x'*(4*1024*1024+1))\nsys.stderr.write('Bearer synthetic-secret')"
    );
    let error = invoke_launch_for_test(
        &python_launch(&oversized, directory.path()),
        &system_info_request(),
        PROCESS_INTEGRATION_TIMEOUT,
    )
    .await
    .unwrap_err();

    assert_eq!(error.code(), BrokerErrorCode::OutputTooLarge);
    let dto = error.dto();
    assert_eq!(
        dto.correlation_id,
        std::fs::read_to_string(captured).unwrap()
    );
    assert!(!dto.message.contains("synthetic-secret"));
}

#[tokio::test]
async fn stderr_is_drained_without_changing_a_valid_result() {
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let reply = invoke_launch_for_test(
        &python_launch(
            &success_script(0.0, "Authorization: Bearer synthetic-secret", 0),
            directory.path(),
        ),
        &system_info_request(),
        PROCESS_INTEGRATION_TIMEOUT,
    )
    .await;

    assert!(reply.is_ok());
}

#[tokio::test]
async fn runtime_integrity_is_rechecked_before_each_launch_and_fails_before_dispatch() {
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let bundle = directory.path().join("bundle");
    std::fs::create_dir(&bundle).unwrap();
    let (trusted_manifest, bundled_executable) = integrity_fixture(&bundle);
    let marker = directory.path().join("launches.txt");
    let marker_literal = serde_json::to_string(&marker.to_string_lossy()).unwrap();
    let script = format!(
        "import json,sys\nr=json.loads(sys.stdin.readline())\nopen({marker_literal},'a',encoding='utf-8').write('1')\no={{'protocol_version':'1.0','request_id':r['request_id'],'method':r['method'],'ok':True,'result':{{'engine_version':'0.1.0-alpha.1','protocol_version':'1.0','platform':'test','python':'3.12','local_only':True,'network_listener':False,'memory_warning':'Local only.'}},'error':None}}\nsys.stdout.write(json.dumps(o,separators=(',',':')))"
    );
    let development = development_launch(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    let launch = LaunchSpec::test_only_with_integrity(
        development.executable().to_path_buf(),
        vec!["-I".into(), "-c".into(), script],
        directory.path().to_path_buf(),
        vec![(OsString::from("PYTHONUTF8"), OsString::from("1"))],
        bundle,
        trusted_manifest,
    );

    invoke_launch_for_test(&launch, &system_info_request(), PROCESS_INTEGRATION_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "1");

    std::fs::write(bundled_executable, b"tampered after first launch").unwrap();
    let error = invoke_launch_for_test(
        &launch,
        &action_execute_request(),
        PROCESS_INTEGRATION_TIMEOUT,
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), BrokerErrorCode::EngineUnavailable);
    assert!(!error.dto().reconcile_required);
    assert_eq!(std::fs::read_to_string(marker).unwrap(), "1");
}

#[tokio::test]
async fn settings_update_is_one_engine_transaction_with_engine_owned_cas() {
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let captured = directory.path().join("requests.jsonl");
    let captured_literal = serde_json::to_string(&captured.to_string_lossy()).unwrap();
    let script = format!(
        r#"import json,sys
r=json.loads(sys.stdin.readline())
with open({captured_literal},'a',encoding='utf-8') as f: f.write(json.dumps(r,separators=(',',':'))+'\n')
o={{'protocol_version':'1.0','request_id':r['request_id'],'method':r['method'],'ok':True,'result':{{'settings':{{'scan_interval_seconds':30,'heartbeat_grace_seconds':120,'retention_days':30,'include_unmanaged_candidates':False,'appearance':'dark','reduced_motion':True}},'revision':r['payload']['expected_revision']+1}},'error':None}}
sys.stdout.write(json.dumps(o,separators=(',',':')))"#
    );
    let broker = BrokerState::default();

    let reply = broker
        .request(
            &python_launch(&script, directory.path()),
            settings_update_request(),
        )
        .await
        .unwrap();
    let requests: Vec<Value> = std::fs::read_to_string(captured)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();

    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["method"], "settings.update");
    assert_eq!(requests[0]["payload"]["expected_revision"], 7);
    assert_eq!(
        serde_json::to_value(reply).unwrap()["result"]["revision"],
        8
    );
}

#[tokio::test]
async fn broker_serializes_concurrent_engine_calls() {
    // Hold one inter-test permit around both calls. Serialization within this test must continue
    // to come exclusively from BrokerState's production gate.
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let release = directory.path().join("release-first");
    let release_literal = serde_json::to_string(&release.to_string_lossy()).unwrap();
    let first_script = format!(
        r#"import json,os,sys,time
r=json.loads(sys.stdin.readline())
while not os.path.exists({release_literal}): time.sleep(0.01)
o={{'protocol_version':'1.0','request_id':r['request_id'],'method':r['method'],'ok':True,'result':{{'engine_version':'0.1.0-alpha.1','protocol_version':'1.0','platform':'test','python':'3.12','local_only':True,'network_listener':False,'memory_warning':'Local only.'}},'error':None}}
sys.stdout.write(json.dumps(o,separators=(',',':')))"#
    );
    let first_launch = python_launch(&first_script, directory.path());
    let second_launch = python_launch(&success_script(0.0, "", 0), directory.path());
    let broker = Arc::new(BrokerState::default());
    let (first_queued_tx, first_queued_rx) = tokio::sync::oneshot::channel();
    let (first_spawned_tx, first_spawned_rx) = tokio::sync::oneshot::channel();
    let first_broker = Arc::clone(&broker);
    let first_task = tokio::spawn(async move {
        first_broker
            .request_with_observers_for_test(
                &first_launch,
                system_info_request(),
                first_queued_tx,
                first_spawned_tx,
            )
            .await
    });
    first_queued_rx.await.unwrap();
    first_spawned_rx.await.unwrap();

    let (second_queued_tx, second_queued_rx) = tokio::sync::oneshot::channel();
    let (second_spawned_tx, mut second_spawned_rx) = tokio::sync::oneshot::channel();
    let second_broker = Arc::clone(&broker);
    let second_task = tokio::spawn(async move {
        second_broker
            .request_with_observers_for_test(
                &second_launch,
                system_info_request(),
                second_queued_tx,
                second_spawned_tx,
            )
            .await
    });
    second_queued_rx.await.unwrap();
    assert!(matches!(
        second_spawned_rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));

    std::fs::write(release, b"release").unwrap();
    let left = first_task.await.unwrap();
    tokio::time::timeout(PROCESS_EVENT_TIMEOUT, &mut second_spawned_rx)
        .await
        .expect("second child never spawned after the first completed")
        .unwrap();
    let right = second_task.await.unwrap();

    assert!(left.is_ok() && right.is_ok());
}

#[tokio::test]
async fn fixed_development_launch_smokes_real_system_doctor_and_scan() {
    let _process_guard = serialize_test_engine_processes().await;
    let development = development_launch(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    let requests = [system_info_request(), doctor_request(), scan_request()];

    for request in requests {
        let reply =
            invoke_launch_for_test(&development, &request, PROCESS_INTEGRATION_TIMEOUT).await;
        assert!(
            reply.is_ok(),
            "real engine call failed for {} with {:?}",
            request.method().as_str(),
            reply.as_ref().err().map(|error| error.code())
        );
        let reply = serde_json::to_value(reply.unwrap()).unwrap();
        assert_eq!(reply["method"], request.method().as_str());
        if request.method() == EngineMethod::SystemInfo {
            assert_eq!(reply["result"]["local_only"], true);
            assert_eq!(reply["result"]["network_listener"], false);
        }
    }
}
