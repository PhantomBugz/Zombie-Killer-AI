use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::json;
use tokio::sync::oneshot;

use crate::engine::{
    LaunchSpec, RendererRequest, arm_child_to_containment_drop_delay_for_test,
    invoke_launch_for_test, invoke_launch_for_test_with_spawn_observer,
    serialize_test_engine_processes,
};

fn sleeping_python_launch(directory: PathBuf) -> LaunchSpec {
    LaunchSpec::test_only(
        PathBuf::from("/usr/bin/python3"),
        vec![
            "-I".into(),
            "-c".into(),
            "import sys,time; sys.stdin.readline(); time.sleep(60)".into(),
        ],
        directory,
        vec![
            (
                OsString::from("PYTHONDONTWRITEBYTECODE"),
                OsString::from("1"),
            ),
            (OsString::from("PYTHONNOUSERSITE"), OsString::from("1")),
            (OsString::from("PYTHONUTF8"), OsString::from("1")),
        ],
    )
}

fn python_launch(script: String, directory: PathBuf) -> LaunchSpec {
    LaunchSpec::test_only(
        PathBuf::from("/usr/bin/python3"),
        vec!["-I".into(), "-c".into(), script],
        directory,
        vec![
            (
                OsString::from("PYTHONDONTWRITEBYTECODE"),
                OsString::from("1"),
            ),
            (OsString::from("PYTHONNOUSERSITE"), OsString::from("1")),
            (OsString::from("PYTHONUTF8"), OsString::from("1")),
        ],
    )
}

fn successful_response_script(body: &str) -> String {
    format!(
        r#"import json,sys
r=json.loads(sys.stdin.readline())
{body}
o={{'protocol_version':'1.0','request_id':r['request_id'],'method':r['method'],'ok':True,'result':{{'engine_version':'0.1.0-alpha.1','protocol_version':'1.0','platform':'test','python':'3.12','local_only':True,'network_listener':False,'memory_warning':'Local only.'}},'error':None}}
sys.stdout.write(json.dumps(o,separators=(',',':')))
sys.stdout.flush()"#,
    )
}

fn system_info_request() -> RendererRequest {
    serde_json::from_value(json!({"method": "system.info", "payload": {}})).unwrap()
}

fn process_exists(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    // SAFETY: signal zero performs an identity/liveness check without delivering a signal.
    unsafe { libc::kill(pid, 0) == 0 }
}

async fn wait_for_process_exit(pid: u32) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while process_exists(pid) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "contained engine process survived broker future cancellation"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn path_literal(path: &std::path::Path) -> String {
    serde_json::to_string(&path.to_string_lossy()).unwrap()
}

fn wait_for_waitable_leader_without_polling_the_runtime(pid: u32) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let pid = i32::try_from(pid).unwrap();
    loop {
        let mut information: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: the positive PID belongs to the child spawned by this process, the result is
        // writable, and WNOWAIT deliberately leaves the leader available to Tokio's drop path.
        let outcome = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                std::ptr::addr_of_mut!(information),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        // SAFETY: a successful waitid call initialized the siginfo payload.
        if outcome == 0 && unsafe { information.si_pid() } == pid {
            return;
        }
        assert!(
            outcome == 0
                || std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted,
            "waitid could not observe engine leader {pid}"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "engine leader {pid} did not become waitable"
        );
        std::thread::yield_now();
    }
}

#[tokio::test]
async fn cancelling_the_broker_future_kills_the_posix_process_group() {
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let launch = sleeping_python_launch(directory.path().to_path_buf());
    let request = system_info_request();
    let (spawned_tx, spawned_rx) = oneshot::channel();
    let invocation = tokio::spawn(async move {
        invoke_launch_for_test_with_spawn_observer(
            &launch,
            &request,
            Duration::from_secs(30),
            spawned_tx,
        )
        .await
    });
    let pid = spawned_rx.await.unwrap();

    invocation.abort();
    let cancelled = invocation.await.unwrap_err();
    assert!(cancelled.is_cancelled());
    wait_for_process_exit(pid).await;
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_after_leader_exit_signals_the_group_before_child_drop_can_reap() {
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let descendant_file = directory.path().join("cancelled-descendant.pid");
    let reuse_window_file = directory
        .path()
        .join("cancelled-leader-reaped-before-cleanup");
    let script = format!(
        r#"import os,time
leader=os.getpid()
pid=os.fork()
if pid == 0:
 os.close(0)
 while True:
  try:
   os.kill(leader,0)
  except ProcessLookupError:
   with open({},'w',encoding='utf-8') as f:
    f.write('unsafe-cancellation-pgid-reuse-window'); f.flush(); os.fsync(f.fileno())
   os.close(1); os.close(2)
   time.sleep(60)
  time.sleep(0.001)
with open({},'w',encoding='utf-8') as f:
 f.write(str(pid)); f.flush(); os.fsync(f.fileno())
time.sleep(0.05)
os._exit(0)"#,
        path_literal(&reuse_window_file),
        path_literal(&descendant_file)
    );
    let launch = python_launch(script, directory.path().to_path_buf());
    let request = system_info_request();
    let (spawned_tx, spawned_rx) = oneshot::channel();
    arm_child_to_containment_drop_delay_for_test();
    let invocation = tokio::spawn(async move {
        invoke_launch_for_test_with_spawn_observer(
            &launch,
            &request,
            Duration::from_secs(30),
            spawned_tx,
        )
        .await
    });
    let leader = spawned_rx.await.unwrap();
    wait_for_waitable_leader_without_polling_the_runtime(leader);
    assert!(descendant_file.exists());

    invocation.abort();
    let cancelled = invocation.await.unwrap_err();
    assert!(cancelled.is_cancelled());
    let descendant: u32 = std::fs::read_to_string(descendant_file)
        .unwrap()
        .parse()
        .unwrap();
    wait_for_process_exit(descendant).await;
    assert!(
        !reuse_window_file.exists(),
        "cancellation reaped the original group leader before containment cleanup"
    );
}

#[tokio::test]
async fn normal_engine_exit_kills_a_detached_stdio_descendant() {
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let descendant_file = directory.path().join("normal-descendant.pid");
    let script = successful_response_script(&format!(
        r#"import os,time
pid=os.fork()
if pid == 0:
 os.close(0); os.close(1); os.close(2)
 time.sleep(60)
 os._exit(0)
with open({},'w',encoding='utf-8') as f:
 f.write(str(pid)); f.flush(); os.fsync(f.fileno())"#,
        path_literal(&descendant_file)
    ));

    invoke_launch_for_test(
        &python_launch(script, directory.path().to_path_buf()),
        &system_info_request(),
        Duration::from_secs(10),
    )
    .await
    .unwrap();

    let descendant: u32 = std::fs::read_to_string(descendant_file)
        .unwrap()
        .parse()
        .unwrap();
    wait_for_process_exit(descendant).await;
}

#[tokio::test]
async fn group_cleanup_precedes_leader_reap_even_when_a_descendant_holds_the_pipes() {
    let _process_guard = serialize_test_engine_processes().await;
    let directory = tempfile::tempdir().unwrap();
    let descendant_file = directory.path().join("adversarial-descendant.pid");
    let reuse_window_file = directory.path().join("leader-reaped-before-cleanup");
    let script = successful_response_script(&format!(
        r#"import os,time
leader=os.getpid()
pid=os.fork()
if pid == 0:
 os.close(0)
 while True:
  try:
   os.kill(leader,0)
  except ProcessLookupError:
   with open({},'w',encoding='utf-8') as f:
    f.write('unsafe-pgid-reuse-window'); f.flush(); os.fsync(f.fileno())
   os.close(1); os.close(2)
   time.sleep(60)
  time.sleep(0.001)
with open({},'w',encoding='utf-8') as f:
 f.write(str(pid)); f.flush(); os.fsync(f.fileno())"#,
        path_literal(&reuse_window_file),
        path_literal(&descendant_file)
    ));

    invoke_launch_for_test(
        &python_launch(script, directory.path().to_path_buf()),
        &system_info_request(),
        Duration::from_secs(10),
    )
    .await
    .unwrap();

    let descendant: u32 = std::fs::read_to_string(descendant_file)
        .unwrap()
        .parse()
        .unwrap();
    wait_for_process_exit(descendant).await;
    assert!(
        !reuse_window_file.exists(),
        "the original process-group leader was reaped before group cleanup"
    );
}
