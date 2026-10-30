#![cfg_attr(windows, windows_subsystem = "windows")]

use std::{
    env,
    path::PathBuf,
    process::{Command, ExitCode},
};
use zombie_killer_portable::{extract, parse_mode};

static PAYLOAD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.zk"));
static SHA256: &str = env!("ZK_PORTABLE_EMBEDDED_SHA256");

fn fail(arguments: &[String], error: &str, show_dialog: impl FnOnce(&str)) -> ExitCode {
    if arguments.iter().any(|argument| argument == "--check") {
        eprintln!("{error}");
    } else {
        show_dialog(error);
    }
    ExitCode::FAILURE
}

fn finish_operation<T>(
    operation: Result<T, String>,
    cleanup: Result<(), String>,
) -> Result<T, String> {
    match (operation, cleanup) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(operation), Err(cleanup)) => Err(format!("{operation}\n\n{cleanup}")),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
    }
}

fn run(check: bool) -> Result<(), String> {
    let parent = PathBuf::from(
        env::var_os("LOCALAPPDATA").ok_or("Windows local application data is unavailable")?,
    );
    let runtime = extract(PAYLOAD, SHA256, &parent)?;
    if check {
        let mut summary = runtime.summary();
        runtime.close()?;
        summary["cleanup"] = serde_json::json!(true);
        println!("{summary}");
        return Ok(());
    }
    let executable = runtime.root().join("target/release/zombie-killer.exe");
    // No shell and no user arguments: execute only the embedded native app.
    let result = Command::new(&executable)
        .current_dir(executable.parent().ok_or("Missing app parent")?)
        .status()
        .map_err(|error| format!("Could not run Zombie Killer: {error}"))
        .and_then(|status| {
            if status.success() {
                Ok(())
            } else {
                Err(format!("Zombie Killer exited with {status}"))
            }
        });
    finish_operation(result, runtime.close())
}

#[cfg(windows)]
fn show_error(message: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
    let text: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
    let title: Vec<u16> = "Zombie Killer — PhantomBugz"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}
#[cfg(not(windows))]
fn show_error(message: &str) {
    eprintln!("{message}");
}

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let check = match parse_mode(&arguments) {
        Ok(check) => check,
        Err(error) => return fail(&arguments, &error, show_error),
    };
    match run(check) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(&arguments, &error, show_error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_invalid_arguments_display_the_error() {
        let mut shown = None;
        let code = fail(&["unexpected".into()], "invalid launch", |error| {
            shown = Some(error.to_owned());
        });
        assert_eq!(code, ExitCode::FAILURE);
        assert_eq!(shown.as_deref(), Some("invalid launch"));
    }

    #[test]
    fn invalid_diagnostic_request_stays_stderr_only() {
        for arguments in [
            vec!["--check".into(), "unexpected".into()],
            vec!["unexpected".into(), "--check".into()],
        ] {
            let mut shown = None;
            let code = fail(&arguments, "invalid diagnostic request", |error| {
                shown = Some(error.to_owned());
            });
            assert_eq!(code, ExitCode::FAILURE);
            assert_eq!(shown, None);
        }
    }

    #[test]
    fn combined_operation_and_cleanup_failures_preserve_both_causes_and_runtime_path() {
        let result: Result<(), String> = Err("native wait failed".into());
        let error = finish_operation(
            result,
            Err("Could not remove runtime C:\\owned runtime: locked".into()),
        )
        .unwrap_err();
        assert!(error.contains("native wait failed"));
        assert!(error.contains("Could not remove runtime C:\\owned runtime: locked"));
    }

    #[test]
    fn finish_operation_preserves_individual_failures_and_success() {
        let result = finish_operation::<()>(Err("native start failed".into()), Ok(()));
        assert_eq!(result.unwrap_err(), "native start failed");
        let result = finish_operation(Ok(7), Err("cleanup failed".into()));
        assert_eq!(result.unwrap_err(), "cleanup failed");
        assert_eq!(finish_operation(Ok(7), Ok(())).unwrap(), 7);
    }
}
