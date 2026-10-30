mod engine;
#[path = "../build_support/resource_manifest.rs"]
mod resource_manifest;

use engine::{BrokerErrorDto, BrokerState, EngineReply, LaunchSpec, RendererRequest};
use tauri::{AppHandle, Runtime, State};

fn fixed_launch<R: Runtime>(app: &AppHandle<R>) -> Result<LaunchSpec, BrokerErrorDto> {
    #[cfg(debug_assertions)]
    {
        let _ = app;
        engine::development_launch(std::path::Path::new(env!("CARGO_MANIFEST_DIR")))
            .map_err(|error| error.dto())
    }
    #[cfg(not(debug_assertions))]
    {
        use tauri::Manager as _;

        let resource_dir = app.path().resource_dir().map_err(|_| {
            engine::BrokerError::protocol("resource directory unavailable", None).dto()
        })?;
        let engine_dir: std::path::PathBuf = resource_dir.join("engine");
        let trusted_manifest = option_env!("ZK_ENGINE_MANIFEST_SHA256").ok_or_else(|| {
            engine::BrokerError::protocol("release trust anchor unavailable", None).dto()
        })?;
        LaunchSpec::bundled(engine_dir, trusted_manifest.to_owned()).map_err(|error| error.dto())
    }
}

#[tauri::command]
async fn engine_request<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, BrokerState>,
    request: RendererRequest,
) -> Result<EngineReply, BrokerErrorDto> {
    let launch = fixed_launch(&app)?;
    state
        .request(&launch, request)
        .await
        .map_err(|error| error.dto())
}

pub fn run() {
    tauri::Builder::default()
        .manage(BrokerState::default())
        .invoke_handler(tauri::generate_handler![engine_request])
        .run(tauri::generate_context!())
        .expect("Zombie Killer desktop runtime failed");
}

#[cfg(test)]
mod engine_tests;
#[cfg(test)]
mod resource_manifest_tests;
