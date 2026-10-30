#[path = "build_support/resource_manifest.rs"]
mod resource_manifest;

fn main() {
    if std::env::var("PROFILE").as_deref() == Ok("release") {
        let resource_root = std::path::Path::new("resources/engine");
        let manifest = resource_root.join("BUILD-MANIFEST.json");
        let target_os = std::env::var("CARGO_CFG_TARGET_OS")
            .expect("Cargo did not provide the release target operating system");
        let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH")
            .expect("Cargo did not provide the release target architecture");
        let platform = if target_os == "macos" {
            "darwin"
        } else {
            target_os.as_str()
        };
        let executable = if target_os == "windows" {
            "zombie-killer-engine.exe"
        } else {
            "zombie-killer-engine"
        };
        let verified = resource_manifest::verify_bundle(resource_root, platform, &target_arch, executable)
            .unwrap_or_else(|error| {
                panic!(
                    "release engine resource is missing or invalid; run the pinned native:prepare step: {error}"
                )
            });
        println!(
            "cargo:rustc-env=ZK_ENGINE_MANIFEST_SHA256={}",
            verified.manifest_sha256()
        );
        println!("cargo:rerun-if-changed={}", resource_root.display());
        println!("cargo:rerun-if-changed={}", manifest.display());
        println!(
            "cargo:rerun-if-changed={}",
            resource_root.join(executable).display()
        );
    }
    tauri_build::build()
}
