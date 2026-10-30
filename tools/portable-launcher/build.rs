use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=ZK_PORTABLE_PAYLOAD");
    println!("cargo:rerun-if-env-changed=ZK_PORTABLE_SHA256");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let payload = match (
        env::var_os("ZK_PORTABLE_PAYLOAD"),
        env::var("ZK_PORTABLE_SHA256"),
    ) {
        (Some(path), Ok(expected)) => {
            let path = PathBuf::from(path);
            println!("cargo:rerun-if-changed={}", path.display());
            let bytes = fs::read(path).expect("Read portable payload");
            let actual = format!("{:x}", Sha256::digest(&bytes));
            assert_eq!(actual, expected, "Portable build payload digest mismatch");
            println!("cargo:rustc-env=ZK_PORTABLE_EMBEDDED_SHA256={actual}");
            bytes
        }
        (None, Err(_)) if env::var("PROFILE").unwrap() == "debug" => {
            println!(
                "cargo:rustc-env=ZK_PORTABLE_EMBEDDED_SHA256={}",
                "0".repeat(64)
            );
            Vec::new()
        }
        _ => panic!("Release builds require ZK_PORTABLE_PAYLOAD and ZK_PORTABLE_SHA256"),
    };
    fs::write(out.join("payload.zk"), payload).expect("Stage embedded payload");
    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let icon = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
            .join("../../apps/desktop/src-tauri/icons/icon.ico");
        println!("cargo:rerun-if-changed={}", icon.display());
        let mut resource = tauri_winres::WindowsResource::new();
        resource.set_icon(icon.to_str().expect("Icon path"))
            .set("CompanyName","PhantomBugz")
            .set("ProductName","Zombie Killer")
            .set("FileDescription","PhantomBugz Zombie Killer portable launcher")
            .set("OriginalFilename","Zombie Killer.exe")
            .set("LegalCopyright","PhantomBugz")
            .set("FileVersion","0.1.0.0")
            .set("ProductVersion","0.1.0-alpha.1")
            .set_manifest(r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security></trustInfo></assembly>"#);
        resource
            .compile()
            .expect("Compile PhantomBugz Windows resources");
    }
}
