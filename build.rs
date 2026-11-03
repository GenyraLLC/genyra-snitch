use std::{env, path::PathBuf, process::Command};
fn main() {
    #[cfg(target_os = "macos")]
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        bindgen::Builder::default()
            .header_contents("genyra-proc.h", "#include <libproc.h>")
            .allowlist_function("proc_pidinfo")
            .allowlist_type("proc_regionwithpathinfo")
            .allowlist_var("PROC_PIDREGIONPATHINFO")
            .generate_comments(false)
            .layout_tests(false)
            .generate()
            .expect("macOS libproc SDK bindings")
            .write_to_file(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("mac_proc.rs"))
            .expect("write macOS process bindings");
    }
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        // Npcap lives in a protected system subdirectory. Delay-load lets
        // main establish a safe search path before the first capture call.
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-lib=delayimp");
    }
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    println!("cargo:rerun-if-changed=kernel/snitch.bpf.c");
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("snitch.bpf.o");
    let mut clang = Command::new(env::var("CLANG").unwrap_or_else(|_| "clang".into()));
    if let Ok(arch) = env::var("CARGO_CFG_TARGET_ARCH") {
        let include = PathBuf::from(format!("/usr/include/{arch}-linux-gnu"));
        if include.is_dir() {
            clang.arg("-I").arg(include);
        }
    }
    let status = clang
        .args([
            "-O2",
            "-g",
            "-target",
            "bpf",
            "-c",
            "kernel/snitch.bpf.c",
            "-o",
        ])
        .arg(&output)
        .status()
        .expect("clang is required to build native eBPF hooks");
    assert!(
        status.success(),
        "failed to compile Genyra Snitch's native eBPF hooks"
    );
    println!("cargo:rustc-link-lib=bpf");
}
