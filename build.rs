//! Generates FreeBSD ioctl constants from the system headers.
//!
//! build/sys_consts.c includes the real headers and prints Rust constants;
//! the SIOC* values are _IOW()/_IOWR() macro expansions that bindgen cannot
//! reach, so they are read from the C preprocessor rather than transcribed.

use std::path::PathBuf;
use std::process::Command;
use std::{env, fs};

const SHIM: &str = "build/sys_consts.c";

fn main() {
    println!("cargo:rerun-if-changed={}", SHIM);
    println!("cargo:rerun-if-env-changed=CC");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("freebsd") {
        panic!("blackship targets FreeBSD only; {} needs its headers", SHIM);
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR unset"));
    let exe = out_dir.join("sys_consts_gen");
    let cc = env::var("CC").unwrap_or_else(|_| "cc".to_string());

    let status = Command::new(&cc)
        .arg("-O0")
        .arg("-Wall")
        .arg("-Werror")
        .arg("-o")
        .arg(&exe)
        .arg(SHIM)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {}: {}", cc, e));
    assert!(status.success(), "{} failed to compile {}", cc, SHIM);

    let output = Command::new(&exe)
        .output()
        .unwrap_or_else(|e| panic!("failed to run {}: {}", exe.display(), e));
    assert!(
        output.status.success(),
        "{} exited with {}",
        exe.display(),
        output.status
    );

    let generated = out_dir.join("sys_consts.rs");
    fs::write(&generated, &output.stdout)
        .unwrap_or_else(|e| panic!("failed to write {}: {}", generated.display(), e));
}
