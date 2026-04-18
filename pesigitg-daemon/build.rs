// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

macro_rules! rustc_env {
    ($key:expr, $value:expr) => {
        println!("cargo:rustc-env={}={}", $key, $value)
    };
}

fn main() {
    // `--cfg fuzzing` is set by libFuzzer harness builds (cargo-fuzz and
    // our `xtask fuzz` wrapper); register it so `unexpected_cfgs` stays
    // quiet under `clippy -D warnings`.
    println!("cargo::rustc-check-cfg=cfg(fuzzing)");

    rustc_env!("TARGET", std::env::var("TARGET").unwrap());

    let rustc = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .expect("failed to run rustc");
    let rustc_version = String::from_utf8(rustc.stdout).unwrap();
    rustc_env!("RUSTC_VERSION", rustc_version.trim());

    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    rustc_env!("BUILD_DATE", date);

    // eBPF object embedding: set by `cargo xtask build`, or fall back to
    // a dummy empty file for standalone `cargo build -p pesigitg-daemon`.
    println!("cargo:rerun-if-env-changed=PESIGITG_EBPF_OBJ");
    match std::env::var("PESIGITG_EBPF_OBJ") {
        Ok(path) => {
            println!("cargo:rerun-if-changed={}", path);
            rustc_env!("PESIGITG_EBPF_OBJ", path);
        }
        Err(_) => {
            let out_dir = std::env::var("OUT_DIR").unwrap();
            let dummy = std::path::Path::new(&out_dir).join("dummy-ebpf");
            std::fs::write(&dummy, []).unwrap();
            rustc_env!("PESIGITG_EBPF_OBJ", dummy.display());
        }
    }
}
