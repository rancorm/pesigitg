// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

use std::string::String;
use std::path::PathBuf;
use std::process::{self, Command};
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args()
        .skip(1)
        .collect();
    let release: bool;

    match args.first().map(String::as_str) {
        Some("build") => {
            release = args.contains(&"--release".into());
            let total = Instant::now();
            let ebpf_obj = build_ebpf(release);
            build_daemon(release, &ebpf_obj);
            eprintln!("[x] total: {}", fmt_duration(total.elapsed()));
        }
        Some("build-ebpf") => {
            release = args.contains(&"--release".into());
            build_ebpf(release);
        }
        Some("run") => {
            release = args.contains(&"--release".into());
            let total = Instant::now();
            let ebpf_obj = build_ebpf(release);
            build_daemon(release, &ebpf_obj);
            eprintln!("[x] total: {}", fmt_duration(total.elapsed()));
            run_daemon(release, &args[1..]);
        }
        _ => {
            eprintln!(
                "Usage: cargo xtask <COMMAND>\n\n\
                 Commands:\n  \
                   build        Build the eBPF program and daemon\n  \
                   build-ebpf   Build only the eBPF program\n  \
                   run          Build and run the daemon (use sudo)\n\n\
                 Options:\n  \
                   --release    Build in release mode"
            );

            process::exit(1);
        }
    }

    if release {
        println!("[x] release build: {}", env!("CARGO_PKG_VERSION"));
    }
}

fn build_ebpf(release: bool) -> PathBuf {
    let ebpf_dir = workspace_root().join("pesigitg-ebpf");

    print_toolchain(&ebpf_dir);

    // Use "cargo" (via rustup) rather than the CARGO env var so that
    // rust-toolchain.toml in pesigitg-ebpf/ selects the nightly toolchain
    // required for build-std.
    let mut cmd = Command::new("cargo");

    cmd.current_dir(&ebpf_dir)
        .env_remove("CARGO")
        .env_remove("RUSTUP_TOOLCHAIN")
        .arg("build")
        .arg("-q");
    
    if release {
        cmd.arg("--release");
    }

    let t = Instant::now();
    let status = cmd
        .status()
        .expect("failed to spawn cargo for eBPF build");

    if !status.success() {
        eprintln!("[*] eBPF build failed");
        process::exit(status.code().unwrap_or(1));
    }

    eprintln!("[x] ebpf: {}", fmt_duration(t.elapsed()));

    let profile = if release { "release" } else { "debug" };

    let obj = ebpf_dir
        .join("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("pesigitg-ebpf");

    print_size(&obj, release);
    obj
}

fn build_daemon(release: bool, ebpf_obj: &std::path::Path) {
    let mut cmd = Command::new(cargo());

    cmd.current_dir(workspace_root())
        .env("PESIGITG_EBPF_OBJ", ebpf_obj)
        .args(["build", "-q", "-p", "pesigitg-daemon"]);

    if release {
        cmd.arg("--release");
    }

    let t = Instant::now();
    let status = cmd
        .status()
        .expect("failed to spawn cargo for daemon build");

    if !status.success() {
        eprintln!("[*] daemon build failed");
        process::exit(status.code().unwrap_or(1));
    }

    eprintln!("[x] daemon: {}", fmt_duration(t.elapsed()));

    let profile = if release { "release" } else { "debug" };
    let bin = workspace_root()
        .join("target")
        .join(profile)
        .join("pesigitgd");

    print_size(&bin, release);
}

fn print_size(path: &std::path::Path, release: bool) {
    let status = Command::new("rust-size")
        .arg(path)
        .status();

    if let Err(e) = status {
        eprintln!("[x] warning: rust-size not found ({}), skipping size report", e);
    }

    let is_ebpf = path
        .file_name()
        .and_then(|f| f.to_str())
        .map(|f| f.contains("ebpf"))
        .unwrap_or(false);

    if release && !is_ebpf {
        let stripped = Command::new("rust-readobj")
            .args(["--sections", path.to_str().unwrap()])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| !s.contains(".symtab"))
            .unwrap_or(false);

        if stripped {
            eprintln!("[x] note: binary is stripped (symbols removed)");
        } else {
            eprintln!("[x] warning: binary is NOT stripped — check [profile.release] strip setting");
        }
    }
}

fn print_toolchain(ebpf_dir: &std::path::Path) {
    let toolchain_file = ebpf_dir.join("rust-toolchain.toml");
    
    let contents = match std::fs::read_to_string(&toolchain_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[*] warning: cannot read {}: {}", toolchain_file.display(), e);
            return;
        }
    };

    let parse_value = |key: &str| -> Option<String> {
        contents.lines().find_map(|line| {
            let rest = line.strip_prefix(key)?;
            let rest = rest.trim_start().strip_prefix('=')?.trim();

            Some(rest.trim_matches('"').to_string())
        })
    };

    let channel = parse_value("channel");
    let components = parse_value("components");

    if let Some(ch) = channel {
        eprint!("[x] ebpf toolchain: {}", ch);

        if let Some(comp) = components {
            eprint!(" ({})", comp);
        }
        
        eprintln!();
    }
}

fn fmt_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    
    if secs >= 60 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!("{}.{:02}s", secs, d.subsec_millis() / 10)
    }
}

fn run_daemon(release: bool, args: &[String]) {
    let profile = if release { "release" } else { "debug" };
    let bin = workspace_root()
        .join("target")
        .join(profile)
        .join("pesigitgd");

    // Pass remaining args (excluding --release) to the daemon
    let daemon_args: Vec<&str> = args.iter()
        .map(String::as_str)
        .filter(|a| *a != "--release")
        .collect();

    let mut cmd = Command::new(&bin);
    cmd.env("RUST_LOG", std::env::var("RUST_LOG").unwrap_or_else(|_| "pesigitgd=info".into()))
        .args(&daemon_args);

    eprintln!("[x] running: {} {}", bin.display(), daemon_args.join(" "));

    let err = exec(&mut cmd);
    eprintln!("failed to exec {}: {}", bin.display(), err);
    process::exit(1);
}

/// Replace the current process with the given command.
#[cfg(unix)]
fn exec(cmd: &mut Command) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    cmd.exec()
}

fn cargo() -> String {
    std::env::var("CARGO")
        .unwrap_or_else(|_| "cargo".into())
}

fn workspace_root() -> PathBuf {
    let output = Command::new(cargo())
        .args(["locate-project", "--workspace", "--message-format=plain"])
        .output()
        .expect("failed to locate workspace root");
    let path = String::from_utf8(output.stdout)
        .expect("invalid utf-8 in cargo output");
    
    PathBuf::from(path.trim())
        .parent()
        .expect("Cargo.toml has no parent directory")
        .to_path_buf()
}
