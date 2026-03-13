use std::string::String;
use std::path::PathBuf;
use std::process::{self, Command};

fn main() {
    let args: Vec<String> = std::env::args()
        .skip(1)
        .collect();

    match args.first().map(String::as_str) {
        Some("build") => {
            let release = args.contains(&"--release".into());
            let ebpf_obj = build_ebpf(release);
            build_daemon(release, &ebpf_obj);
        }
        Some("build-ebpf") => {
            let release = args.contains(&"--release".into());
            build_ebpf(release);
        }
        _ => {
            eprintln!(
                "Usage: cargo xtask <COMMAND>\n\n\
                 Commands:\n  \
                   build        Build the eBPF program and daemon\n  \
                   build-ebpf   Build only the eBPF program\n\n\
                 Options:\n  \
                   --release    Build in release mode"
            );
            
            process::exit(1);
        }
    }
}

fn build_ebpf(release: bool) -> PathBuf {
    let ebpf_dir = workspace_root().join("pesigitg-ebpf");

    // Use "cargo" (via rustup) rather than the CARGO env var so that
    // rust-toolchain.toml in pesigitg-ebpf/ selects the nightly toolchain
    // required for build-std.
    let mut cmd = Command::new("cargo");

    cmd.current_dir(&ebpf_dir)
        .env_remove("CARGO")
        .env_remove("RUSTUP_TOOLCHAIN")
        .arg("build");
    
    if release {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .expect("failed to spawn cargo for eBPF build");

    if !status.success() {
        eprintln!("eBPF build failed");
        process::exit(status.code().unwrap_or(1));
    }

    let profile = if release { "release" } else { "debug" };

    let obj = ebpf_dir
        .join("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("pesigitg-ebpf");

    print_size(&obj);
    obj
}

fn build_daemon(release: bool, ebpf_obj: &std::path::Path) {
    let mut cmd = Command::new(cargo());

    cmd.current_dir(workspace_root())
        .env("PESIGITG_EBPF_OBJ", ebpf_obj)
        .args(["build", "-p", "pesigitg-daemon"]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .expect("failed to spawn cargo for daemon build");

    if !status.success() {
        eprintln!("daemon build failed");
        process::exit(status.code().unwrap_or(1));
    }

    let profile = if release { "release" } else { "debug" };
    let bin = workspace_root()
        .join("target")
        .join(profile)
        .join("pesigitgd");

    print_size(&bin);
}

fn print_size(path: &std::path::Path) {
    let status = Command::new("rust-size")
        .arg(path)
        .status();

    if let Err(e) = status {
        eprintln!("warning: rust-size not found ({}), skipping size report", e);
    }
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
