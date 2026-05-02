// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

use std::path::PathBuf;
use std::process::{self, Command};
use std::string::String;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Emit a warning if the pinned eBPF nightly is older than this many days.
const NIGHTLY_STALE_DAYS: i64 = 30;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
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
            let total = Instant::now();
            build_ebpf(release);
            eprintln!("[x] total: {}", fmt_duration(total.elapsed()));
        }
        Some("run") => {
            release = args.contains(&"--release".into());
            let total = Instant::now();
            let ebpf_obj = build_ebpf(release);
            build_daemon(release, &ebpf_obj);
            eprintln!("[x] total: {}", fmt_duration(total.elapsed()));
            run_daemon(release, &args[1..]);
        }
        Some("build-man") => {
            release = false;
            let total = Instant::now();
            build_man();
            eprintln!("[x] man total: {}", fmt_duration(total.elapsed()));
        }
        Some("lint") => {
            release = false;
            let total = Instant::now();
            run_lint();
            eprintln!("[x] lint total: {}", fmt_duration(total.elapsed()));
        }
        Some("fuzz") => {
            release = false;
            let total = Instant::now();
            run_fuzz(&args[1..]);
            eprintln!("[x] fuzz total: {}", fmt_duration(total.elapsed()));
        }
        Some("clean") => {
            release = false;
            let total = Instant::now();
            run_clean();
            eprintln!("[x] clean total: {}", fmt_duration(total.elapsed()));
        }
        _ => {
            eprintln!(
                "Usage: cargo xtask <COMMAND>\n\n\
                 Commands:\n  \
                   build        Build the eBPF program and daemon\n  \
                   build-ebpf   Build only the eBPF program\n  \
                   build-man    Render man pages from man/*.md via pandoc\n  \
                   clean        Remove every target/ tree (workspace + ebpf + fuzz)\n  \
                   fuzz         Build a libFuzzer target (workaround for cargo-fuzz \
                                 + LLVM ≥ 16, see fn run_fuzz)\n  \
                   lint         Run cargo fmt --check + clippy -D warnings\n  \
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
    let status = cmd.status().expect("failed to spawn cargo for eBPF build");

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
    let status = Command::new("rust-size").arg(path).status();

    if let Err(e) = status {
        eprintln!(
            "[x] warning: rust-size not found ({}), skipping size report",
            e
        );
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
            eprintln!(
                "[x] warning: binary is NOT stripped — check [profile.release] strip setting"
            );
        }
    }
}

fn print_toolchain(ebpf_dir: &std::path::Path) {
    let toolchain_file = ebpf_dir.join("rust-toolchain.toml");

    let contents = match std::fs::read_to_string(&toolchain_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "[*] warning: cannot read {}: {}",
                toolchain_file.display(),
                e
            );
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

        if let Some(age) = nightly_age_days(&ch)
            && age > NIGHTLY_STALE_DAYS
        {
            eprintln!(
                "[*] warning: pinned nightly is {} days old (> {}); \
                 consider bumping {}",
                age,
                NIGHTLY_STALE_DAYS,
                ebpf_dir.join("rust-toolchain.toml").display()
            );
        }
    }
}

/// Days between today (UTC) and the date embedded in a
/// `nightly-YYYY-MM-DD` channel string. `None` for non-dated channels
/// (e.g. plain `"nightly"` or `"stable"`).
fn nightly_age_days(channel: &str) -> Option<i64> {
    let date = channel.strip_prefix("nightly-")?;
    let mut parts = date.splitn(3, '-');
    let y: i32 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;

    let today = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64 / 86_400;
    Some(today - days_from_civil(y, m, d))
}

/// Proleptic Gregorian days since 1970-01-01 (Howard Hinnant's algorithm).
fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y } as i64;
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn fmt_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();

    if secs >= 60 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!("{}.{:02}s", secs, d.subsec_millis() / 10)
    }
}

/// Sweep every `target/` directory we maintain. The eBPF crate lives
/// outside the workspace (its own pinned-nightly toolchain) and
/// `cargo fuzz` writes to a separate `target/` even though the fuzz
/// crate is a workspace member, so each tree needs an explicit
/// `cargo clean` against its own manifest.
fn run_clean() {
    let root = workspace_root();
    let targets = [
        ("workspace", root.join("Cargo.toml")),
        ("ebpf", root.join("pesigitg-ebpf/Cargo.toml")),
        ("fuzz", root.join("pesigitg-daemon/fuzz/Cargo.toml")),
    ];

    for (label, manifest) in targets {
        let target_dir = manifest
            .parent()
            .expect("manifest has no parent")
            .join("target");
        let before = dir_size_bytes(&target_dir);

        let t = Instant::now();
        let status = Command::new(cargo())
            .arg("clean")
            .arg("--manifest-path")
            .arg(&manifest)
            .status()
            .expect("failed to spawn cargo clean");

        if !status.success() {
            eprintln!("[*] cargo clean ({}) failed", label);
            process::exit(status.code().unwrap_or(1));
        }

        eprintln!(
            "[x] {}: {} freed in {}",
            label,
            fmt_bytes(before),
            fmt_duration(t.elapsed()),
        );
    }
}

/// Recursive byte total for a directory, or 0 if it doesn't exist /
/// can't be read. Best-effort: silent on per-entry stat errors so a
/// permission glitch doesn't abort the cleanup report.
fn dir_size_bytes(path: &std::path::Path) -> u64 {
    let entries = match std::fs::read_dir(path) {
        Ok(it) => it,
        Err(_) => return 0,
    };

    let mut total = 0u64;
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_dir() {
            total += dir_size_bytes(&entry.path());
        } else {
            total += meta.len();
        }
    }
    total
}

fn fmt_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} {}", n, UNITS[0])
    } else {
        format!("{:.1} {}", v, UNITS[i])
    }
}

fn run_lint() {
    let root = workspace_root();

    let t = Instant::now();
    let status = Command::new(cargo())
        .current_dir(&root)
        .args(["fmt", "--all", "--", "--check"])
        .status()
        .expect("failed to spawn cargo fmt");
    if !status.success() {
        eprintln!("[*] cargo fmt --check failed");
        process::exit(status.code().unwrap_or(1));
    }
    eprintln!("[x] fmt: {}", fmt_duration(t.elapsed()));

    let t = Instant::now();
    let status = Command::new(cargo())
        .current_dir(&root)
        .args([
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ])
        .status()
        .expect("failed to spawn cargo clippy");
    if !status.success() {
        eprintln!("[*] cargo clippy failed");
        process::exit(status.code().unwrap_or(1));
    }
    eprintln!("[x] clippy: {}", fmt_duration(t.elapsed()));
}

/// Build (and optionally smoke-run) a libFuzzer target without going
/// through `cargo fuzz`.
///
/// Why: cargo-fuzz 0.13.1 hard-codes `-Cpasses=sancov-module` in the
/// RUSTFLAGS it passes to rustc. That is the legacy LLVM pass-manager
/// invocation for SanitizerCoverage; it has been a no-op since LLVM 16,
/// so on a recent nightly the sancov pass never runs and the link step
/// fails with `undefined symbol: __sancov_gen_*`. Until cargo-fuzz ships
/// a fix we replicate its `cargo build` invocation minus that flag.
///
/// Usage:
///   cargo xtask fuzz <target>            # build only
///   cargo xtask fuzz <target> --smoke    # build + 30s libFuzzer run
fn run_fuzz(args: &[String]) {
    let target = match args.iter().find(|a| !a.starts_with("--")) {
        Some(t) => t,
        None => {
            eprintln!("Usage: cargo xtask fuzz <target> [--smoke]");
            process::exit(1);
        }
    };
    let smoke = args.iter().any(|a| a == "--smoke");

    let root = workspace_root();
    let fuzz_manifest = root.join("pesigitg-daemon/fuzz/Cargo.toml");

    // Same RUSTFLAGS cargo-fuzz 0.13.1 sets, minus `-Cpasses=sancov-module`.
    let rustflags = "-Cllvm-args=-sanitizer-coverage-level=4 \
                     -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
                     -Cllvm-args=-sanitizer-coverage-pc-table \
                     -Cllvm-args=-sanitizer-coverage-trace-compares \
                     --cfg fuzzing \
                     -Cllvm-args=-simplifycfg-branch-fold-threshold=0 \
                     -Zsanitizer=address \
                     -Cllvm-args=-sanitizer-coverage-stack-depth \
                     -Cdebug-assertions \
                     -Ccodegen-units=1";

    // Linux x86_64 only. Other hosts would need a different sanitizer
    // story (libfuzzer-sys's build.rs is platform-gated) and we don't
    // claim to support them yet.
    let triple = "x86_64-unknown-linux-gnu";

    let t = Instant::now();
    let status = Command::new(cargo())
        .env("RUSTUP_TOOLCHAIN", "nightly")
        .env("RUSTFLAGS", rustflags)
        .env("ASAN_OPTIONS", "detect_odr_violation=0")
        .arg("build")
        .arg("--manifest-path")
        .arg(&fuzz_manifest)
        .args(["--target", triple, "--release", "--bin", target])
        .status()
        .expect("failed to spawn cargo for fuzz build");

    if !status.success() {
        eprintln!("[*] fuzz build failed");
        process::exit(status.code().unwrap_or(1));
    }
    eprintln!("[x] fuzz build {}: {}", target, fmt_duration(t.elapsed()));

    let bin = root
        .join("target")
        .join(triple)
        .join("release")
        .join(target);

    if !smoke {
        eprintln!("[x] binary: {}", bin.display());
        return;
    }

    let corpus = root.join("pesigitg-daemon/fuzz/corpus").join(target);
    let artifacts = root.join("pesigitg-daemon/fuzz/artifacts").join(target);

    for dir in [&corpus, &artifacts] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("[*] cannot create {}: {}", dir.display(), e);
            process::exit(1);
        }
    }

    let artifact_prefix = format!("-artifact_prefix={}/", artifacts.display());

    let t = Instant::now();
    let status = Command::new(&bin)
        .arg(&corpus)
        .arg(&artifact_prefix)
        .arg("-max_total_time=30")
        .status()
        .expect("failed to spawn fuzz binary");

    if !status.success() {
        eprintln!("[*] fuzz smoke {} failed", target);
        process::exit(status.code().unwrap_or(1));
    }
    eprintln!("[x] fuzz smoke {}: {}", target, fmt_duration(t.elapsed()));
}

fn build_man() {
    let root = workspace_root();
    let src_dir = root.join("man");
    let out_dir = root.join("target").join("man");

    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        eprintln!("[*] cannot create {}: {}", out_dir.display(), e);
        process::exit(1);
    }

    let entries = match std::fs::read_dir(&src_dir) {
        Ok(it) => it,
        Err(e) => {
            eprintln!("[*] cannot read {}: {}", src_dir.display(), e);
            process::exit(1);
        }
    };

    let mut sources: Vec<PathBuf> = entries
        .filter_map(|r| r.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with(".md"))
                .unwrap_or(false)
        })
        .collect();

    sources.sort();

    if sources.is_empty() {
        eprintln!("[*] no *.md files found in {}", src_dir.display());
        process::exit(1);
    }

    for src in &sources {
        // pesigitgd.8.md -> pesigitgd.8
        let stem = src
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".md"))
            .expect("non-md file slipped through filter");
        let out = out_dir.join(stem);

        let t = Instant::now();
        let status = Command::new("pandoc")
            .args(["-s", "-f", "markdown", "-t", "man"])
            .arg(src)
            .arg("-o")
            .arg(&out)
            .status();

        match status {
            Ok(s) if s.success() => {
                eprintln!("[x] {}: {}", stem, fmt_duration(t.elapsed()));
            }
            Ok(s) => {
                eprintln!("[*] pandoc failed for {}: exit {}", src.display(), s);
                process::exit(s.code().unwrap_or(1));
            }
            Err(e) => {
                eprintln!(
                    "[*] failed to spawn pandoc ({}); install it via your package manager",
                    e
                );
                process::exit(1);
            }
        }
    }

    eprintln!("[x] man pages written to {}", out_dir.display());
}

fn run_daemon(release: bool, args: &[String]) {
    let profile = if release { "release" } else { "debug" };
    let bin = workspace_root()
        .join("target")
        .join(profile)
        .join("pesigitgd");

    // Pass remaining args (excluding --release) to the daemon
    let daemon_args: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| *a != "--release")
        .collect();

    let mut cmd = Command::new(&bin);
    cmd.env(
        "RUST_LOG",
        std::env::var("RUST_LOG").unwrap_or_else(|_| "pesigitgd=info".into()),
    )
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
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".into())
}

fn workspace_root() -> PathBuf {
    let output = Command::new(cargo())
        .args(["locate-project", "--workspace", "--message-format=plain"])
        .output()
        .expect("failed to locate workspace root");
    let path = String::from_utf8(output.stdout).expect("invalid utf-8 in cargo output");

    PathBuf::from(path.trim())
        .parent()
        .expect("Cargo.toml has no parent directory")
        .to_path_buf()
}
