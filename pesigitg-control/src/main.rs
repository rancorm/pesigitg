// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! pesigitg-ctl — control utility for pesigitgd instances.
//!
//! Discovery works in both systemd and non-systemd modes by combining
//! three sources:
//!   - pidfiles at /var/run/pesigitgd-<interface>.pid (non-systemd only)
//!   - status sockets at /run/pesigitg/status-<interface>.sock (any
//!     instance with status_socket= set)
//!   - live processes in /proc whose `comm` is pesigitgd (any instance)
//!
//! Instances are keyed by interface; processes that can't be mapped to
//! an interface (e.g. systemd instance with -c <config>, no status
//! socket) are listed separately.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::{self, Display};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process;
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use pico_args::Arguments;
use serde_json::Value;

use pesigitg_common::{PID_DIR, PROC_NAME};
use pesigitg_routing::route::{Encryption, RouteConfig};

const RUN_DIR: &str = "/run/pesigitg";
const PIDFILE_PREFIX: &str = "pesigitgd-";
const PIDFILE_SUFFIX: &str = ".pid";
const SOCKET_PREFIX: &str = "status-";
const SOCKET_SUFFIX: &str = ".sock";
const SOCKET_TIMEOUT: Duration = Duration::from_secs(5);

type CmdFn = fn(&[String]) -> Result<(), TargetError>;

#[derive(Debug)]
struct Cmd {
    name: &'static str,
    aliases: &'static [&'static str],
    summary: &'static str,
    run: CmdFn,
}

#[derive(Debug, PartialEq, Eq)]
enum Target {
    Interface(String),
    Pid(u32),
}

#[derive(Debug)]
enum TargetError {
    Empty,
    NotFound(String),
    Ambiguous(Vec<String>),
    NotAPesigitgdProcess(u32),
    NoStatusSocket(String),
    Io(io::Error),
    ExtraArgs(String),
    BadResponse(String),
    RemoteError(String),
}

impl Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetError::Empty => write!(f, "no target"),
            TargetError::NotFound(q) => write!(f, "no pesigitgd instance matching '{}'", q),
            TargetError::Ambiguous(names) => write!(
                f,
                "multiple pesigitgd instances running; specify one of: {}",
                names.join(", ")
            ),
            TargetError::NotAPesigitgdProcess(pid) => {
                write!(f, "pid {} is not a pesigitgd process", pid)
            }
            TargetError::NoStatusSocket(iface) => {
                write!(
                    f,
                    "no status socket for interface {} (status_socket not configured?)",
                    iface
                )
            }
            TargetError::Io(e) => write!(f, "i/o error: {}", e),
            TargetError::ExtraArgs(s) => write!(f, "{}", s),
            TargetError::BadResponse(s) => write!(f, "bad response from daemon: {}", s),
            TargetError::RemoteError(s) => write!(f, "daemon error: {}", s),
        }
    }
}

impl From<io::Error> for TargetError {
    fn from(e: io::Error) -> Self {
        TargetError::Io(e)
    }
}

impl FromStr for Target {
    type Err = TargetError;

    fn from_str(s: &str) -> Result<Self, TargetError> {
        let s = s.trim();

        if s.is_empty() {
            return Err(TargetError::Empty);
        }

        if let Ok(pid) = s.parse::<u32>() {
            return Ok(Target::Pid(pid));
        }

        Ok(Target::Interface(s.to_string()))
    }
}

#[derive(Debug, Default, Clone)]
struct Instance {
    interface: Option<String>,
    pid: Option<u32>,
    pidfile: Option<PathBuf>,
    status_socket: Option<PathBuf>,
    cmdline: Option<String>,
}

#[derive(Debug, Clone)]
struct ResolvedTarget {
    interface: String,
    pid: u32,
    status_socket: Option<PathBuf>,
}

/// Discover all pesigitgd instances on this host from pidfiles, status
/// sockets, and `/proc`. Instances with an identifiable interface are
/// returned first (sorted by interface); processes whose interface
/// can't be determined from the command line follow.
fn discover_instances() -> Vec<Instance> {
    let mut by_iface: BTreeMap<String, Instance> = BTreeMap::new();
    let mut unnamed: Vec<Instance> = Vec::new();

    // Source 1: pidfiles (non-systemd daemonized mode).
    if let Ok(entries) = fs::read_dir(PID_DIR) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            let Some(iface) = iface_from_pidfile(name_str) else {
                continue;
            };
            let path = entry.path();
            let pid = fs::read_to_string(&path)
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok());
            let inst = by_iface.entry(iface.to_string()).or_default();

            inst.interface = Some(iface.to_string());
            inst.pidfile = Some(path);
            inst.pid = pid;
        }
    }

    // Source 2: status sockets (any mode with status API enabled).
    if let Ok(entries) = fs::read_dir(RUN_DIR) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            let Some(iface) = iface_from_sockname(name_str) else {
                continue;
            };
            let inst = by_iface.entry(iface.to_string()).or_default();

            inst.interface = Some(iface.to_string());
            inst.status_socket = Some(entry.path());
        }
    }

    // Source 3: live processes (picks up systemd-managed instances,
    // confirms pidfile liveness for the rest).
    for hit in scan_proc_for_pesigitgd() {
        match hit.interface.as_deref() {
            Some(iface) => {
                let inst = by_iface.entry(iface.to_string()).or_default();
                inst.interface = Some(iface.to_string());
                inst.pid = Some(hit.pid);
                inst.cmdline = Some(hit.cmdline);
            }
            None => {
                // Try to attach this /proc hit to a named instance whose
                // pidfile already pointed at this pid.
                let matched = by_iface.values_mut().find(|i| i.pid == Some(hit.pid));

                if let Some(inst) = matched {
                    inst.cmdline = Some(hit.cmdline);
                } else {
                    unnamed.push(Instance {
                        pid: Some(hit.pid),
                        cmdline: Some(hit.cmdline),
                        ..Default::default()
                    });
                }
            }
        }
    }

    let mut out: Vec<Instance> = by_iface.into_values().collect();

    out.extend(unnamed);
    out
}

fn iface_from_pidfile(name: &str) -> Option<&str> {
    let rest = name.strip_prefix(PIDFILE_PREFIX)?;
    let iface = rest.strip_suffix(PIDFILE_SUFFIX)?;

    if iface.is_empty() { None } else { Some(iface) }
}

fn iface_from_sockname(name: &str) -> Option<&str> {
    let rest = name.strip_prefix(SOCKET_PREFIX)?;
    let iface = rest.strip_suffix(SOCKET_SUFFIX)?;

    if iface.is_empty() { None } else { Some(iface) }
}

#[derive(Debug, Clone)]
struct ProcHit {
    pid: u32,
    interface: Option<String>,
    cmdline: String,
}

fn scan_proc_for_pesigitgd() -> Vec<ProcHit> {
    let mut hits = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return hits;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };

        if !is_pesigitgd_proc(pid) {
            continue;
        }

        let Ok(cmdline_bytes) = fs::read(format!("/proc/{}/cmdline", pid)) else {
            continue;
        };
        let interface = iface_from_cmdline(&cmdline_bytes);
        let cmdline = cmdline_bytes
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect::<Vec<_>>()
            .join(" ");

        hits.push(ProcHit {
            pid,
            interface,
            cmdline,
        });
    }

    hits
}

fn is_pesigitgd_proc(pid: u32) -> bool {
    match fs::read_to_string(format!("/proc/{}/comm", pid)) {
        Ok(s) => s.trim() == PROC_NAME,
        Err(_) => false,
    }
}

/// Extract `-i <val>` / `-i<val>` / `--interface <val>` / `--interface=<val>`
/// from a /proc/<pid>/cmdline byte blob (null-separated args).
fn iface_from_cmdline(bytes: &[u8]) -> Option<String> {
    let args: Vec<&[u8]> = bytes.split(|&b| b == 0).filter(|s| !s.is_empty()).collect();
    let mut i = 0;

    while i < args.len() {
        let arg = args[i];

        if arg == b"-i" || arg == b"--interface" {
            if let Some(next) = args.get(i + 1) {
                return std::str::from_utf8(next).ok().map(str::to_string);
            }
        } else if let Some(rest) = arg.strip_prefix(b"-i") {
            if !rest.is_empty() {
                return std::str::from_utf8(rest).ok().map(str::to_string);
            }
        } else if let Some(rest) = arg.strip_prefix(b"--interface=") {
            return std::str::from_utf8(rest).ok().map(str::to_string);
        }

        i += 1;
    }

    None
}

/// Map an optional target argument onto a live instance. With no
/// argument, auto-selects when exactly one instance is fully identified
/// (has both interface and pid); otherwise returns a NotFound or
/// Ambiguous error. With an argument, looks up by interface or pid.
fn resolve(target_arg: Option<&str>) -> Result<ResolvedTarget, TargetError> {
    let instances = discover_instances();
    let identified: Vec<Instance> = instances
        .iter()
        .filter(|i| i.interface.is_some() && i.pid.is_some())
        .cloned()
        .collect();

    match target_arg {
        None => match identified.len() {
            0 => Err(TargetError::NotFound("<auto>".into())),
            1 => {
                let inst = identified.into_iter().next().unwrap();
                let r = to_resolved(&inst).unwrap();

                println!("{} (pid {})", r.interface, r.pid);

                Ok(r)
            }
            _ => {
                let names: Vec<String> = identified
                    .iter()
                    .filter_map(|i| i.interface.clone())
                    .collect();

                Err(TargetError::Ambiguous(names))
            }
        },
        Some(s) => {
            let t: Target = s.parse()?;
            match t {
                Target::Interface(iface) => identified
                    .into_iter()
                    .find(|i| i.interface.as_deref() == Some(iface.as_str()))
                    .and_then(|i| to_resolved(&i))
                    .ok_or(TargetError::NotFound(iface)),
                Target::Pid(pid) => {
                    if !is_pesigitgd_proc(pid) {
                        return Err(TargetError::NotAPesigitgdProcess(pid));
                    }

                    // Prefer the identified record (has interface+socket);
                    // fall back to the unidentified process if no match.
                    let inst = instances
                        .into_iter()
                        .find(|i| i.pid == Some(pid))
                        .unwrap_or(Instance {
                            pid: Some(pid),
                            ..Default::default()
                        });

                    to_resolved(&inst).ok_or_else(|| {
                        TargetError::NotFound(format!(
                            "pid {} (running, but interface not on cmdline)",
                            pid
                        ))
                    })
                }
            }
        }
    }
}

fn to_resolved(i: &Instance) -> Option<ResolvedTarget> {
    Some(ResolvedTarget {
        interface: i.interface.clone()?,
        pid: i.pid?,
        status_socket: i.status_socket.clone(),
    })
}

// ----- Argument helpers -----

fn expect_no_args(args: &[String]) -> Result<(), TargetError> {
    if !args.is_empty() {
        return Err(TargetError::ExtraArgs(format!(
            "unexpected argument(s): {}",
            args.join(" ")
        )));
    }
    Ok(())
}

fn expect_optional_target(args: &[String]) -> Result<Option<&str>, TargetError> {
    if args.len() > 1 {
        return Err(TargetError::ExtraArgs(format!(
            "expected at most one target, got: {}",
            args.join(" ")
        )));
    }
    Ok(args.first().map(String::as_str))
}

/// Pull a `<short> <value>` / `<long> <value>` / `<long>=<value>` flag
/// out of `args` and return (value, remaining positional args). The
/// last occurrence wins. We hand-roll this rather than threading
/// pico-args into every command, because each command takes a
/// `&[String]` and only one or two of them want flags.
fn extract_flag(
    args: &[String],
    short: &str,
    long: &str,
) -> Result<(Option<String>, Vec<String>), TargetError> {
    let mut value: Option<String> = None;
    let mut rest: Vec<String> = Vec::with_capacity(args.len());
    let long_eq = format!("{}=", long);
    let mut iter = args.iter();

    while let Some(a) = iter.next() {
        if a == short || a == long {
            match iter.next() {
                Some(v) => value = Some(v.clone()),
                None => {
                    return Err(TargetError::ExtraArgs(format!("{} requires a value", a)));
                }
            }
        } else if let Some(v) = a.strip_prefix(&long_eq) {
            value = Some(v.to_string());
        } else {
            rest.push(a.clone());
        }
    }

    Ok((value, rest))
}

// ----- Status API client -----

/// Open the per-instance status socket, send `GET <path>\n`, parse the
/// JSON reply. Surfaces `{"error": "..."}` shapes as `RemoteError`.
fn query_endpoint(
    target: Option<&str>,
    path: &str,
) -> Result<(ResolvedTarget, Value), TargetError> {
    let resolved = resolve(target)?;
    let socket = resolved
        .status_socket
        .as_ref()
        .ok_or_else(|| TargetError::NoStatusSocket(resolved.interface.clone()))?;

    let mut stream = UnixStream::connect(socket)?;

    stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
    stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;
    writeln!(stream, "GET {}", path)?;

    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;

    let trimmed = buf.trim();
    let value: Value = serde_json::from_str(trimmed)
        .map_err(|e| TargetError::BadResponse(format!("{}: {:?}", e, trimmed)))?;

    if let Some(msg) = value.get("error").and_then(|v| v.as_str()) {
        return Err(TargetError::RemoteError(msg.to_string()));
    }

    Ok((resolved, value))
}

fn print_pretty(v: &Value) {
    match serde_json::to_string_pretty(v) {
        Ok(s) => println!("{}", s),
        Err(_) => println!("{}", v),
    }
}

fn print_health_summary(target: &ResolvedTarget, v: &Value) {
    let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("?");
    let uptime = v.get("uptime_secs").and_then(|n| n.as_u64());
    let alive = v.get("workers_alive").and_then(|n| n.as_u64());
    let expected = v.get("workers_expected").and_then(|n| n.as_u64());

    let mut parts = vec![status.to_string()];

    if let Some(u) = uptime {
        parts.push(format!("uptime {}", format_duration(u)));
    }
    if let (Some(a), Some(e)) = (alive, expected) {
        parts.push(format!("workers {}/{}", a, e));
    }

    println!(
        "{} (pid {}): {}",
        target.interface,
        target.pid,
        parts.join(", ")
    );
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        return format!("{}s", secs);
    }
    let (m, s) = (secs / 60, secs % 60);
    if m < 60 {
        return format!("{}m{}s", m, s);
    }
    let (h, m) = (m / 60, m % 60);
    if h < 24 {
        return format!("{}h{}m", h, m);
    }
    let (d, h) = (h / 24, h % 24);
    format!("{}d{}h", d, h)
}

// ----- Commands -----

fn cmd_list(args: &[String]) -> Result<(), TargetError> {
    expect_no_args(args)?;

    let instances = discover_instances();
    let (named, unnamed): (Vec<_>, Vec<_>) =
        instances.into_iter().partition(|i| i.interface.is_some());

    if named.is_empty() && unnamed.is_empty() {
        println!("no pesigitgd instances found");

        return Ok(());
    }

    if !named.is_empty() {
        let iface_w = named
            .iter()
            .filter_map(|i| i.interface.as_deref().map(str::len))
            .max()
            .unwrap_or(9)
            .max("INTERFACE".len());

        println!("{:<w$}  {:<7}  SOURCES", "INTERFACE", "PID", w = iface_w);

        for inst in &named {
            let iface = inst.interface.as_deref().unwrap_or("?");
            let pid = match inst.pid {
                Some(p) => format!("{}", p),
                None => "?".to_string(),
            };

            let mut sources = Vec::new();

            if inst.pidfile.is_some() {
                sources.push("pidfile");
            }
            if inst.status_socket.is_some() {
                sources.push("socket");
            }
            if inst.cmdline.is_some() {
                sources.push("proc");
            }

            // Flag stale pidfile: pidfile present but no /proc entry.
            let stale = inst.pidfile.is_some() && inst.cmdline.is_none();
            let note = if stale { "  (stale pidfile)" } else { "" };

            println!(
                "{:<w$}  {:<7}  {}{}",
                iface,
                pid,
                sources.join(","),
                note,
                w = iface_w
            );
        }
    }

    if !unnamed.is_empty() {
        if !named.is_empty() {
            println!();
        }

        println!("Unmatched processes (interface not on cmdline):");

        for inst in &unnamed {
            let pid = inst
                .pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "?".into());
            let cmd = inst.cmdline.as_deref().unwrap_or("");

            println!("  pid={}  {}", pid, cmd);
        }
    }

    Ok(())
}

fn cmd_version(args: &[String]) -> Result<(), TargetError> {
    expect_no_args(args)?;

    println!("{}", env!("CARGO_PKG_VERSION"));

    Ok(())
}

fn cmd_paths(args: &[String]) -> Result<(), TargetError> {
    expect_no_args(args)?;

    println!("pidfile dir:    {}", PID_DIR);
    println!("runtime dir:    {}", RUN_DIR);
    println!("bpffs pin root: /sys/fs/bpf/pesigitg/<interface>/");

    Ok(())
}

fn cmd_hup(args: &[String]) -> Result<(), TargetError> {
    let target = resolve(expect_optional_target(args)?)?;

    send_signal(target.pid, libc::SIGHUP)?;

    println!("sent SIGHUP to {} (pid {})", target.interface, target.pid);

    Ok(())
}

fn cmd_stop(args: &[String]) -> Result<(), TargetError> {
    let target = resolve(expect_optional_target(args)?)?;

    send_signal(target.pid, libc::SIGTERM)?;

    println!("sent SIGTERM to {} (pid {})", target.interface, target.pid);

    Ok(())
}

fn cmd_dump_stats(args: &[String]) -> Result<(), TargetError> {
    let target = resolve(expect_optional_target(args)?)?;

    send_signal(target.pid, libc::SIGUSR1)?;

    println!("sent SIGUSR1 to {} (pid {})", target.interface, target.pid);

    Ok(())
}

fn cmd_restart(args: &[String]) -> Result<(), TargetError> {
    let target = resolve(expect_optional_target(args)?)?;

    send_signal(target.pid, libc::SIGUSR2)?;

    println!(
        "sent SIGUSR2 to {} (pid {}); daemon will hand off to a fresh instance",
        target.interface, target.pid
    );

    Ok(())
}

fn cmd_status(args: &[String]) -> Result<(), TargetError> {
    let (resolved, value) = query_endpoint(expect_optional_target(args)?, "/health")?;

    print_health_summary(&resolved, &value);

    Ok(())
}

fn cmd_health(args: &[String]) -> Result<(), TargetError> {
    let (_, v) = query_endpoint(expect_optional_target(args)?, "/health")?;

    print_pretty(&v);

    Ok(())
}

fn cmd_stats(args: &[String]) -> Result<(), TargetError> {
    let (_, v) = query_endpoint(expect_optional_target(args)?, "/stats")?;

    print_pretty(&v);

    Ok(())
}

fn cmd_config(args: &[String]) -> Result<(), TargetError> {
    let (_, v) = query_endpoint(expect_optional_target(args)?, "/config")?;

    print_pretty(&v);

    Ok(())
}

fn cmd_info(args: &[String]) -> Result<(), TargetError> {
    let (_, v) = query_endpoint(expect_optional_target(args)?, "/version")?;

    print_pretty(&v);

    Ok(())
}

/// `whoami <cid-hex> [target] [--route-config <path>]` — given a QUIC
/// Connection ID, decode it against either the daemon's live route
/// table (online, default) or a route TOML file (offline,
/// `--route-config`). The offline path can decode encrypted schemes
/// because it has direct access to the keys; the online path
/// deliberately can't, since `/config` redacts them.
fn cmd_whoami(args: &[String]) -> Result<(), TargetError> {
    let (route_config_path, args) = extract_flag(args, "-r", "--route-config")?;

    if args.is_empty() {
        return Err(TargetError::ExtraArgs(
            "whoami requires a CID hex string (e.g. '00010203...')".into(),
        ));
    }
    if args.len() > 2 {
        return Err(TargetError::ExtraArgs(format!(
            "expected '<cid-hex> [target]', got: {}",
            args.join(" ")
        )));
    }

    let cid = parse_cid_hex(&args[0])?;

    if let Some(path) = route_config_path {
        if args.len() > 1 {
            return Err(TargetError::ExtraArgs(
                "--route-config skips the daemon, so a target argument cannot be combined with it"
                    .into(),
            ));
        }

        let configs = pesigitg_routing::route::parse_routes_file(&path)
            .map_err(|e| TargetError::ExtraArgs(format!("--route-config '{}': {}", path, e)))?;

        println!("source:    {}", path);

        for line in analyze_whoami_offline(&cid, &configs) {
            println!("{}", line);
        }

        return Ok(());
    }

    let target = args.get(1).map(String::as_str);
    let (resolved, v) = query_endpoint(target, "/config")?;

    let configs = v
        .get("route")
        .and_then(|r| r.get("configs"))
        .and_then(|c| c.as_array())
        .ok_or_else(|| TargetError::BadResponse("/config response missing route.configs".into()))?;

    println!("target:    {} (pid {})", resolved.interface, resolved.pid);

    for line in analyze_whoami(&cid, configs) {
        println!("{}", line);
    }

    Ok(())
}

fn parse_cid_hex(s: &str) -> Result<Vec<u8>, TargetError> {
    let bytes = pesigitg_common::hex::decode(s)
        .map_err(|e| TargetError::ExtraArgs(format!("invalid CID hex: {}", e)))?;

    if bytes.is_empty() {
        return Err(TargetError::ExtraArgs("CID must be non-empty".into()));
    }

    Ok(bytes)
}

/// Pure analyzer: given a CID and the `route.configs` array from
/// `/config`, return the lines to print after the target header. Kept
/// out of `cmd_whoami` so the rendering can be exercised under test
/// without standing up a fake status socket.
fn analyze_whoami(cid: &[u8], configs: &[Value]) -> Vec<String> {
    let mut out = Vec::new();

    out.push(format!("cid:       {}", pesigitg_common::hex::encode(cid)));

    // First octet's top three bits encode the rotation/config_id
    // (draft-ietf-quic-load-balancers-21 §3). 7 is reserved for
    // unroutable / pre-handshake CIDs.
    let config_id = cid[0] >> 5;

    if config_id == 7 {
        out.push("verdict:   config_id 7 is reserved (unroutable)".into());

        return out;
    }

    out.push(format!("config_id: {}", config_id));

    let cfg = configs
        .iter()
        .find(|c| c.get("config_id").and_then(|n| n.as_u64()) == Some(config_id as u64));

    let Some(cfg) = cfg else {
        out.push(format!(
            "verdict:   no route config with config_id={} on this daemon",
            config_id
        ));

        return out;
    };

    let scheme = cfg
        .get("encryption")
        .and_then(|s| s.as_str())
        .unwrap_or("?");
    let sid_len = cfg
        .get("server_id_length")
        .and_then(|n| n.as_u64())
        .unwrap_or(0) as usize;
    let nonce_len = cfg
        .get("nonce_length")
        .and_then(|n| n.as_u64())
        .unwrap_or(0) as usize;
    let payload_len = sid_len + nonce_len;

    out.push(format!("scheme:    {}", scheme));
    out.push(format!("sid_len:   {} bytes", sid_len));
    out.push(format!("nonce_len: {} bytes", nonce_len));

    if cid.len() < 1 + payload_len {
        out.push(format!(
            "verdict:   truncated (CID is {} byte(s); payload needs {})",
            cid.len(),
            1 + payload_len
        ));

        return out;
    }

    if scheme != "plaintext" {
        out.push(format!(
            "verdict:   encrypted ({}) — online decode requires the key,",
            scheme
        ));
        out.push("           which /config does not expose. Re-run with".into());
        out.push("           --route-config <path> for a full decode.".into());

        return out;
    }

    // Plaintext: server_id is the first sid_len bytes after the first
    // octet. /config exposes server `id` as a hex string, so compare
    // directly in hex form.
    let server_id_hex = pesigitg_common::hex::encode(&cid[1..1 + sid_len]);

    out.push(format!("server_id: {}", server_id_hex));

    let servers = match cfg.get("servers").and_then(|s| s.as_array()) {
        Some(s) => s,
        None => {
            out.push("verdict:   route config missing 'servers' array".into());

            return out;
        }
    };

    let matched = servers
        .iter()
        .find(|s| s.get("id").and_then(|i| i.as_str()) == Some(server_id_hex.as_str()));

    match matched {
        Some(s) => {
            let addr = s.get("address").and_then(|a| a.as_str()).unwrap_or("?");
            let mac = s
                .get("mac")
                .and_then(|m| m.as_str())
                .map(String::from)
                .unwrap_or_else(|| "(unset)".into());
            let healthy = s.get("healthy").and_then(|b| b.as_bool()).unwrap_or(false);
            let draining = s.get("draining").and_then(|b| b.as_bool()).unwrap_or(false);
            let transitions = s.get("transitions").and_then(|n| n.as_u64()).unwrap_or(0);
            let state_since_secs = s.get("state_since_secs").and_then(|n| n.as_u64());

            let mut state: Vec<String> = Vec::new();
            state.push(if healthy { "healthy" } else { "UNHEALTHY" }.into());
            if draining {
                state.push("draining".into());
            }
            if let Some(secs) = state_since_secs {
                state.push(format!("for {}", format_duration(secs)));
            }
            if transitions > 0 {
                state.push(format!(
                    "{} flap{}",
                    transitions,
                    if transitions == 1 { "" } else { "s" }
                ));
            }

            out.push(format!("verdict:   routes to {} ({})", addr, mac));
            out.push(format!("state:     {}", state.join(", ")));
        }
        None => {
            out.push(format!(
                "verdict:   server_id has no entry in config_id={} (would count as cid_unroutable)",
                config_id
            ));
        }
    }

    out
}

/// Pure analyzer for offline whoami: decode `cid` against parsed
/// [`RouteConfig`] entries (typically from
/// [`pesigitg_routing::route::parse_routes_file`]). Unlike
/// [`analyze_whoami`], this path has direct access to the encryption
/// keys, so `single_pass` and `four_pass` CIDs are decoded the same
/// way the datapath would.
fn analyze_whoami_offline(cid: &[u8], configs: &[RouteConfig]) -> Vec<String> {
    let mut out = Vec::new();

    out.push(format!("cid:       {}", pesigitg_common::hex::encode(cid)));

    let config_id = cid[0] >> 5;

    if config_id == 7 {
        out.push("verdict:   config_id 7 is reserved (unroutable)".into());

        return out;
    }

    out.push(format!("config_id: {}", config_id));

    let cfg = match configs.iter().find(|c| c.config_id == config_id) {
        Some(c) => c,
        None => {
            out.push(format!(
                "verdict:   no route config with config_id={} in this file",
                config_id
            ));

            return out;
        }
    };

    let scheme = match cfg.encryption {
        Encryption::Plaintext => "plaintext",
        Encryption::SinglePass { .. } => "single_pass",
        Encryption::FourPass { .. } => "four_pass",
    };

    out.push(format!("scheme:    {}", scheme));
    out.push(format!("sid_len:   {} bytes", cfg.server_id_length));
    out.push(format!("nonce_len: {} bytes", cfg.nonce_length));

    let payload_len = cfg.cid_payload_length() as usize;
    if cid.len() < 1 + payload_len {
        out.push(format!(
            "verdict:   truncated (CID is {} byte(s); payload needs {})",
            cid.len(),
            1 + payload_len
        ));

        return out;
    }

    match pesigitg_routing::cid::resolve_server_idx(cid, cfg) {
        Some(idx) => {
            let server = &cfg.servers[idx];
            let id_hex = pesigitg_common::hex::encode(&server.id);

            out.push(format!("server_id: {}", id_hex));

            let mac_str = match server.mac {
                Some(m) => format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    m[0], m[1], m[2], m[3], m[4], m[5]
                ),
                None => "(unset)".into(),
            };

            out.push(format!(
                "verdict:   routes to {} ({})",
                server.address, mac_str
            ));

            // healthy is a runtime probe result that doesn't apply
            // offline; only the declared draining flag is meaningful
            // when reading the TOML.
            if server.draining {
                out.push("state:     draining".into());
            }
        }
        None => {
            out.push(format!(
                "verdict:   server_id has no entry in config_id={} (would count as cid_unroutable)",
                config_id
            ));
        }
    }

    out
}

/// `backend-config <server-id-hex> [target] [--route-config <path>]
/// [--no-key] [--config-id <N>]` — emit per-backend QUIC-LB
/// provisioning JSON for one server_id.
///
/// A backend admin runs this against `lb.toml` to extract exactly the
/// values their QUIC stack needs to mint CIDs the LB will later
/// decrypt: `config_id`, `server_id`, lengths, AES key, and encryption
/// mode. Multiple matches mean the server appears in multiple configs
/// (mid-rollover); both must be provisioned. The output is always a
/// well-formed JSON document, even with zero matches — the consumer
/// checks `matches | length`.
///
/// The offline path (`--route-config`) sees the raw key. The online
/// path queries `/config`, which redacts keys server-side; encrypted
/// configs come back as `key: null, key_redacted: true`.
fn cmd_backend_config(args: &[String]) -> Result<(), TargetError> {
    let (route_config_path, args) = extract_flag(args, "-r", "--route-config")?;
    // Empty short flag never matches a real arg.
    let (config_id_filter_str, args) = extract_flag(&args, "", "--config-id")?;

    let mut no_key = false;
    let mut positional: Vec<String> = Vec::new();

    for a in args {
        if a == "--no-key" {
            no_key = true;
        } else {
            positional.push(a);
        }
    }

    if positional.is_empty() {
        return Err(TargetError::ExtraArgs(
            "backend-config requires a server-id hex string (e.g. '000001')".into(),
        ));
    }
    if positional.len() > 2 {
        return Err(TargetError::ExtraArgs(format!(
            "expected '<server-id-hex> [target]', got: {}",
            positional.join(" ")
        )));
    }

    let server_id_hex = positional[0].trim().to_lowercase();

    // Validate hex shape now so a typo doesn't silently match nothing.
    pesigitg_common::hex::decode(&server_id_hex)
        .map_err(|e| TargetError::ExtraArgs(format!("invalid server-id hex: {}", e)))?;

    let config_id_filter = match config_id_filter_str.as_deref() {
        None => None,
        Some(s) => {
            let n: u8 = s.parse().map_err(|_| {
                TargetError::ExtraArgs(format!("--config-id expects an integer 0-6, got '{}'", s))
            })?;
            if n > 6 {
                return Err(TargetError::ExtraArgs(format!(
                    "--config-id must be 0-6, got {}",
                    n
                )));
            }
            Some(n)
        }
    };

    let (source, matches) = if let Some(path) = route_config_path {
        if positional.len() > 1 {
            return Err(TargetError::ExtraArgs(
                "--route-config skips the daemon, so a target argument cannot be combined with it"
                    .into(),
            ));
        }

        let configs = pesigitg_routing::route::parse_routes_file(&path)
            .map_err(|e| TargetError::ExtraArgs(format!("--route-config '{}': {}", path, e)))?;
        let matches =
            analyze_backend_config_offline(&server_id_hex, &configs, no_key, config_id_filter);
        let source = serde_json::json!({
            "kind": "file",
            "path": path,
        });

        (source, matches)
    } else {
        let target = positional.get(1).map(String::as_str);
        let (resolved, v) = query_endpoint(target, "/config")?;
        let configs = v
            .get("route")
            .and_then(|r| r.get("configs"))
            .and_then(|c| c.as_array())
            .ok_or_else(|| {
                TargetError::BadResponse("/config response missing route.configs".into())
            })?;
        let matches = analyze_backend_config_online(&server_id_hex, configs, config_id_filter);
        let source = serde_json::json!({
            "kind": "daemon",
            "interface": resolved.interface,
            "pid": resolved.pid,
        });

        (source, matches)
    };

    let doc = serde_json::json!({
        "schema_version": 1,
        "source": source,
        "matches": matches,
    });

    print_pretty(&doc);

    Ok(())
}

/// Pure analyzer: walk offline-parsed [`RouteConfig`] entries and
/// return one JSON object per `config_id` that contains the server.
/// Mid-rollover the same server_id appears in two configs — emit
/// both so the backend can provision them in parallel.
fn analyze_backend_config_offline(
    server_id_hex: &str,
    configs: &[RouteConfig],
    redact_key: bool,
    config_id_filter: Option<u8>,
) -> Vec<Value> {
    let mut out = Vec::new();

    for cfg in configs {
        if let Some(filter) = config_id_filter
            && cfg.config_id != filter
        {
            continue;
        }

        let Some(server) = cfg
            .servers
            .iter()
            .find(|s| pesigitg_common::hex::encode(&s.id) == server_id_hex)
        else {
            continue;
        };

        let (encryption_str, key_value, key_redacted) = match &cfg.encryption {
            Encryption::Plaintext => ("plaintext", Value::Null, false),
            Encryption::SinglePass { key, .. } => (
                "single_pass",
                if redact_key {
                    Value::Null
                } else {
                    Value::String(pesigitg_common::hex::encode(key))
                },
                redact_key,
            ),
            Encryption::FourPass { key, .. } => (
                "four_pass",
                if redact_key {
                    Value::Null
                } else {
                    Value::String(pesigitg_common::hex::encode(key))
                },
                redact_key,
            ),
        };

        out.push(serde_json::json!({
            "config_id": cfg.config_id,
            "server_id": pesigitg_common::hex::encode(&server.id),
            "server_id_length": cfg.server_id_length,
            "nonce_length": cfg.nonce_length,
            "first_octet_encodes_cid_length": cfg.first_octet_encodes_cid_length,
            "encryption": encryption_str,
            "key": key_value,
            "key_redacted": key_redacted,
            "draining": server.draining,
            "address": server.address.to_string(),
            "cid_total_length": cfg.cid_length(),
        }));
    }

    out
}

/// Pure analyzer: walk the `route.configs` JSON array returned by
/// `/config`. Online `/config` always redacts keys, so encrypted
/// configs come back as `key: null, key_redacted: true`.
fn analyze_backend_config_online(
    server_id_hex: &str,
    configs: &[Value],
    config_id_filter: Option<u8>,
) -> Vec<Value> {
    let mut out = Vec::new();

    for cfg in configs {
        let config_id = cfg.get("config_id").and_then(|n| n.as_u64()).unwrap_or(0) as u8;

        if let Some(filter) = config_id_filter
            && config_id != filter
        {
            continue;
        }

        let Some(servers) = cfg.get("servers").and_then(|s| s.as_array()) else {
            continue;
        };
        let Some(server) = servers
            .iter()
            .find(|s| s.get("id").and_then(|i| i.as_str()) == Some(server_id_hex))
        else {
            continue;
        };

        let encryption = cfg
            .get("encryption")
            .and_then(|s| s.as_str())
            .unwrap_or("?");
        let sid_len = cfg
            .get("server_id_length")
            .and_then(|n| n.as_u64())
            .unwrap_or(0) as u8;
        let nonce_len = cfg
            .get("nonce_length")
            .and_then(|n| n.as_u64())
            .unwrap_or(0) as u8;
        let first_octet_encodes_cid_length = cfg
            .get("first_octet_encodes_cid_length")
            .and_then(|b| b.as_bool())
            .unwrap_or(false);
        let address = server.get("address").and_then(|a| a.as_str()).unwrap_or("");
        let draining = server
            .get("draining")
            .and_then(|b| b.as_bool())
            .unwrap_or(false);

        // `/config` strips keys server-side, so anything other than
        // plaintext is reported as redacted regardless of caller flags.
        let key_redacted = encryption != "plaintext";

        out.push(serde_json::json!({
            "config_id": config_id,
            "server_id": server_id_hex,
            "server_id_length": sid_len,
            "nonce_length": nonce_len,
            "first_octet_encodes_cid_length": first_octet_encodes_cid_length,
            "encryption": encryption,
            "key": Value::Null,
            "key_redacted": key_redacted,
            "draining": draining,
            "address": address,
            "cid_total_length": (1 + sid_len + nonce_len) as u16,
        }));
    }

    out
}

/// `endpoint <path> [target]` — escape hatch for any future status
/// endpoint without a dedicated subcommand. Path must start with `/`.
fn cmd_endpoint(args: &[String]) -> Result<(), TargetError> {
    if args.is_empty() {
        return Err(TargetError::ExtraArgs(
            "endpoint requires a path argument (e.g. /stats)".into(),
        ));
    }
    if args.len() > 2 {
        return Err(TargetError::ExtraArgs(format!(
            "expected '<path> [target]', got: {}",
            args.join(" ")
        )));
    }

    let path = &args[0];

    if !path.starts_with('/') {
        return Err(TargetError::ExtraArgs(format!(
            "endpoint path must start with '/', got '{}'",
            path
        )));
    }

    let target = args.get(1).map(String::as_str);
    let (_, v) = query_endpoint(target, path)?;

    print_pretty(&v);

    Ok(())
}

fn cmd_cleanup(args: &[String]) -> Result<(), TargetError> {
    expect_no_args(args)?;

    let instances = discover_instances();
    let mut removed = 0usize;
    let mut errors = 0usize;

    for inst in instances {
        let stale = inst.pidfile.is_some() && inst.cmdline.is_none();

        if !stale {
            continue;
        }

        // Safe to unwrap: stale implies pidfile.is_some().
        let path = inst.pidfile.unwrap();

        match fs::remove_file(&path) {
            Ok(()) => {
                println!("removed stale pidfile: {}", path.display());
                removed += 1;
            }
            Err(e) => {
                eprintln!("failed to remove {}: {}", path.display(), e);
                errors += 1;
            }
        }
    }

    if removed == 0 && errors == 0 {
        println!("no stale pidfiles");
    }
    if errors > 0 {
        // Surface a non-zero exit so callers (cron, scripts) notice.
        return Err(TargetError::Io(io::Error::other(format!(
            "{} pidfile(s) could not be removed",
            errors
        ))));
    }

    Ok(())
}

fn cmd_pin_info(args: &[String]) -> Result<(), TargetError> {
    let target_arg = expect_optional_target(args)?;

    // Pin-info only needs an interface name; the daemon doesn't have to
    // be running for pins to exist (handoff shutdown leaves them in
    // place). Accept a literal interface arg and only fall back to
    // discovery when the caller didn't supply one.
    let iface = match target_arg {
        Some(s) => match s.parse::<Target>()? {
            Target::Interface(i) => i,
            Target::Pid(_) => {
                return Err(TargetError::ExtraArgs(
                    "pin-info expects an interface name, not a pid".into(),
                ));
            }
        },
        None => resolve(None)?.interface,
    };

    let dir_path = format!("/sys/fs/bpf/pesigitg/{}", iface);

    println!("{}", dir_path);

    let entries = match fs::read_dir(&dir_path) {
        Ok(it) => it,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            println!(
                "  (no pin directory; daemon may not have run yet on {})",
                iface
            );

            return Ok(());
        }
        Err(e) => return Err(TargetError::Io(e)),
    };

    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();

    names.sort();

    if names.is_empty() {
        println!("  (empty)");
    } else {
        for n in names {
            println!("  {}", n);
        }
    }

    Ok(())
}

/// Per-tick snapshot of the counters watch cares about. Carries its
/// observation timestamp so rate computation uses real elapsed time
/// rather than the requested interval (sleep + RTT vary).
struct StatsSample {
    at: Instant,
    rx: u64,
    fwd: u64,
    cid: u64,
    fb: u64,
    unrt: u64,
    retry_iss: u64,
}

impl StatsSample {
    fn from_value(v: &Value, at: Instant) -> Self {
        let g = |k: &str| v.get(k).and_then(|n| n.as_u64()).unwrap_or(0);
        let retry_iss = v
            .get("retry")
            .and_then(|r| r.get("issued"))
            .and_then(|n| n.as_u64())
            .unwrap_or(0);

        Self {
            at,
            rx: g("rx_packets"),
            fwd: g("forwarded"),
            cid: g("cid_routed"),
            fb: g("fallback_routed"),
            unrt: g("cid_unroutable"),
            retry_iss,
        }
    }
}

fn rate(curr: u64, prev: u64, dt_secs: f64) -> String {
    if curr < prev {
        // Counter went backwards — daemon restarted between ticks.
        return "*".to_string();
    }
    let r = (curr - prev) as f64 / dt_secs;
    if r >= 10_000.0 {
        format!("{:.0}", r)
    } else if r >= 100.0 {
        format!("{:.1}", r)
    } else {
        format!("{:.2}", r)
    }
}

fn watch_header() -> String {
    format!(
        "{:<8}  {:>10}  {:>10}  {:>10}  {:>12}  {:>10}  {:>12}",
        "elapsed", "rx/s", "fwd/s", "cid/s", "fallback/s", "unrt/s", "retry_iss/s"
    )
}

fn cmd_watch(args: &[String]) -> Result<(), TargetError> {
    let (interval_str, rest) = extract_flag(args, "-n", "--interval")?;
    let interval_secs: u64 = match interval_str.as_deref() {
        None => 1,
        Some(s) => s.parse().map_err(|_| {
            TargetError::ExtraArgs(format!("--interval expects an integer, got '{}'", s))
        })?,
    };

    if interval_secs == 0 {
        return Err(TargetError::ExtraArgs(
            "--interval must be at least 1 second".into(),
        ));
    }

    let target = expect_optional_target(&rest)?.map(String::from);
    let interval = Duration::from_secs(interval_secs);

    let header = watch_header();

    println!("{}", header);

    let start = Instant::now();
    let mut prev: Option<StatsSample> = None;
    let mut row: usize = 0;

    loop {
        let (_, v) = query_endpoint(target.as_deref(), "/stats")?;
        let now = Instant::now();
        let sample = StatsSample::from_value(&v, now);
        let elapsed = format!("{}s", start.elapsed().as_secs());

        match &prev {
            None => {
                println!(
                    "{:<8}  {:>10}  {:>10}  {:>10}  {:>12}  {:>10}  {:>12}",
                    elapsed, "-", "-", "-", "-", "-", "-"
                );
            }
            Some(p) => {
                let dt = sample.at.duration_since(p.at).as_secs_f64().max(1e-9);

                println!(
                    "{:<8}  {:>10}  {:>10}  {:>10}  {:>12}  {:>10}  {:>12}",
                    elapsed,
                    rate(sample.rx, p.rx, dt),
                    rate(sample.fwd, p.fwd, dt),
                    rate(sample.cid, p.cid, dt),
                    rate(sample.fb, p.fb, dt),
                    rate(sample.unrt, p.unrt, dt),
                    rate(sample.retry_iss, p.retry_iss, dt),
                );
            }
        }

        prev = Some(sample);
        row += 1;

        // Repaint the header every 20 rows so a long-running watch
        // remains readable after scrollback.
        if row.is_multiple_of(20) {
            println!("{}", header);
        }

        thread::sleep(interval);
    }
}

fn cmd_help(args: &[String]) -> Result<(), TargetError> {
    expect_no_args(args)?;

    print_usage();

    Ok(())
}

fn print_usage() {
    println!("pesigitg-ctl — control utility for pesigitgd instances");
    println!();
    println!("Usage: pesigitg-ctl <command> [args]");
    println!("       pesigitg-ctl -h | --help");
    println!("       pesigitg-ctl -V | --version");
    println!();
    println!("Commands:");

    let width = CMDS.iter().map(|c| c.name.len()).max().unwrap_or(0);

    for c in CMDS {
        println!("  {:<w$}  {}", c.name, c.summary, w = width);

        if !c.aliases.is_empty() {
            println!(
                "  {:<w$}  (aliases: {})",
                "",
                c.aliases.join(", "),
                w = width
            );
        }
    }

    println!();
    println!("A unique prefix is accepted (e.g. 'co' → config, 'res' → restart).");
    println!("Targets are an interface name (e.g. eth0) or a pid. With exactly");
    println!("one running instance, the target may be omitted.");
}

fn send_signal(pid: u32, sig: libc::c_int) -> Result<(), TargetError> {
    // SAFETY: libc::kill is a thin wrapper over the kill(2) syscall; no
    // invariants are violated by calling it with a pid_t and a signal
    // number. Return code is checked for error.
    let ret = unsafe { libc::kill(pid as libc::pid_t, sig) };

    if ret != 0 {
        return Err(TargetError::Io(io::Error::last_os_error()));
    }

    Ok(())
}

static CMDS: &[Cmd] = &[
    Cmd {
        name: "list",
        aliases: &[],
        summary: "list discovered pesigitgd instances",
        run: cmd_list,
    },
    Cmd {
        name: "status",
        aliases: &[],
        summary: "one-line health summary for a target",
        run: cmd_status,
    },
    Cmd {
        name: "health",
        aliases: &[],
        summary: "fetch /health JSON",
        run: cmd_health,
    },
    Cmd {
        name: "stats",
        aliases: &[],
        summary: "fetch /stats JSON",
        run: cmd_stats,
    },
    Cmd {
        name: "config",
        aliases: &[],
        summary: "fetch /config JSON (live daemon args + route table)",
        run: cmd_config,
    },
    Cmd {
        name: "info",
        aliases: &[],
        summary: "fetch /version JSON from the daemon (build identifiers)",
        run: cmd_info,
    },
    Cmd {
        name: "endpoint",
        aliases: &[],
        summary: "fetch an arbitrary status endpoint: endpoint <path> [target]",
        run: cmd_endpoint,
    },
    Cmd {
        name: "whoami",
        aliases: &[],
        summary: "decode a QUIC CID: whoami <cid-hex> [target] [--route-config <path>]",
        run: cmd_whoami,
    },
    Cmd {
        name: "backend-config",
        aliases: &[],
        summary: "emit per-backend QUIC-LB provisioning JSON: backend-config <server-id-hex> [target] [-r <path>] [--no-key] [--config-id N]",
        run: cmd_backend_config,
    },
    Cmd {
        name: "watch",
        aliases: &[],
        summary: "poll /stats periodically and print rate deltas: watch [target] [-n SECS]",
        run: cmd_watch,
    },
    Cmd {
        name: "pin-info",
        aliases: &[],
        summary: "list bpffs pins under /sys/fs/bpf/pesigitg/<iface>/",
        run: cmd_pin_info,
    },
    Cmd {
        name: "cleanup",
        aliases: &[],
        summary: "remove stale pidfiles for daemons that are no longer running",
        run: cmd_cleanup,
    },
    Cmd {
        name: "hup",
        aliases: &["reload"],
        summary: "send SIGHUP (reload daemon + route config, reset health backoff)",
        run: cmd_hup,
    },
    Cmd {
        name: "stop",
        aliases: &[],
        summary: "send SIGTERM (graceful shutdown)",
        run: cmd_stop,
    },
    Cmd {
        name: "dump-stats",
        aliases: &["usr1"],
        summary: "send SIGUSR1 (log a stats snapshot)",
        run: cmd_dump_stats,
    },
    Cmd {
        name: "restart",
        aliases: &["usr2", "handoff"],
        summary: "send SIGUSR2 (zero-drop handoff to a fresh process)",
        run: cmd_restart,
    },
    Cmd {
        name: "version",
        aliases: &[],
        summary: "print this control utility's version",
        run: cmd_version,
    },
    Cmd {
        name: "paths",
        aliases: &[],
        summary: "show pidfile, runtime, and bpffs pin paths",
        run: cmd_paths,
    },
    Cmd {
        name: "help",
        aliases: &[],
        summary: "show this help",
        run: cmd_help,
    },
];

/// Resolve a command name. Exact matches (including aliases) win; if
/// none, fall back to a unique prefix on the primary name. Ambiguous
/// prefixes are an error so we never silently pick `status` over
/// `stats` based on table order.
fn find_cmd(name: &str) -> Result<&'static Cmd, String> {
    for c in CMDS {
        if c.name == name || c.aliases.contains(&name) {
            return Ok(c);
        }
    }

    let matches: Vec<&'static Cmd> = CMDS.iter().filter(|c| c.name.starts_with(name)).collect();

    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(format!(
            "unknown command: {} (try `pesigitg-ctl help`)",
            name
        )),
        _ => {
            let names: Vec<&str> = matches.iter().map(|c| c.name).collect();
            Err(format!(
                "ambiguous command '{}' (matches: {})",
                name,
                names.join(", ")
            ))
        }
    }
}

fn convert(args: Vec<OsString>) -> Vec<String> {
    args.into_iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect()
}

fn run() -> Result<(), String> {
    let mut pargs = Arguments::from_env();

    // Pull the command first so `pesigitg-ctl status --help` routes to
    // per-command help instead of being eaten by the top-level scan.
    let cmd_name = pargs.subcommand().map_err(|e| e.to_string())?;

    let Some(cmd_name) = cmd_name else {
        if pargs.contains(["-h", "--help"]) {
            print_usage();
        } else if pargs.contains(["-V", "--version"]) {
            println!("{}", env!("CARGO_PKG_VERSION"));
        } else {
            return Err("missing command (try `pesigitg-ctl help`)".into());
        }

        return Ok(());
    };

    let cmd = find_cmd(&cmd_name)?;
    let raw = pargs.finish();
    let args = convert(raw);

    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{}: {}", cmd.name, cmd.summary);

        if !cmd.aliases.is_empty() {
            println!("  aliases: {}", cmd.aliases.join(", "));
        }

        return Ok(());
    }

    (cmd.run)(&args).map_err(|e| e.to_string())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);

        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iface_from_pidfile_accepts_typical() {
        assert_eq!(iface_from_pidfile("pesigitgd-eth0.pid"), Some("eth0"));
        assert_eq!(
            iface_from_pidfile("pesigitgd-enp2s0f0.pid"),
            Some("enp2s0f0")
        );
    }

    #[test]
    fn iface_from_pidfile_rejects_non_matches() {
        assert_eq!(iface_from_pidfile("pesigitgd.pid"), None);
        assert_eq!(iface_from_pidfile("pesigitgd-.pid"), None);
        assert_eq!(iface_from_pidfile("other-eth0.pid"), None);
        assert_eq!(iface_from_pidfile("pesigitgd-eth0"), None);
    }

    #[test]
    fn iface_from_sockname_accepts_typical() {
        assert_eq!(iface_from_sockname("status-eth0.sock"), Some("eth0"));
        assert_eq!(
            iface_from_sockname("status-enp2s0f0.sock"),
            Some("enp2s0f0")
        );
    }

    #[test]
    fn iface_from_sockname_rejects_non_matches() {
        assert_eq!(iface_from_sockname("status-.sock"), None);
        assert_eq!(iface_from_sockname("eth0.sock"), None);
        assert_eq!(iface_from_sockname("status-eth0"), None);
    }

    #[test]
    fn iface_from_cmdline_short_space() {
        let cmd = b"pesigitgd\0-i\0eth0\0-p\x00443\0";
        assert_eq!(iface_from_cmdline(cmd), Some("eth0".to_string()));
    }

    #[test]
    fn iface_from_cmdline_short_combined() {
        // short-space-opt form: -ieth0.
        let cmd = b"pesigitgd\0-ieth0\0";
        assert_eq!(iface_from_cmdline(cmd), Some("eth0".to_string()));
    }

    #[test]
    fn iface_from_cmdline_long_space() {
        let cmd = b"pesigitgd\0--interface\0eth0\0";
        assert_eq!(iface_from_cmdline(cmd), Some("eth0".to_string()));
    }

    #[test]
    fn iface_from_cmdline_long_equals() {
        let cmd = b"pesigitgd\0--interface=eth0\0";
        assert_eq!(iface_from_cmdline(cmd), Some("eth0".to_string()));
    }

    #[test]
    fn iface_from_cmdline_missing_when_only_config() {
        let cmd = b"pesigitgd\0-c\0/etc/pesigitg.conf\0";
        assert_eq!(iface_from_cmdline(cmd), None);
    }

    #[test]
    fn iface_from_cmdline_handles_dangling_flag() {
        // -i at end of args with no value is not a match.
        let cmd = b"pesigitgd\0-i\0";
        assert_eq!(iface_from_cmdline(cmd), None);
    }

    #[test]
    fn target_parses_pid() {
        assert_eq!("1234".parse::<Target>().unwrap(), Target::Pid(1234));
    }

    #[test]
    fn target_parses_interface() {
        assert_eq!(
            "eth0".parse::<Target>().unwrap(),
            Target::Interface("eth0".to_string())
        );
    }

    #[test]
    fn target_rejects_empty() {
        assert!(matches!("".parse::<Target>(), Err(TargetError::Empty)));
        assert!(matches!("   ".parse::<Target>(), Err(TargetError::Empty)));
    }

    #[test]
    fn target_trims_whitespace() {
        assert_eq!(
            "  eth0  ".parse::<Target>().unwrap(),
            Target::Interface("eth0".to_string())
        );
        assert_eq!(" 42 ".parse::<Target>().unwrap(), Target::Pid(42));
    }

    #[test]
    fn find_cmd_exact_match_wins_over_prefix() {
        // `stats` is an exact match even though `status` shares its
        // first four letters; alias/exact resolution must run first.
        let c = find_cmd("stats").unwrap();
        assert_eq!(c.name, "stats");
    }

    #[test]
    fn find_cmd_alias_resolves_to_primary() {
        assert_eq!(find_cmd("reload").unwrap().name, "hup");
        assert_eq!(find_cmd("usr1").unwrap().name, "dump-stats");
        assert_eq!(find_cmd("usr2").unwrap().name, "restart");
        assert_eq!(find_cmd("handoff").unwrap().name, "restart");
    }

    #[test]
    fn find_cmd_unique_prefix() {
        assert_eq!(find_cmd("hu").unwrap().name, "hup");
        assert_eq!(find_cmd("co").unwrap().name, "config");
        assert_eq!(find_cmd("res").unwrap().name, "restart");
    }

    #[test]
    fn find_cmd_ambiguous_prefix_rejected() {
        // `s` matches status, stats, stop — must error rather than pick
        // whichever sits first in the table.
        let err = find_cmd("s").unwrap_err();
        assert!(err.contains("ambiguous"), "got: {}", err);
    }

    #[test]
    fn find_cmd_unknown() {
        let err = find_cmd("nope").unwrap_err();
        assert!(err.contains("unknown"), "got: {}", err);
    }

    #[test]
    fn expect_no_args_accepts_empty() {
        assert!(expect_no_args(&[]).is_ok());
    }

    #[test]
    fn expect_no_args_rejects_extras() {
        let args = vec!["x".to_string()];
        assert!(matches!(
            expect_no_args(&args),
            Err(TargetError::ExtraArgs(_))
        ));
    }

    #[test]
    fn expect_optional_target_zero_or_one() {
        assert_eq!(expect_optional_target(&[]).unwrap(), None);
        let one = vec!["eth0".to_string()];
        assert_eq!(expect_optional_target(&one).unwrap(), Some("eth0"));
    }

    #[test]
    fn expect_optional_target_rejects_two() {
        let two = vec!["eth0".to_string(), "extra".to_string()];
        assert!(matches!(
            expect_optional_target(&two),
            Err(TargetError::ExtraArgs(_))
        ));
    }

    #[test]
    fn format_duration_units() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(59), "59s");
        assert_eq!(format_duration(60), "1m0s");
        assert_eq!(format_duration(3600), "1h0m");
        assert_eq!(format_duration(86_400), "1d0h");
    }

    #[test]
    fn extract_flag_short_space() {
        let args = vec!["-n".into(), "5".into(), "eth0".into()];
        let (v, rest) = extract_flag(&args, "-n", "--interval").unwrap();
        assert_eq!(v.as_deref(), Some("5"));
        assert_eq!(rest, vec!["eth0".to_string()]);
    }

    #[test]
    fn extract_flag_long_space() {
        let args = vec!["--interval".into(), "10".into()];
        let (v, rest) = extract_flag(&args, "-n", "--interval").unwrap();
        assert_eq!(v.as_deref(), Some("10"));
        assert!(rest.is_empty());
    }

    #[test]
    fn extract_flag_long_equals() {
        let args = vec!["--interval=2".into(), "eth0".into()];
        let (v, rest) = extract_flag(&args, "-n", "--interval").unwrap();
        assert_eq!(v.as_deref(), Some("2"));
        assert_eq!(rest, vec!["eth0".to_string()]);
    }

    #[test]
    fn extract_flag_absent_leaves_args() {
        let args = vec!["eth0".into()];
        let (v, rest) = extract_flag(&args, "-n", "--interval").unwrap();
        assert!(v.is_none());
        assert_eq!(rest, vec!["eth0".to_string()]);
    }

    #[test]
    fn extract_flag_dangling_value() {
        let args = vec!["-n".into()];
        assert!(matches!(
            extract_flag(&args, "-n", "--interval"),
            Err(TargetError::ExtraArgs(_))
        ));
    }

    #[test]
    fn extract_flag_last_occurrence_wins() {
        let args = vec!["-n".into(), "1".into(), "--interval=5".into()];
        let (v, rest) = extract_flag(&args, "-n", "--interval").unwrap();
        assert_eq!(v.as_deref(), Some("5"));
        assert!(rest.is_empty());
    }

    #[test]
    fn rate_zero_delta_is_zero() {
        assert_eq!(rate(100, 100, 1.0), "0.00");
    }

    #[test]
    fn rate_counter_reset_marker() {
        // Daemon restart: counter went backwards.
        assert_eq!(rate(5, 1000, 1.0), "*");
    }

    #[test]
    fn rate_scales_format_to_magnitude() {
        // < 100 keeps two decimals.
        assert_eq!(rate(110, 100, 1.0), "10.00");
        // [100, 10_000) keeps one decimal.
        assert_eq!(rate(1100, 100, 1.0), "1000.0");
        // >= 10_000 rounds to integer.
        assert_eq!(rate(20_100, 100, 1.0), "20000");
    }

    // ----- whoami analyzer -----

    use serde_json::json;

    fn plaintext_cfg(config_id: u8, sid_len: u8, nonce_len: u8, servers: Value) -> Value {
        json!({
            "config_id": config_id,
            "encryption": "plaintext",
            "server_id_length": sid_len,
            "nonce_length": nonce_len,
            "servers": servers,
        })
    }

    fn server(id_hex: &str, addr: &str, mac: &str, healthy: bool, draining: bool) -> Value {
        json!({
            "id": id_hex,
            "address": addr,
            "mac": mac,
            "healthy": healthy,
            "draining": draining,
        })
    }

    fn find_line<'a>(lines: &'a [String], prefix: &str) -> &'a str {
        lines
            .iter()
            .find(|l| l.starts_with(prefix))
            .unwrap_or_else(|| panic!("no line starting with '{}': {:#?}", prefix, lines))
    }

    #[test]
    fn whoami_reserved_config_id() {
        // First octet 0xe0 → top three bits = 7 (reserved).
        let cid = vec![0xe0, 0x00, 0x01];
        let out = analyze_whoami(&cid, &[]);
        assert!(find_line(&out, "verdict:").contains("reserved"));
    }

    #[test]
    fn whoami_unknown_config_id() {
        // 0x40 → config_id = 2; configs only define 0.
        let cid = vec![0x40, 0x00, 0x01];
        let configs = vec![plaintext_cfg(0, 3, 13, json!([]))];
        let out = analyze_whoami(&cid, &configs);
        assert!(find_line(&out, "verdict:").contains("no route config with config_id=2"));
    }

    #[test]
    fn whoami_truncated_cid() {
        // Plaintext config requires sid_len=3 + nonce_len=13 = 16 byte payload.
        let cid = vec![0x00, 0x01, 0x02];
        let configs = vec![plaintext_cfg(0, 3, 13, json!([]))];
        let out = analyze_whoami(&cid, &configs);
        let v = find_line(&out, "verdict:");
        assert!(v.contains("truncated"));
        assert!(
            v.contains("17"),
            "expected payload-required count in: {}",
            v
        );
    }

    #[test]
    fn whoami_plaintext_routes_to_known_server() {
        // server_id = 0x000001, full payload follows.
        let mut cid = vec![0x00];
        cid.extend_from_slice(&[0x00, 0x00, 0x01]);
        cid.extend_from_slice(&[0x00; 13]);
        let configs = vec![plaintext_cfg(
            0,
            3,
            13,
            json!([
                server("000001", "10.0.1.10:443", "aa:bb:cc:dd:ee:01", true, false),
                server("000002", "10.0.1.11:443", "aa:bb:cc:dd:ee:02", true, false),
            ]),
        )];
        let out = analyze_whoami(&cid, &configs);
        assert_eq!(find_line(&out, "server_id:"), "server_id: 000001");
        let v = find_line(&out, "verdict:");
        assert!(v.contains("routes to 10.0.1.10:443"));
        assert!(v.contains("aa:bb:cc:dd:ee:01"));
        assert_eq!(find_line(&out, "state:"), "state:     healthy");
    }

    #[test]
    fn whoami_plaintext_draining_server_flagged() {
        let mut cid = vec![0x00];
        cid.extend_from_slice(&[0x00, 0x00, 0x01]);
        cid.extend_from_slice(&[0x00; 13]);
        let configs = vec![plaintext_cfg(
            0,
            3,
            13,
            json!([server(
                "000001",
                "10.0.1.10:443",
                "aa:bb:cc:dd:ee:01",
                true,
                true
            )]),
        )];
        let out = analyze_whoami(&cid, &configs);
        assert!(find_line(&out, "state:").contains("draining"));
    }

    #[test]
    fn whoami_plaintext_unhealthy_server_flagged() {
        let mut cid = vec![0x00];
        cid.extend_from_slice(&[0x00, 0x00, 0x01]);
        cid.extend_from_slice(&[0x00; 13]);
        let configs = vec![plaintext_cfg(
            0,
            3,
            13,
            json!([server(
                "000001",
                "10.0.1.10:443",
                "aa:bb:cc:dd:ee:01",
                false,
                false
            )]),
        )];
        let out = analyze_whoami(&cid, &configs);
        assert!(find_line(&out, "state:").contains("UNHEALTHY"));
    }

    #[test]
    fn whoami_plaintext_unknown_server_flagged() {
        let mut cid = vec![0x00];
        cid.extend_from_slice(&[0xff, 0xff, 0xff]);
        cid.extend_from_slice(&[0x00; 13]);
        let configs = vec![plaintext_cfg(
            0,
            3,
            13,
            json!([server(
                "000001",
                "10.0.1.10:443",
                "aa:bb:cc:dd:ee:01",
                true,
                false
            )]),
        )];
        let out = analyze_whoami(&cid, &configs);
        let v = find_line(&out, "verdict:");
        assert!(v.contains("no entry"));
        assert!(v.contains("cid_unroutable"));
    }

    #[test]
    fn whoami_state_line_surfaces_transitions_and_age() {
        // Server view from /config now carries transitions and
        // state_since_secs. They should appear in whoami's state line
        // when present.
        let mut cid = vec![0x00];
        cid.extend_from_slice(&[0x00, 0x00, 0x01]);
        cid.extend_from_slice(&[0x00; 13]);
        let configs = vec![plaintext_cfg(
            0,
            3,
            13,
            json!([{
                "id": "000001",
                "address": "10.0.1.10:443",
                "mac": "aa:bb:cc:dd:ee:01",
                "healthy": true,
                "draining": false,
                "transitions": 3,
                "state_since_secs": 192,
            }]),
        )];
        let out = analyze_whoami(&cid, &configs);
        let state = find_line(&out, "state:");
        assert!(state.contains("healthy"));
        assert!(state.contains("for 3m12s"));
        assert!(state.contains("3 flaps"));
    }

    #[test]
    fn whoami_state_line_pluralizes_single_flap() {
        let mut cid = vec![0x00];
        cid.extend_from_slice(&[0x00, 0x00, 0x01]);
        cid.extend_from_slice(&[0x00; 13]);
        let configs = vec![plaintext_cfg(
            0,
            3,
            13,
            json!([{
                "id": "000001",
                "address": "10.0.1.10:443",
                "mac": "aa:bb:cc:dd:ee:01",
                "healthy": true,
                "draining": false,
                "transitions": 1,
                "state_since_secs": 5,
            }]),
        )];
        let out = analyze_whoami(&cid, &configs);
        let state = find_line(&out, "state:");
        assert!(state.contains("1 flap,") || state.ends_with("1 flap"));
        assert!(!state.contains("1 flaps"));
    }

    #[test]
    fn whoami_state_line_omits_counters_when_absent() {
        // Older /config responses (or pesigitg-ctl pointed at a
        // pre-update daemon) won't carry the new fields.
        let mut cid = vec![0x00];
        cid.extend_from_slice(&[0x00, 0x00, 0x01]);
        cid.extend_from_slice(&[0x00; 13]);
        let configs = vec![plaintext_cfg(
            0,
            3,
            13,
            json!([server(
                "000001",
                "10.0.1.10:443",
                "aa:bb:cc:dd:ee:01",
                true,
                false
            )]),
        )];
        let out = analyze_whoami(&cid, &configs);
        let state = find_line(&out, "state:");
        assert!(!state.contains("flap"));
        assert!(!state.contains("for "));
    }

    #[test]
    fn whoami_encrypted_scheme_defers_to_offline() {
        // single_pass with 16-byte payload (sid 3 + nonce 13).
        let mut cid = vec![0x00];
        cid.extend_from_slice(&[0xaa; 16]);
        let configs = vec![json!({
            "config_id": 0,
            "encryption": "single_pass",
            "server_id_length": 3,
            "nonce_length": 13,
            "servers": [server("000001", "10.0.1.10:443", "aa:bb:cc:dd:ee:01", true, false)],
        })];
        let out = analyze_whoami(&cid, &configs);
        let v = find_line(&out, "verdict:");
        assert!(v.contains("encrypted (single_pass)"));
        assert!(out.iter().any(|l| l.contains("--route-config")));
    }

    // ----- offline whoami analyzer -----

    fn parse_offline(toml: &str) -> Vec<RouteConfig> {
        pesigitg_routing::route::parse_routes(toml).unwrap()
    }

    const PLAINTEXT_TOML: &str = r#"
[[configs]]
config_id = 0
server_id_length = 3
nonce_length = 13

[[configs.servers]]
id = "000001"
address = "10.0.1.10"
mac = "aa:bb:cc:dd:ee:01"

[[configs.servers]]
id = "000002"
address = "10.0.1.11"
mac = "aa:bb:cc:dd:ee:02"
"#;

    #[test]
    fn offline_plaintext_routes_to_known_server() {
        let configs = parse_offline(PLAINTEXT_TOML);
        let mut cid = vec![0x00];
        cid.extend_from_slice(&[0x00, 0x00, 0x01]);
        cid.extend_from_slice(&[0x00; 13]);

        let out = analyze_whoami_offline(&cid, &configs);
        assert_eq!(find_line(&out, "scheme:"), "scheme:    plaintext");
        assert_eq!(find_line(&out, "server_id:"), "server_id: 000001");
        let v = find_line(&out, "verdict:");
        assert!(v.contains("routes to 10.0.1.10"));
        assert!(v.contains("aa:bb:cc:dd:ee:01"));
    }

    #[test]
    fn offline_reserved_config_id() {
        let cid = vec![0xe0, 0x00, 0x01];
        let out = analyze_whoami_offline(&cid, &[]);
        assert!(find_line(&out, "verdict:").contains("reserved"));
    }

    #[test]
    fn offline_unknown_config_id() {
        let configs = parse_offline(PLAINTEXT_TOML);
        let cid = vec![0x40, 0x00, 0x01];
        let out = analyze_whoami_offline(&cid, &configs);
        assert!(find_line(&out, "verdict:").contains("config_id=2"));
    }

    #[test]
    fn offline_truncated_cid() {
        let configs = parse_offline(PLAINTEXT_TOML);
        let cid = vec![0x00, 0x01, 0x02];
        let out = analyze_whoami_offline(&cid, &configs);
        let v = find_line(&out, "verdict:");
        assert!(v.contains("truncated"));
    }

    #[test]
    fn offline_unknown_server_flagged() {
        let configs = parse_offline(PLAINTEXT_TOML);
        let mut cid = vec![0x00];
        cid.extend_from_slice(&[0xff, 0xff, 0xff]);
        cid.extend_from_slice(&[0x00; 13]);

        let out = analyze_whoami_offline(&cid, &configs);
        let v = find_line(&out, "verdict:");
        assert!(v.contains("no entry"));
        assert!(v.contains("cid_unroutable"));
    }

    #[test]
    fn offline_draining_flag_surfaced() {
        let toml = r#"
[[configs]]
config_id = 0
server_id_length = 3
nonce_length = 13

[[configs.servers]]
id = "000001"
address = "10.0.1.10"
mac = "aa:bb:cc:dd:ee:01"
draining = true
"#;
        let configs = parse_offline(toml);
        let mut cid = vec![0x00];
        cid.extend_from_slice(&[0x00, 0x00, 0x01]);
        cid.extend_from_slice(&[0x00; 13]);

        let out = analyze_whoami_offline(&cid, &configs);
        assert_eq!(find_line(&out, "state:"), "state:     draining");
    }

    #[test]
    fn offline_encrypted_scheme_label() {
        // No need to round-trip a real ciphertext here — the routing
        // crate covers `resolve_server_idx` for single_pass/four_pass.
        // We just verify the analyzer reports the correct scheme name.
        let toml = r#"
[[configs]]
config_id = 0
server_id_length = 3
nonce_length = 13
key = "000102030405060708090a0b0c0d0e0f"

[[configs.servers]]
id = "000001"
address = "10.0.1.10"
"#;
        let configs = parse_offline(toml);
        let mut cid = vec![0x00];
        cid.extend_from_slice(&[0xaa; 16]);
        let out = analyze_whoami_offline(&cid, &configs);
        assert_eq!(find_line(&out, "scheme:"), "scheme:    single_pass");
        // The garbage payload almost certainly won't decrypt to a known
        // server_id; verdict should be a graceful unroutable, not panic.
        assert!(find_line(&out, "verdict:").contains("no entry"));
    }

    // ----- backend-config analyzer -----

    const ROLLOVER_TOML: &str = r#"
[[configs]]
config_id = 0
first_octet_encodes_cid_length = true
server_id_length = 3
nonce_length = 13
key = "597a84b3093ebb17567bcb7e06721d68"

[[configs.servers]]
id = "000001"
address = "10.0.1.10"

[[configs.servers]]
id = "000002"
address = "10.0.1.11"
draining = true

[[configs]]
config_id = 1
first_octet_encodes_cid_length = true
server_id_length = 3
nonce_length = 13
key = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"

[[configs.servers]]
id = "000001"
address = "10.0.1.10"
"#;

    const FOUR_PASS_TOML: &str = r#"
[[configs]]
config_id = 2
server_id_length = 3
nonce_length = 4
key = "000102030405060708090a0b0c0d0e0f"

[[configs.servers]]
id = "abc123"
address = "2001:db8::1"
"#;

    const PLAINTEXT_BACKEND_TOML: &str = r#"
[[configs]]
config_id = 0
server_id_length = 2
nonce_length = 5

[[configs.servers]]
id = "0001"
address = "10.0.1.10"
"#;

    #[test]
    fn backend_config_offline_single_pass_emits_all_fields() {
        let configs = parse_offline(ROLLOVER_TOML);
        let m = analyze_backend_config_offline("000002", &configs, false, None);
        assert_eq!(m.len(), 1);
        let entry = &m[0];
        assert_eq!(entry["config_id"], 0);
        assert_eq!(entry["server_id"], "000002");
        assert_eq!(entry["server_id_length"], 3);
        assert_eq!(entry["nonce_length"], 13);
        assert_eq!(entry["first_octet_encodes_cid_length"], true);
        assert_eq!(entry["encryption"], "single_pass");
        assert_eq!(entry["key"], "597a84b3093ebb17567bcb7e06721d68");
        assert_eq!(entry["key_redacted"], false);
        assert_eq!(entry["draining"], true);
        assert_eq!(entry["address"], "10.0.1.11");
        assert_eq!(entry["cid_total_length"], 17);
    }

    #[test]
    fn backend_config_offline_rollover_returns_both_configs() {
        // server_id 000001 is in both config_id 0 and config_id 1.
        let configs = parse_offline(ROLLOVER_TOML);
        let m = analyze_backend_config_offline("000001", &configs, false, None);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0]["config_id"], 0);
        assert_eq!(m[1]["config_id"], 1);
        // Different keys per config — the whole point of rollover.
        assert_ne!(m[0]["key"], m[1]["key"]);
    }

    #[test]
    fn backend_config_offline_no_key_redacts_only_encrypted() {
        let configs = parse_offline(ROLLOVER_TOML);
        let m = analyze_backend_config_offline("000001", &configs, true, None);
        assert_eq!(m.len(), 2);
        for entry in &m {
            assert_eq!(entry["encryption"], "single_pass");
            assert!(entry["key"].is_null());
            assert_eq!(entry["key_redacted"], true);
        }
    }

    #[test]
    fn backend_config_offline_plaintext_keeps_key_null_unredacted() {
        // No key exists at all — `key: null` but `key_redacted: false`
        // distinguishes "no key in config" from "key was hidden".
        let configs = parse_offline(PLAINTEXT_BACKEND_TOML);
        let m = analyze_backend_config_offline("0001", &configs, false, None);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0]["encryption"], "plaintext");
        assert!(m[0]["key"].is_null());
        assert_eq!(m[0]["key_redacted"], false);
    }

    #[test]
    fn backend_config_offline_four_pass_label() {
        let configs = parse_offline(FOUR_PASS_TOML);
        let m = analyze_backend_config_offline("abc123", &configs, false, None);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0]["encryption"], "four_pass");
        // 1 + 3 + 4 = 8 byte CID.
        assert_eq!(m[0]["cid_total_length"], 8);
    }

    #[test]
    fn backend_config_offline_config_id_filter() {
        let configs = parse_offline(ROLLOVER_TOML);
        let m = analyze_backend_config_offline("000001", &configs, false, Some(1));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0]["config_id"], 1);
    }

    #[test]
    fn backend_config_offline_no_match_returns_empty() {
        let configs = parse_offline(ROLLOVER_TOML);
        let m = analyze_backend_config_offline("ffffff", &configs, false, None);
        assert!(m.is_empty());
    }

    #[test]
    fn backend_config_online_redacts_keys_for_encrypted_configs() {
        // Mirror the shape `/config` actually emits: scheme name, no key.
        let configs = vec![json!({
            "config_id": 0,
            "encryption": "single_pass",
            "server_id_length": 3,
            "nonce_length": 13,
            "first_octet_encodes_cid_length": true,
            "servers": [
                {"id": "000001", "address": "10.0.1.10", "mac": "aa:bb:cc:dd:ee:01", "healthy": true, "draining": false},
            ],
        })];
        let m = analyze_backend_config_online("000001", &configs, None);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0]["encryption"], "single_pass");
        assert!(m[0]["key"].is_null());
        assert_eq!(m[0]["key_redacted"], true);
        assert_eq!(m[0]["cid_total_length"], 17);
        assert_eq!(m[0]["address"], "10.0.1.10");
    }

    #[test]
    fn backend_config_online_plaintext_unredacted() {
        let configs = vec![json!({
            "config_id": 0,
            "encryption": "plaintext",
            "server_id_length": 2,
            "nonce_length": 5,
            "first_octet_encodes_cid_length": false,
            "servers": [
                {"id": "0001", "address": "10.0.1.10", "mac": null, "healthy": true, "draining": false},
            ],
        })];
        let m = analyze_backend_config_online("0001", &configs, None);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0]["encryption"], "plaintext");
        assert_eq!(m[0]["key_redacted"], false);
    }

    #[test]
    fn backend_config_online_no_match_returns_empty() {
        let configs = vec![json!({
            "config_id": 0,
            "encryption": "plaintext",
            "server_id_length": 3,
            "nonce_length": 13,
            "first_octet_encodes_cid_length": true,
            "servers": [
                {"id": "000001", "address": "10.0.1.10", "mac": null, "healthy": true, "draining": false},
            ],
        })];
        let m = analyze_backend_config_online("ffffff", &configs, None);
        assert!(m.is_empty());
    }

    #[test]
    fn parse_cid_hex_accepts_typical() {
        let v = parse_cid_hex("0001020304").unwrap();
        assert_eq!(v, vec![0x00, 0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn parse_cid_hex_rejects_empty() {
        assert!(matches!(parse_cid_hex(""), Err(TargetError::ExtraArgs(_))));
    }

    #[test]
    fn parse_cid_hex_rejects_odd_length() {
        let err = parse_cid_hex("abc").unwrap_err();
        assert!(matches!(err, TargetError::ExtraArgs(_)));
    }

    #[test]
    fn parse_cid_hex_rejects_non_hex() {
        let err = parse_cid_hex("ab0g").unwrap_err();
        assert!(matches!(err, TargetError::ExtraArgs(_)));
    }
}
