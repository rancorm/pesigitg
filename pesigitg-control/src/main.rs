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
use std::io;
use std::path::PathBuf;
use std::str::FromStr;

use pico_args::Arguments;

use pesigitg_common::{PID_DIR, PROC_NAME};

const RUN_DIR: &str = "/run/pesigitg";
const PIDFILE_PREFIX: &str = "pesigitgd-";
const PIDFILE_SUFFIX: &str = ".pid";
const SOCKET_PREFIX: &str = "status-";
const SOCKET_SUFFIX: &str = ".sock";

type CmdFn = fn(&[String]) -> Result<(), TargetError>;

struct Cmd {
    name: &'static str,
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
    #[allow(dead_code)]
    pidfile: Option<PathBuf>,
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
                    .ok_or_else(|| TargetError::NotFound(iface)),
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
        pidfile: i.pidfile.clone(),
    })
}

fn cmd_list(_args: &[String]) -> Result<(), TargetError> {
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

fn cmd_version(_args: &[String]) -> Result<(), TargetError> {
    println!("{}", env!("CARGO_PKG_VERSION"));

    Ok(())
}

fn cmd_paths(_args: &[String]) -> Result<(), TargetError> {
    println!("pidfile dir:    {}", PID_DIR);
    println!("runtime dir:    {}", RUN_DIR);
    println!("bpffs pin root: /sys/fs/bpf/pesigitg/<interface>/");

    Ok(())
}

fn cmd_hub(args: &[String]) -> Result<(), TargetError> {
    let target = resolve(args.first().map(String::as_str))?;

    send_signal(target.pid, libc::SIGHUP)?;

    println!("sent SIGHUP to {} (pid {})", target.interface, target.pid);

    Ok(())
}

fn cmd_status(args: &[String]) -> Result<(), TargetError> {
    let target = resolve(args.first().map(String::as_str))?;
    let socket = target
        .status_socket
        .as_ref()
        .ok_or_else(|| TargetError::NoStatusSocket(target.interface.clone()))?;

    // TODO: actually query /stats, /config, /health over the socket.

    println!("socket: {}", socket.display());

    Ok(())
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
        run: cmd_list,
    },
    Cmd {
        name: "version",
        run: cmd_version,
    },
    Cmd {
        name: "paths",
        run: cmd_paths,
    },
    Cmd {
        name: "hub",
        run: cmd_hub,
    },
    Cmd {
        name: "status",
        run: cmd_status,
    },
];

fn convert(args: Vec<OsString>) -> Vec<String> {
    args.into_iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect()
}

fn main() -> Result<(), String> {
    let mut pargs = Arguments::from_env();

    let cmd_name: String = pargs
        .free_from_str()
        .map_err(|_| "missing command".to_string())?;

    let cmd = CMDS
        .iter()
        .find(|c| c.name.starts_with(&cmd_name))
        .ok_or_else(|| format!("unknown command: {}", cmd_name))?;

    let raw = pargs.finish();
    let args = convert(raw);

    (cmd.run)(&args).map_err(|e| e.to_string())
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
        let cmd = b"pesigitgd\0-i\0eth0\0-p\0443\0";
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
}
