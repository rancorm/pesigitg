// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

use std::{ffi::OsString, fs};
use std::str::FromStr;
use std::path::Path;
use std::fmt::Display;

use pico_args::Arguments;

use pesigitg_common::PID_DIR;

const PIDEXT: &str = ".pid";
const PIDPAT: &str = "pesigitgd-";
const RUNDIR: &str = "/var/run/pesigitg/";

type CmdFn = fn(&[String]) -> Result<(), TargetError>;

struct Cmd {
    name: &'static str,
    run: CmdFn,
}

macro_rules! iface {
    ($filename:expr, $start_ref:expr, $end_ref:expr) => {{
        let start = $start_ref.len();
        let end = $filename.len() - $end_ref.len();

        &$filename[start..end]
    }};
}

#[derive(Debug, PartialEq, Eq)]
enum Target {
    Interface(String),
    Pid(u32),
}

#[derive(Debug)]
enum TargetError {
    Empty,
    InvalidPid,
    InvalidInterface,
    Unsupported,
}

impl Display for TargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetError::Empty => write!(f, "no target"),
            TargetError::InvalidPid => write!(f, "invalid PID"),
            TargetError::InvalidInterface => write!(f, "invalid interface"),
            TargetError::Unsupported => write!(f, "not supported"),
        }
    }
}

impl FromStr for Target {
    type Err = TargetError;

    fn from_str(s: &str) -> Result<Self, TargetError> {
        if s.trim().is_empty() {
            return Err(TargetError::Empty);
        }

        if s.parse::<u32>().is_ok() {
            return Ok(Target::Pid(s.parse().unwrap()));
        }

        Ok(Target::Interface(s.to_string()))
    }
}

fn parse_arg(arg: &str) -> Result<Target, TargetError> {
    arg.parse()
}

fn cmd_list(_args: &[String]) -> Result<(), TargetError> {
    let pidfiles = fs::read_dir(PID_DIR);
    
    match pidfiles {
        Err(e) => eprintln!("PID directory error: {}", e),
        Ok(reader) => {

            // Enumerate PID files
            for entry in reader {
                match entry {
                    Ok(pidfile) => {
                        let path = pidfile.path();

                        // For every PID file we find, read it for PID and check for socket.
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            if is_pidfile(name) {
                                let pid = fs::read_to_string(&path).unwrap();
                                let iface = iface!(name, PIDPAT, PIDEXT);
                                let sock_path = format!("{}/status-{}.sock", RUNDIR, iface);

                                print!("{} (file: {}", pid, name);

                                if let Some(n) = sock_name(&sock_path) {
                                    print!(", socket: {}", n);
                                }

                                println!(")");
                            }
                        }
                    }
                    Err(e) => eprintln!("Error reading entry: {}", e),
                }
            }
        }
    }

    Ok(())
}

fn cmd_version(_args: &[String]) -> Result<(), TargetError> {
    let version = env!("CARGO_PKG_VERSION");
    
    println!("{}", version);

    Ok(()) 
}

fn cmd_paths(_args: &[String]) -> Result<(), TargetError> {
    // TODO: Retrieve all the important file/directory paths
    // output them.
    Ok(())
}

fn cmd_hub(args: &[String]) -> Result<(), TargetError> {
    if args.len() > 0 {
        let target = parse_arg(&args[0])?;

        match target {
            Target::Pid(pid) => println!("Got PID: {}", pid),
            Target::Interface(_) => return Err(TargetError::Unsupported),
        };

        return Ok(())
    }

    Err(TargetError::Empty)
}

fn cmd_status(_args: &[String]) -> Result<(), TargetError> {
    // TODO: Query status socket, first argument is /, /stats/, /config, etc.

    Ok(())
}

static CMDS: &[Cmd] = &[
    Cmd { name: "list", run: cmd_list },
    Cmd { name: "version", run: cmd_version },
    Cmd { name: "paths", run: cmd_paths },
    Cmd { name: "hub", run: cmd_hub },
    Cmd { name: "status", run: cmd_status },
];

fn sock_name(path: &str) -> Option<&str> {
    let sock_path = Path::new(path);

    // If the file at path exists, return the file name. Otherwise, None.
    match sock_path.exists() {
        true => sock_path
            .file_name()
            .and_then(|n| n.to_str()),
        false => None
    }
}

fn is_pidfile(name: &str) -> bool {
    name.starts_with(PIDPAT)
        && name.ends_with(PIDEXT)
}

fn convert(args: Vec<OsString>) -> Vec<String> {
    args.into_iter()
        .map(|s|
            s.to_string_lossy()
            .into_owned())
        .collect()
}

fn main() -> Result<(), String> {
    let mut pargs = Arguments::from_env(); 

    // First argument, command name
    let cmd_name: String = pargs
        .free_from_str()
        .map_err(|_| "missing command")?;

    // Find command or bail
    let cmd = CMDS
        .iter()
        .find(|c| c.name.starts_with(&cmd_name))
        .ok_or_else(|| format!("unknown command: {}", cmd_name))?;

    // Remaining positional args
    let raw = pargs.finish();
    let args = convert(raw);

    // Run it baby!
    (cmd.run)(&args)
        .map_err(|e| e.to_string())
}
