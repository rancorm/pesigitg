// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

use std::fmt;
use std::path::PathBuf;

use anyhow::{bail, Result};
use pesigitg_common::{DEFAULT_INTF, DEFAULT_PORT, DEFAULT_QUEUES, MAX_QUEUES, PROC_NAME, TAGLINE, exit};

use crate::config::daemon::FileConfig;

pub struct Args {
    pub ports: Vec<u16>,
    pub interface: String,
    pub queues: u32,
    pub config: Option<PathBuf>,
    pub routeconfig: Option<PathBuf>,
    #[cfg(debug_assertions)]
    pub ebpf_obj: Option<PathBuf>,
    pub foreground: bool,
}

impl fmt::Display for Args {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "daemon args:")?;
        writeln!(f, "  interface:      {}", self.interface)?;
        writeln!(f, "  ports:          {:?}", self.ports)?;
        writeln!(f, "  queues:         {}", self.queues)?;
        writeln!(f, "  foreground:     {}", self.foreground)?;
        match &self.config {
            Some(p) => writeln!(f, "  config:         {}", p.display())?,
            None => writeln!(f, "  config:         (none)")?,
        }
        match &self.routeconfig {
            Some(p) => writeln!(f, "  route config:   {}", p.display())?,
            None => writeln!(f, "  route config:   (default)")?,
        }
        #[cfg(debug_assertions)]
        match &self.ebpf_obj {
            Some(p) => writeln!(f, "  ebpf obj:       {}", p.display())?,
            None => writeln!(f, "  ebpf obj:       (embedded)")?,
        }
        Ok(())
    }
}

pub fn parse_args() -> Result<Args> {
    let mut pargs = pico_args::Arguments::from_env();

    // --version / -V
    if pargs.contains(["-V", "--version"]) {
        println!("{} {} ({})", PROC_NAME, env!("CARGO_PKG_VERSION"), env!("BUILD_DATE"));
        println!("{}", env!("RUSTC_VERSION"));
        println!("platform: {}", env!("TARGET"));

        exit!();
    }

    // --help / -h
    if pargs.contains(["-h", "--help"]) {
        println!(
            "{0} {2}\n\n\
            {1}\n\n\
            Usage: {0} [OPTIONS]\n\n\
            Options:\n  \
            -p, --port <PORT>         Port to listen on (repeatable)\n  \
            -i, --interface <NAME>    Network interface [default: {DEFAULT_INTF}]\n  \
            -c, --config <PATH>       Daemon config file path\n  \
            -q, --queues <NUM>        Number of NIC queues [default: 1]\n  \
            -f, --foreground          Run in foreground (don't daemonize)\n  \
            -V, --version             Print version\
        ", PROC_NAME, TAGLINE, env!("CARGO_PKG_VERSION"));

        #[cfg(debug_assertions)]
        {
            println!("\nDevelopment Options:");
            println!("  -l, --load-ebpf <PATH>    eBPF object path (overrides embedded)");
        }

        exit!();
    }

    #[cfg(debug_assertions)]
    let ebpf_obj: Option<PathBuf> = pargs.opt_value_from_str(["-l", "--load-ebpf"])?;
    let foreground = pargs.contains(["-f", "--foreground"]);
    let config: Option<PathBuf> = pargs.opt_value_from_str(["-c", "--config"])?;
    let interface: Option<String> = pargs.opt_value_from_str(["-i", "--interface"])?;
    let queues: Option<u32> = pargs.opt_value_from_str(["-q", "--queues"])?;

    // Collect all -p / --port values
    let mut ports = Vec::new();
    while let Some(port) = pargs.opt_value_from_str::<_, u16>(["-p", "--port"])? {
        ports.push(port);
    }

    // Check for unexpected arguments
    let remaining = pargs.finish();
    if !remaining.is_empty() {
        bail!("unknown arguments: {:?}", remaining);
    }

    // If config file provided, use it as base
    let file_config = config.as_ref().map(|path| {
        FileConfig::from_file(path)
    }).transpose()?;

    // CLI -> config file -> defaults
    let queues = queues
        .or(file_config.as_ref().map(|fc| fc.queues))
        .unwrap_or(DEFAULT_QUEUES);
    if queues == 0 || queues > MAX_QUEUES {
        bail!("--queues must be between 1 and {}", MAX_QUEUES);
    }

    // Build arguments struct
    Ok(Args {
        ports: if !ports.is_empty() {
            ports
        } else if let Some(ref fc) = file_config {
            fc.ports.clone()
        } else {
            vec![DEFAULT_PORT]
        },
        interface: interface
            .or(file_config.as_ref().map(|fc| fc.interface.clone()))
            .unwrap_or_else(|| DEFAULT_INTF.into()),
        queues,
        config,
        routeconfig: file_config.as_ref().and_then(|fc| fc.route_config.clone()),
        #[cfg(debug_assertions)]
        ebpf_obj,
        foreground,
    })
}
