// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

use std::fmt;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

use anyhow::{Result, bail};
use pesigitg_common::{
    DEFAULT_INTF, DEFAULT_PORT, DEFAULT_QUEUES, MAX_QUEUES, PROC_NAME, TAGLINE, exit,
};

use crate::config::daemon::FileConfig;

#[derive(Debug)]
pub struct Args {
    pub ports: Vec<u16>,
    pub interface: String,
    pub queues: u32,
    pub config: Option<PathBuf>,
    pub routeconfig: Option<PathBuf>,
    pub status_socket: Option<PathBuf>,
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
        match &self.status_socket {
            Some(p) => writeln!(f, "  status socket:  {}", p.display())?,
            None => writeln!(f, "  status socket:  (disabled)")?,
        }
        #[cfg(debug_assertions)]
        match &self.ebpf_obj {
            Some(p) => writeln!(f, "  ebpf obj:       {}", p.display())?,
            None => writeln!(f, "  ebpf obj:       (embedded)")?,
        }
        Ok(())
    }
}

/// Raw CLI flags, prior to merging with a config file or defaults.
///
/// Split out from [`Args`] so [`merge_args`] — the CLI > file > defaults
/// precedence ladder — can be tested without touching argv or the disk.
struct CliArgs {
    ports: Vec<u16>,
    interface: Option<String>,
    queues: Option<u32>,
    config: Option<PathBuf>,
    status_socket: Option<PathBuf>,
    #[cfg(debug_assertions)]
    ebpf_obj: Option<PathBuf>,
    foreground: bool,
}

fn parse_cli(mut pargs: pico_args::Arguments) -> Result<CliArgs> {
    #[cfg(debug_assertions)]
    let ebpf_obj: Option<PathBuf> = pargs.opt_value_from_str(["-l", "--load-ebpf"])?;
    let foreground = pargs.contains(["-f", "--foreground"]);
    let config: Option<PathBuf> = pargs.opt_value_from_str(["-c", "--config"])?;
    let interface: Option<String> = pargs.opt_value_from_str(["-i", "--interface"])?;
    let queues: Option<u32> = pargs.opt_value_from_str(["-q", "--queues"])?;
    let status_socket: Option<PathBuf> = pargs.opt_value_from_str(["-s", "--status-socket"])?;

    let mut ports = Vec::new();
    while let Some(port) = pargs.opt_value_from_str::<_, u16>(["-p", "--port"])? {
        ports.push(port);
    }

    let remaining = pargs.finish();
    if !remaining.is_empty() {
        bail!("unknown arguments: {:?}", remaining);
    }

    Ok(CliArgs {
        ports,
        interface,
        queues,
        config,
        status_socket,
        #[cfg(debug_assertions)]
        ebpf_obj,
        foreground,
    })
}

/// Resolve CLI args against an optional config file and compiled-in defaults.
///
/// Precedence: CLI > file > default. `queues` range is validated here because
/// it is a cross-source concern: a bogus value from either source must fail.
fn merge_args(cli: CliArgs, file_config: Option<FileConfig>) -> Result<Args> {
    let queues = cli
        .queues
        .or(file_config.as_ref().map(|fc| fc.queues))
        .unwrap_or(DEFAULT_QUEUES);
    if queues == 0 || queues > MAX_QUEUES {
        bail!("--queues must be between 1 and {}", MAX_QUEUES);
    }

    Ok(Args {
        ports: if !cli.ports.is_empty() {
            cli.ports
        } else if let Some(ref fc) = file_config {
            fc.ports.clone()
        } else {
            vec![DEFAULT_PORT]
        },
        interface: cli
            .interface
            .or(file_config.as_ref().map(|fc| fc.interface.clone()))
            .unwrap_or_else(|| DEFAULT_INTF.into()),
        queues,
        config: cli.config,
        routeconfig: file_config.as_ref().and_then(|fc| fc.route_config.clone()),
        status_socket: cli
            .status_socket
            .or_else(|| file_config.as_ref().and_then(|fc| fc.status_socket.clone())),
        #[cfg(debug_assertions)]
        ebpf_obj: cli.ebpf_obj,
        foreground: cli.foreground,
    })
}

pub fn parse_args() -> Result<Args> {
    let mut pargs = pico_args::Arguments::from_env();

    // --version / -V
    if pargs.contains(["-V", "--version"]) {
        println!(
            "{} {} ({})",
            PROC_NAME,
            env!("CARGO_PKG_VERSION"),
            env!("BUILD_DATE")
        );
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
            -s, --status-socket <PATH> Unix-domain socket for JSON status API (disabled if unset)\n  \
            -f, --foreground          Run in foreground (don't daemonize)\n  \
            -V, --version             Print version\
        ",
            PROC_NAME,
            TAGLINE,
            env!("CARGO_PKG_VERSION")
        );

        #[cfg(debug_assertions)]
        {
            println!("\nDevelopment Options:");
            println!("  -l, --load-ebpf <PATH>    eBPF object path (overrides embedded)");
        }

        exit!();
    }

    let cli = parse_cli(pargs)?;
    let file_config = cli.config.as_ref().map(FileConfig::from_file).transpose()?;
    merge_args(cli, file_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_cli() -> CliArgs {
        CliArgs {
            ports: Vec::new(),
            interface: None,
            queues: None,
            config: None,
            status_socket: None,
            #[cfg(debug_assertions)]
            ebpf_obj: None,
            foreground: false,
        }
    }

    fn file_with(interface: &str, queues: u32, ports: Vec<u16>) -> FileConfig {
        FileConfig {
            ports,
            interface: interface.into(),
            queues,
            route_config: None,
            status_socket: None,
        }
    }

    #[test]
    fn defaults_when_nothing_specified() {
        let args = merge_args(empty_cli(), None).unwrap();
        assert_eq!(args.ports, vec![DEFAULT_PORT]);
        assert_eq!(args.interface, DEFAULT_INTF);
        assert_eq!(args.queues, DEFAULT_QUEUES);
        assert!(args.config.is_none());
        assert!(args.routeconfig.is_none());
        assert!(args.status_socket.is_none());
        assert!(!args.foreground);
    }

    #[test]
    fn cli_port_overrides_file_port() {
        let cli = CliArgs {
            ports: vec![1234],
            ..empty_cli()
        };
        let file = file_with("eth0", 1, vec![443, 8443]);
        let args = merge_args(cli, Some(file)).unwrap();
        assert_eq!(args.ports, vec![1234]);
    }

    #[test]
    fn file_port_used_when_cli_absent() {
        let file = file_with("eth0", 1, vec![9000, 9001]);
        let args = merge_args(empty_cli(), Some(file)).unwrap();
        assert_eq!(args.ports, vec![9000, 9001]);
    }

    #[test]
    fn cli_ports_do_not_merge_with_file_ports() {
        // Precedence is all-or-nothing, not set-union.
        let cli = CliArgs {
            ports: vec![443],
            ..empty_cli()
        };
        let file = file_with("eth0", 1, vec![8443, 9443]);
        let args = merge_args(cli, Some(file)).unwrap();
        assert_eq!(args.ports, vec![443]);
    }

    #[test]
    fn interface_precedence() {
        let args = merge_args(
            CliArgs {
                interface: Some("cli-if".into()),
                ..empty_cli()
            },
            Some(file_with("file-if", 1, vec![443])),
        )
        .unwrap();
        assert_eq!(args.interface, "cli-if");

        let args = merge_args(empty_cli(), Some(file_with("file-if", 1, vec![443]))).unwrap();
        assert_eq!(args.interface, "file-if");

        let args = merge_args(empty_cli(), None).unwrap();
        assert_eq!(args.interface, DEFAULT_INTF);
    }

    #[test]
    fn queues_precedence() {
        let args = merge_args(
            CliArgs {
                queues: Some(8),
                ..empty_cli()
            },
            Some(file_with("eth0", 4, vec![443])),
        )
        .unwrap();
        assert_eq!(args.queues, 8);

        let args = merge_args(empty_cli(), Some(file_with("eth0", 4, vec![443]))).unwrap();
        assert_eq!(args.queues, 4);
    }

    #[test]
    fn queues_zero_rejected() {
        let err = merge_args(
            CliArgs {
                queues: Some(0),
                ..empty_cli()
            },
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("between 1"));
    }

    #[test]
    fn queues_over_max_rejected() {
        let err = merge_args(
            CliArgs {
                queues: Some(MAX_QUEUES + 1),
                ..empty_cli()
            },
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains(&MAX_QUEUES.to_string()));
    }

    #[test]
    fn queues_out_of_range_from_file_also_rejected() {
        // The bounds check must be cross-source, not CLI-only.
        let file = FileConfig {
            ports: vec![443],
            interface: "eth0".into(),
            queues: MAX_QUEUES + 100,
            route_config: None,
            status_socket: None,
        };
        let err = merge_args(empty_cli(), Some(file)).unwrap_err();
        assert!(err.to_string().contains("between 1"));
    }

    #[test]
    fn status_socket_cli_wins() {
        let cli = CliArgs {
            status_socket: Some(PathBuf::from("/cli.sock")),
            ..empty_cli()
        };
        let file = FileConfig {
            status_socket: Some(PathBuf::from("/file.sock")),
            ..file_with("eth0", 1, vec![443])
        };
        let args = merge_args(cli, Some(file)).unwrap();
        assert_eq!(args.status_socket.as_deref(), Some(Path::new("/cli.sock")));
    }

    #[test]
    fn status_socket_file_used_when_cli_absent() {
        let file = FileConfig {
            status_socket: Some(PathBuf::from("/file.sock")),
            ..file_with("eth0", 1, vec![443])
        };
        let args = merge_args(empty_cli(), Some(file)).unwrap();
        assert_eq!(args.status_socket.as_deref(), Some(Path::new("/file.sock")));
    }

    #[test]
    fn routeconfig_comes_from_file_only() {
        // There is no CLI flag for routeconfig; it's exclusively a file-level concern.
        let file = FileConfig {
            route_config: Some(PathBuf::from("/etc/pesigitg/lb.toml")),
            ..file_with("eth0", 1, vec![443])
        };
        let args = merge_args(empty_cli(), Some(file)).unwrap();
        assert_eq!(
            args.routeconfig.as_deref(),
            Some(Path::new("/etc/pesigitg/lb.toml"))
        );

        let args = merge_args(empty_cli(), None).unwrap();
        assert!(args.routeconfig.is_none());
    }

    #[test]
    fn foreground_propagates_from_cli() {
        let args = merge_args(
            CliArgs {
                foreground: true,
                ..empty_cli()
            },
            None,
        )
        .unwrap();
        assert!(args.foreground);
    }
}
