mod pidfile;

use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use log::{error, info};
use nix::unistd::{chdir, close, dup2, fork, setsid, ForkResult};
use sd_notify::NotifyState;
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use anyhow::{anyhow, bail, Result};

use pesigitg_common::{
    DEFAULT_INTF,
    DEFAULT_PORT,
    PID_FILE,
    PROC_NAME,
};

use pidfile::PidFile;

struct Args {
    ports: Vec<u16>,
    interface: String,
    queues: u16,
    config: Option<PathBuf>,
    foreground: bool,
}

struct FileConfig {
    ports: Vec<u16>,
    interface: String,
    queues: u16,
}

fn parse_config(path: &PathBuf) -> Result<FileConfig> {
    let content = std::fs::read_to_string(path)?;
    let mut ports = Vec::new();
    let mut interface = DEFAULT_INTF.to_string();
    let mut queues: u16 = 1;

    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') { continue; }

        if let Some((k, v)) = line.split_once('=') {
            match k.trim() {
                "port" => ports.push(v.trim().parse::<u16>()?),
                "interface" => interface = v.trim().to_string(),
                "queues" => queues = v.trim().parse::<u16>()?,
                _ => {}
            }
        }
    }

    Ok(FileConfig { ports, interface, queues })
}

fn parse_args() -> Result<Args> {
    let mut pargs = pico_args::Arguments::from_env();

    // --version / -V
    if pargs.contains(["-V", "--version"]) {
        println!("{} {} ({})", PROC_NAME, env!("CARGO_PKG_VERSION"), env!("BUILD_DATE"));
        println!("{}", env!("RUSTC_VERSION"));
        println!("platform: {}", env!("TARGET"));

        std::process::exit(0);
    }

    // --help / -h
    if pargs.contains(["-h", "--help"]) {
        println!(
            "{0} {1}\n\n\
            A QUIC-aware load balancer\n\n\
            Usage: {0} [OPTIONS]\n\n\
            Options:\n  \
            -p, --port <PORT>         Port to listen on (repeatable)\n  \
            -i, --interface <NAME>    Network interface [default: {DEFAULT_INTF}]\n  \
            -c, --config <PATH>       Config file path\n  \
            -q, --queues <NUM>        Number of NIC queues [default: 1]\n  \
            -f, --foreground          Run in foreground (don't daemonize)\n  \
            -V, --version             Print version\
        ", PROC_NAME, env!("CARGO_PKG_VERSION"));

        std::process::exit(0);
    }

    let foreground = pargs.contains(["-f", "--foreground"]);
    let config: Option<PathBuf> = pargs.opt_value_from_str(["-c", "--config"])?;
    let interface: Option<String> = pargs.opt_value_from_str(["-i", "--interface"])?;
    let queues: Option<u16> = pargs.opt_value_from_str(["-q", "--queues"])?;

    // Collect all -p / --port values
    let mut ports = Vec::new();
    while let Some(port) = pargs.opt_value_from_str::<_, u16>(["-p", "--port"])? {
        ports.push(port);
    }

    // Check for unexpected arguments
    let remaining = pargs.finish();
    if !remaining.is_empty() {
        bail!("Unknown arguments: {:?}", remaining);
    }

    // If config file provided, use it as base
    let file_config = config.as_ref().map(|path| {
        parse_config(path)
    }).transpose()?;

    // CLI -> config file -> defaults
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
        queues: queues
            .or(file_config.as_ref().map(|fc| fc.queues))
            .unwrap_or(1),
        config,
        foreground,
    })
}

fn daemonize() -> Result<()> {
    // First fork: parent exits, child continues
    match unsafe { fork() }? {
        ForkResult::Parent { .. } => std::process::exit(0),
        ForkResult::Child => {}
    }

    // Create a new session, detach from controlling terminal
    setsid()?;

    // Second fork: session leader exits, grandchild can never acquire a terminal
    match unsafe { fork() }? {
        ForkResult::Parent { .. } => std::process::exit(0),
        ForkResult::Child => {}
    }

    chdir("/")?;

    // Redirect stdin/stdout/stderr to /dev/null
    let devnull = nix::fcntl::open(
        "/dev/null",
        nix::fcntl::OFlag::O_RDWR,
        nix::sys::stat::Mode::empty(),
    )?;
    
    dup2(devnull, 0)?;
    dup2(devnull, 1)?;
    dup2(devnull, 2)?;
    
    if devnull > 2 {
        close(devnull)?;
    }

    Ok(())
}

fn init_logging() -> Result<()> {
    let formatter = syslog::Formatter3164 {
        facility: syslog::Facility::LOG_DAEMON,
        hostname: None,
        process: PROC_NAME.into(),
        pid: std::process::id(),
    };

    let logger = syslog::unix(formatter)
        .map_err(|e| anyhow!("failed to connect to syslog: {}", e))?;

    log::set_boxed_logger(Box::new(syslog::BasicLogger::new(logger)))
        .map_err(|e| anyhow!(e))?;
    log::set_max_level(log::LevelFilter::Info);

    Ok(())
}

fn reload_config(args: &mut Args) {
    let Some(ref path) = args.config else {
        info!("SIGHUP received but no config file specified; ignoring");

        return;
    };

    let _ = sd_notify::notify(false, &[NotifyState::Reloading]);

    match parse_config(path) {
        Ok(fc) => {
            args.ports = fc.ports;
            args.interface = fc.interface;
            args.queues = fc.queues;

            info!(
                "config reloaded: interface='{}', ports={:?}, queues={}",
                args.interface, args.ports, args.queues
            );
        }
        Err(e) => {
            error!("failed to reload config: {}; keeping current settings", e);
        }
    }

    let _ = sd_notify::notify(false, &[
        NotifyState::Ready,
        NotifyState::Status(&format!(
            "listening on {} ports {:?}", args.interface, args.ports
        )),
    ]);
}

fn num_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn running_under_systemd() -> bool {
    std::env::var_os("INVOCATION_ID").is_some()
}

fn main() -> Result<()> {
    let mut args = parse_args()?;

    // To be, or not to be a daemon.
    if !args.foreground && !running_under_systemd() {
        daemonize()?;
    }

    // Setup logging: stderr in foreground mode (journald captures it), syslog otherwise
    if args.foreground {
        env_logger::init();
    } else {
        init_logging()?;
    }

    // PID file (unnecessary under systemd) and signal hooks
    let pidfile = if !running_under_systemd() {
        Some(PidFile::create(PID_FILE.as_ref())?)
    } else {
        None
    };

    let mut signals = Signals::new([SIGINT, SIGTERM, SIGHUP])?;

    info!("PID: {}", std::process::id());
    if let Some(ref pidfile) = pidfile {
        info!("PID file: {}", pidfile.path().display());
    }
    
    info!("number of cores: {}", num_cores());
    info!(
        "starting on interface '{}', ports: {:?}, queues: {}",
        args.interface, args.ports, args.queues
    );

    // Notify systemd that we're ready with a status string
    let _ = sd_notify::notify(false, &[
        NotifyState::Ready,
        NotifyState::Status(&format!(
            "listening on {} ports {:?}, queues: {}", 
            args.interface, args.ports, args.queues
        )),
    ]);

    // Poll for signals with a timeout to allow watchdog keepalives
    loop {
        for sig in signals.pending() {
            match sig {
                SIGHUP => reload_config(&mut args),
                SIGINT | SIGTERM => {
                    let _ = sd_notify::notify(false, &[NotifyState::Stopping]);
                    info!("received signal {}, shutting down", sig);

                    return Ok(());
                }
                _ => unreachable!(),
            }
        }

        let _ = sd_notify::notify(false, &[NotifyState::Watchdog]);
        thread::sleep(Duration::from_secs(5));
    }
}
