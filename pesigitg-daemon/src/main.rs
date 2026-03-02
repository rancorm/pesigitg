mod args;
mod config;
mod pidfile;
mod threading;
mod utils;

use std::thread;
use std::time::Duration;

use log::{error, warn, info};
use nix::unistd::{chdir, dup2_stdin, dup2_stdout, dup2_stderr, fork, setsid, ForkResult};
use sd_notify::NotifyState;
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use anyhow::{anyhow, bail, Result};
use pesigitg_common::{PID_FILE, PROC_NAME, DEFAULT_ROUTE_CONFIG, current_pid, exit};

use args::{Args, parse_args};
use config::daemon::FileConfig;
use config::route::RouteConfig;
use pidfile::PidFile;
use threading::{get_hw_queues, plan_threads};
use utils::{is_aes_available, num_cores, running_under_systemd};

fn daemonize() -> Result<()> {
    // First fork: parent exits, child continues
    match unsafe { fork() }? {
        ForkResult::Parent { .. } => exit!(),
        ForkResult::Child => {}
    }

    // Create a new session, detach from controlling terminal
    setsid()?;

    // Second fork: session leader exits, grandchild can never acquire a terminal
    match unsafe { fork() }? {
        ForkResult::Parent { .. } => exit!(),
        ForkResult::Child => {}
    }

    chdir("/")?;

    // Redirect stdin/stdout/stderr to /dev/null
    let devnull = nix::fcntl::open(
        "/dev/null",
        nix::fcntl::OFlag::O_RDWR,
        nix::sys::stat::Mode::empty(),
    )?;
 
    dup2_stdin(&devnull)?;
    dup2_stdout(&devnull)?;
    dup2_stderr(&devnull)?;

    Ok(())
}

fn init_logging() -> Result<()> {
    let formatter = syslog::Formatter3164 {
        facility: syslog::Facility::LOG_DAEMON,
        hostname: None,
        process: PROC_NAME.into(),
        pid: current_pid(),
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

    match FileConfig::from_file(path) {
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

    // Output details
    info!("PID: {}", current_pid());

    if let Some(ref pidfile) = pidfile {
        info!("PID file: {}", pidfile);
    }

    // AES-NI instruction set availability. AES-NI was introduced with
    // Westmere in 2010, so anything from the last ~15 years has it.
    // 
    // Few notable exceptions:
    //  - Early Atom Celeron/Pentium processors
    //  - Some Xeon Phi models
    //  - BIOS/firmware disabling (rare)
    if is_aes_available() {
        info!("AES-NI available");
    } else {
        error!("AES-NI not available - try again please");
        bail!("AES-NI not available - try again please");
    }

    info!("number of cores: {}", num_cores());
    info!(
        "starting on interface '{}', ports: {:?}, queues: {}",
        args.interface, args.ports, args.queues
    );

    match get_hw_queues(&args.interface) {
        Ok((current, max)) => {
            info!("current combined queues: {}", current);
            info!("max. combined queues: {}", max);

            // Warn about thread queue coverage
            if args.queues < current {
                warn!("spawn {0} AF_XDP threads for full queue coverage (--queues {0})", current);
            }
        }
        Err(e) => {
            error!("failed to query {}: {}", args.interface, e);
            error!("(requires root or CAP_NET_ADMIN)");
            
            exit!(1);
        }
    }

    // Threads
    let threads = plan_threads(&args.interface, Some(args.queues));
    
    for t in &threads {
        info!("thread: queue={}, core={}", t.queue_id, t.core_id);
    }

    // Route config
    let route_config = match &args.routeconfig {
        Some(path) => RouteConfig::from_file(path),
        None => RouteConfig::from_file(DEFAULT_ROUTE_CONFIG),
    }
    .map_err(|e| anyhow!("failed to load route config: {}", e))?;

    info!("Loaded route config: {}", route_config.path.display());
    info!("{}", route_config);

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
