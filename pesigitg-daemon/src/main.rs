mod args;
mod cid;
mod config;
mod conntable;
mod ebpf;
mod neigh;
mod packet;
mod pidfile;
mod stats;
mod threading;
mod utils;
mod xsk;

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use log::{error, warn, info};
use nix::unistd::{chdir, dup2_stdin, dup2_stdout, dup2_stderr, fork, setsid, ForkResult};
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM, SIGUSR1};
use signal_hook::iterator::Signals;
use anyhow::{anyhow, bail, Result};
use pesigitg_common::{PID_FILE, PROC_NAME, DEFAULT_ROUTE_CONFIG, current_pid, exit};

use args::{Args, parse_args};
use config::daemon::FileConfig;
use config::route::ConfigTable;
use pidfile::PidFile;
use stats::{Snapshot, StatsTable};
use threading::{get_hw_queues, plan_threads, WorkerPool};
use utils::{is_aes_available, notify_ready, num_cores, running_under_systemd, systemd_notify};

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

fn reload_config(args: &mut Args, route_config: &Arc<RwLock<ConfigTable>>) {
    systemd_notify!(sd_notify::NotifyState::Reloading);

    if let Some(ref path) = args.config.clone() {
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
    }

    let rc_path = args.routeconfig.as_ref();
    let new_rc = match rc_path {
        Some(path) => ConfigTable::from_file(path),
        None => ConfigTable::from_file(DEFAULT_ROUTE_CONFIG),
    };

    match new_rc {
        Ok(mut rc) => {
            for config in rc.configs_mut() {
                neigh::resolve_macs(&mut config.servers);
            }
            rc.rebuild_fallback_servers();

            info!("route config reloaded: {}", rc.path.display());
            info!("{}", rc);

            *route_config.write().unwrap() = rc;
        }
        Err(e) => {
            error!("failed to reload route config: {}; keeping current settings", e);
        }
    }

    notify_ready(&format!(
        "listening on {} ports {:?}", args.interface, args.ports
    ));
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

    let mut signals = Signals::new([SIGINT, SIGTERM, SIGHUP, SIGUSR1])?;

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

    // Route config
    let mut route_config = match &args.routeconfig {
        Some(path) => ConfigTable::from_file(path),
        None => ConfigTable::from_file(DEFAULT_ROUTE_CONFIG),
    }
    .map_err(|e| anyhow!("failed to load route config: {}", e))?;

    info!("loaded route config: {}", route_config.path.display());
    info!("{}", route_config);

    for config in route_config.configs_mut() {
        neigh::resolve_macs(&mut config.servers);
    }
    route_config.rebuild_fallback_servers();

    let route_config = Arc::new(RwLock::new(route_config));

    // Load XDP program and populate PORTS map.
    let ebpf = ebpf::load_ebpf(
        #[cfg(debug_assertions)]
        args.ebpf_obj.as_deref(),
        #[cfg(not(debug_assertions))]
        None,
        &args.interface,
        &args.ports,
    )?;

    let ebpf = Arc::new(Mutex::new(ebpf));

    // Plan and spawn AF_XDP worker threads, one per NIC queue.
    // Workers create their own AF_XDP sockets and register them with
    // the eBPF XSKS map.
    let thread_plan = plan_threads(&args.interface, Some(args.queues));

    for t in &thread_plan {
        info!("thread planned: queue={} -> core={}", t.queue_id, t.core_id);
    }

    let local_mac = utils::interface_mac(&args.interface)
        .map_err(|e| anyhow!("failed to get MAC for {}: {}", args.interface, e))?;
    let mac_str = local_mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
    info!("interface MAC: {}", mac_str);

    let shutdown = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(StatsTable::new(thread_plan.len()));
    let mut workers = WorkerPool::spawn(
        thread_plan,
        &args.interface,
        local_mac,
        Arc::clone(&route_config),
        Arc::clone(&ebpf),
        Arc::clone(&shutdown),
        Arc::clone(&stats),
    );

    // Notify systemd that we're ready with a status string
    notify_ready(&format!(
        "listening on {} ports {:?}, queues: {}",
        args.interface, args.ports, args.queues
    ));

    // Poll for signals with a timeout to allow watchdog keepalives
    let mut prev_stats = Snapshot::default();

    loop {
        for sig in signals.pending() {
            match sig {
                SIGHUP => reload_config(&mut args, &route_config),
                SIGUSR1 => {
                    info!("stats dump: {}", stats.aggregate());
                }
                SIGINT | SIGTERM => {
                    systemd_notify!(sd_notify::NotifyState::Stopping);

                    info!("received signal {}, shutting down", sig);

                    workers.shutdown();

                    info!("all workers stopped");

                    return Ok(());
                }
                _ => unreachable!(),
            }
        }

        // Statistics
        let current = stats.aggregate();
        let delta = current.delta(&prev_stats);
        
        if delta.rx_packets > 0 {
            info!("stats: {}", delta);
        }
        
        prev_stats = current;

        // Retry MAC resolution for servers whose ARP entries weren't
        // cached at startup (e.g. first boot, backend not yet pinged).
        if route_config.read().unwrap().has_unresolved_macs() {
            let mut rc = route_config.write().unwrap();
            for config in rc.configs_mut() {
                neigh::resolve_macs(&mut config.servers);
            }
            rc.rebuild_fallback_servers();
        }

        systemd_notify!(sd_notify::NotifyState::Watchdog);
        thread::sleep(Duration::from_secs(5));
    }
}
