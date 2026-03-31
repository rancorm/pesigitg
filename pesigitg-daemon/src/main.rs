mod args;
mod cid;
mod config;
mod conntable;
mod ebpf;
mod health;
mod neigh;
mod packet;
mod pidfile;
mod stats;
mod threading;
mod utils;
mod xsk;

use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use log::{error, warn, info};
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM, SIGUSR1};
use signal_hook::iterator::Signals;
use anyhow::{anyhow, ensure, Result};
use pesigitg_common::{PID_FILE, DEFAULT_ROUTE_CONFIG, current_pid, exit};

use args::parse_args;
use config::{log_draining_servers, reload_config};
use health::HealthChecker;
use config::route::ConfigTable;
use pidfile::PidFile;
use stats::{Snapshot, StatsTable};
use threading::{get_hw_queues, plan_threads, WorkerPool};
use utils::{
    daemonize,
    init_logging,
    is_aes_available,
    notify_ready,
    num_cores,
    running_under_systemd,
    systemd_notify
};

fn main() -> Result<()> {
    let mut args = parse_args()?;

    // To be, or not to be a daemon.
    if !args.foreground && !running_under_systemd() {
        daemonize()?;
    }

    // Setup logging: stderr in foreground mode (journald captures it), syslog otherwise
    match args.foreground {
        true => { env_logger::init(); }
        false => { init_logging()?; }
    }

    // PID file (unnecessary under systemd) and signal hooks
    let pidfile = if !running_under_systemd() {
        Some(PidFile::create(PID_FILE.as_ref())?)
    } else {
        None
    };

    let mut signals = Signals::new([SIGINT, SIGTERM, SIGHUP, SIGUSR1])?;
    let sig_handle = signals.handle();
    let (sig_tx, sig_rx) = mpsc::sync_channel(10);

    thread::spawn(move || {
        for sig in signals.forever() {
            if sig_tx.send(sig).is_err() {
                break;
            }
        }
    });

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
    ensure!(is_aes_available(), "AES-NI not available - try again please");
    info!("AES-NI available");

    info!("number of cores: {}", num_cores());
    info!(
        "starting on interface '{}', ports: {:?}, queues: {}",
        args.interface, args.ports, args.queues
    );

    // Handle NIC hardware queues
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

    // Resolve config server MAC addresses
    for config in route_config.configs_mut() {
        neigh::resolve_macs(&mut config.servers);
    }

    route_config.rebuild_fallback_servers();
    log_draining_servers(&route_config);

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

    // Resolve and log interface MAC
    let local_mac = utils::interface_mac(&args.interface)
        .map_err(|e| anyhow!("failed to get MAC for {}: {}", args.interface, e))?;
    info!("interface MAC: {}", utils::format_mac(&local_mac));

    // Thread safe
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

    // Health checker probes backends on the first configured port.
    let mut health = HealthChecker::new(args.ports[0]);

    // Poll for signals with a timeout to allow watchdog keepalives
    let mut prev_stats = Snapshot::default();
    let mut draining_had_traffic = false;

    loop {
        // Wait up to 5 seconds for a signal, then run periodic tasks
        let mut got_signal = match sig_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(sig) => Some(sig),
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };

        // Process all pending signals
        loop {
            if let Some(sig) = got_signal.take() {
                match sig {
                    SIGHUP => reload_config(&mut args, &route_config),
                    SIGUSR1 => {
                        info!("stats dump: {}", stats.aggregate());
                    }
                    SIGINT | SIGTERM => {
                        systemd_notify!(sd_notify::NotifyState::Stopping);

                        info!("received signal {}, shutting down", sig);

                        sig_handle.close();
                        workers.shutdown();

                        info!("all workers stopped");

                        return Ok(());
                    }
                    _ => unreachable!(),
                }
            }

            // Drain any additional queued signals
            match sig_rx.try_recv() {
                Ok(sig) => got_signal = Some(sig),
                Err(_) => break,
            }
        }

        // Statistics
        let current = stats.aggregate();
        let delta = current.delta(&prev_stats);

        if delta.rx_packets > 0 {
            info!("stats: {}", delta);
        }

        // Detect drain completion: once traffic was flowing to draining
        // servers and then drops to zero, log that draining is complete.
        if delta.draining_forwarded > 0 {
            draining_had_traffic = true;
        } else if draining_had_traffic {
            let rc = route_config.read().unwrap();

            if rc.has_draining_servers() {
                info!("all draining servers fully drained — safe to remove from config");

                draining_had_traffic = false;
            }
        }

        prev_stats = current;

        // Retry MAC resolution and run health probes.
        check_and_rebuild(&route_config, &mut health);

        systemd_notify!(sd_notify::NotifyState::Watchdog);
    }

    Ok(())
}

fn check_and_rebuild(route_config: &RwLock<ConfigTable>, health: &mut HealthChecker) {
    let mut rc = route_config.write().unwrap();
    let mut rebuild = false;

    if rc.has_unresolved_macs() {
        for config in rc.configs_mut() {
            neigh::resolve_macs(&mut config.servers);
        }

        rebuild = true;
    }

    if health.check(&mut rc) {
        rebuild = true;
    }

    if rebuild {
        rc.rebuild_fallback_servers();
    }
}
