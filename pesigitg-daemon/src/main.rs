// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

mod args;
mod cid;
mod config;
mod conntable;
mod ebpf;
mod fdstore;
mod frame;
mod health;
mod neigh;
mod packet;
mod pidfile;
mod quic;
mod retry;
mod stats;
mod status_api;
mod threading;
mod utils;
mod worker_socket;
mod xdp_adopt;
mod xsk;

use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, ensure};
use log::{debug, error, info, warn};
use pesigitg_common::{DEFAULT_ROUTE_CONFIG, current_pid, exit, pid_file};
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM, SIGUSR1, SIGUSR2};
use signal_hook::iterator::SignalsInfo;
use signal_hook::iterator::exfiltrator::WithOrigin;
use signal_hook::low_level::siginfo::Origin;

use args::parse_args;
use config::route::ConfigTable;
use config::{build_status, log_draining_servers, reload_config};
use health::HealthChecker;
use pidfile::PidFile;
use stats::{Snapshot, StatsTable};
use status_api::StatusApi;
use threading::{WorkerPool, get_hw_queues, plan_threads};
use utils::{
    daemonize, init_logging, is_aes_available, notify_ready, num_cores, running_under_systemd,
    systemd_notify,
};

const LOOP_TIMEOUT: Duration = Duration::from_secs(5);

fn main() -> Result<()> {
    let args = parse_args()?;
    let epoch = Instant::now();

    // To be, or not to be a daemon.
    if !args.foreground && !running_under_systemd() {
        daemonize()?;
    }

    init_logging(args.foreground)?;

    // PID file (unnecessary under systemd) and signal hooks
    let pidfile = if !running_under_systemd() {
        Some(PidFile::create(&pid_file(&args.interface))?)
    } else {
        None
    };

    let mut signals = SignalsInfo::<WithOrigin>::new([SIGINT, SIGTERM, SIGHUP, SIGUSR1, SIGUSR2])?;
    let sig_handle = signals.handle();
    let (sig_tx, sig_rx) = mpsc::sync_channel::<Origin>(10);

    thread::spawn(move || {
        for origin in signals.forever() {
            if sig_tx.send(origin).is_err() {
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
    ensure!(
        is_aes_available(),
        "AES-NI not available - try again please"
    );
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
                warn!(
                    "spawn {0} AF_XDP threads for full queue coverage (--queues {0})",
                    current
                );
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
    debug!("route config parsed: T+{:.2?}", epoch.elapsed());

    // Resolve config server MAC addresses
    for config in route_config.configs_mut() {
        neigh::resolve_macs(&mut config.servers);
    }

    route_config.rebuild_fallback_servers();
    log_draining_servers(&route_config);
    debug!(
        "initial MAC resolution complete: T+{:.2?} ({} fallback server(s))",
        epoch.elapsed(),
        route_config.fallback_servers.len()
    );

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
    debug!("eBPF loaded and attached: T+{:.2?}", epoch.elapsed());

    let ebpf = Arc::new(Mutex::new(ebpf));

    // Read FDs handed in by systemd's per-service FDSTORE. On a cold
    // boot this is empty; on a SIGUSR2 handoff restart it carries one
    // (sockfd, umem_fd) pair per queue from the outgoing daemon, which
    // workers rehydrate via AdoptedSocket::adopt to skip socket+UMEM
    // creation and bind.
    let inherited = fdstore::inherit_from_systemd()?;
    if !inherited.is_empty() {
        info!(
            "FDSTORE handoff: rehydrating {} AF_XDP queue(s) from previous instance",
            inherited.len()
        );
    }

    // Plan and spawn AF_XDP worker threads, one per NIC queue.
    // Workers create their own AF_XDP sockets and register them with
    // the eBPF XSKS map.
    let thread_plan = plan_threads(&args.interface, Some(args.queues))?;

    for t in &thread_plan {
        info!("thread planned: queue={} -> core={}", t.queue_id, t.core_id);
    }
    debug!("thread plan ready: T+{:.2?}", epoch.elapsed());

    // Resolve and log interface MAC
    let local_mac = utils::interface_mac(&args.interface)
        .map_err(|e| anyhow!("failed to get MAC for {}: {}", args.interface, e))?;
    info!(
        "interface MAC: {}",
        pesigitg_common::mac::format(&local_mac)
    );

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
        inherited,
    );
    debug!("worker pool spawned: T+{:.2?}", epoch.elapsed());

    // Notify systemd that we're ready with a live status string.
    notify_ready(&build_status(
        &args,
        &route_config.read().expect("lock poisoned"),
    ));

    // Backends are probed on the first configured port only; see the
    // HEALTH CHECKING section of pesigitgd(8) for the rationale.
    let mut health = HealthChecker::new(args.ports[0])?;
    debug!("health checker ready: T+{:.2?}", epoch.elapsed());

    // Wrap Args for shared read access from the status API and locked
    // mutation from the SIGHUP reload path. Init is complete at this
    // point, so nothing below indexes into `args` directly.
    let args = Arc::new(RwLock::new(args));

    // Optional JSON status API on a Unix-domain socket. Enabled when
    // `status_socket = /path` is set in the daemon config (or via
    // --status-socket). Bind failure is fatal.
    let worker_health = workers.health();
    let mut status_api = {
        let path = args.read().expect("lock poisoned").status_socket.clone();
        path.map(|p| {
            StatusApi::spawn(
                p,
                Arc::clone(&args),
                Arc::clone(&route_config),
                Arc::clone(&stats),
                Arc::clone(&worker_health),
                epoch,
            )
        })
        .transpose()?
    };

    // Poll for signals with a timeout to allow watchdog keepalives
    let mut prev_stats = Snapshot::default();
    let mut draining_had_traffic = false;

    debug!("entering main loop: T+{:.2?}", epoch.elapsed());

    loop {
        // Wait up to 5 seconds for a signal, then run periodic tasks
        let mut got_signal = match sig_rx.recv_timeout(LOOP_TIMEOUT) {
            Ok(origin) => Some(origin),
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };

        // Process all pending signals
        loop {
            if let Some(origin) = got_signal.take() {
                let sig = origin.signal;
                let from = format_sender(&origin);
                debug!("signal received: {}{}", sig, from);

                match sig {
                    SIGHUP => {
                        info!("received SIGHUP{}, reloading config", from);
                        reload_config(&args, &route_config);
                        health.reset_backoff();
                    }
                    SIGUSR1 => {
                        info!("received SIGUSR1{}, dumping stats", from);
                        info!("stats dump: {}", stats.aggregate());
                    }
                    SIGUSR2 => {
                        // Handoff shutdown: leave XDP program and map pins in
                        // place so the next daemon invocation adopts them
                        // (phase 1), and hand AF_XDP socket + UMEM FDs to
                        // systemd's FDSTORE so the next invocation can
                        // rehydrate the live sockets without a kernel-side
                        // close + rebind window (phase 2).
                        systemd_notify!(sd_notify::NotifyState::Stopping);

                        info!("received SIGUSR2{}, beginning handoff shutdown", from);

                        ebpf.lock().expect("lock poisoned").set_handoff();

                        sig_handle.close();
                        if let Some(api) = status_api.as_mut() {
                            api.shutdown();
                        }
                        let detached = workers.shutdown_for_handoff();

                        info!(
                            "all workers stopped; {} AF_XDP queue(s) detached for FDSTORE",
                            detached.len()
                        );

                        match fdstore::export_to_systemd(detached) {
                            Ok(0) => {
                                info!("FDSTORE export skipped (not running under systemd)");
                            }
                            Ok(n) => {
                                info!("FDSTORE export complete: {} queue(s) handed to systemd", n);
                            }
                            Err(e) => {
                                error!("FDSTORE export failed: {:#}", e);
                            }
                        }

                        info!("handoff complete; pins preserved for next invocation");

                        return Ok(());
                    }
                    SIGINT | SIGTERM => {
                        systemd_notify!(sd_notify::NotifyState::Stopping);

                        info!("received signal {}{}, shutting down", sig, from);

                        sig_handle.close();
                        if let Some(api) = status_api.as_mut() {
                            api.shutdown();
                        }
                        workers.shutdown();

                        info!("all workers stopped");

                        return Ok(());
                    }
                    _ => unreachable!(),
                }
            }

            // Drain any additional queued signals
            match sig_rx.try_recv() {
                Ok(origin) => got_signal = Some(origin),
                Err(_) => break,
            }
        }

        // Statistics
        let current = stats.aggregate();
        let delta = current.delta(&prev_stats);

        if delta.rx_packets > 0 {
            info!("stats: {}", delta);
        } else {
            debug!("idle loop: no RX in last {:?}", LOOP_TIMEOUT);
        }

        // Detect drain completion: once traffic was flowing to draining
        // servers and then drops to zero, log that draining is complete.
        if delta.draining_forwarded > 0 {
            draining_had_traffic = true;
        } else if draining_had_traffic {
            let rc = route_config.read().expect("lock poisoned");

            if rc.has_draining_servers() {
                info!("all draining servers fully drained — safe to remove from config");

                draining_had_traffic = false;
            }
        }

        prev_stats = current;

        // Retry MAC resolution and run health probes. When any backend
        // state changes, refresh the systemd STATUS= string so
        // `systemctl status` reflects current health counts.
        if check_and_rebuild(&route_config, &mut health) {
            let a = args.read().expect("lock poisoned");
            let rc = route_config.read().expect("lock poisoned");
            let status = build_status(&a, &rc);
            systemd_notify!(sd_notify::NotifyState::Status(&status));
        }

        // Detect unexpected worker thread exits. If any AF_XDP worker
        // has terminated without the shutdown flag being set, the
        // daemon can no longer service its assigned NIC queue — escalate
        // to a full shutdown so systemd sees the failure instead of a
        // silent watchdog heartbeat.
        workers.refresh_health();
        let dead = workers.dead_queues();
        if !dead.is_empty() {
            error!("worker thread(s) exited unexpectedly: queues={:?}", dead);

            systemd_notify!(
                sd_notify::NotifyState::Stopping,
                sd_notify::NotifyState::Status("worker thread exited unexpectedly"),
            );

            sig_handle.close();
            if let Some(api) = status_api.as_mut() {
                api.shutdown();
            }
            workers.shutdown();

            return Err(anyhow!("worker thread(s) exited unexpectedly: {:?}", dead));
        }

        systemd_notify!(sd_notify::NotifyState::Watchdog);
    }

    Ok(())
}

/// Returns `true` if any backend state changed (MAC resolved, health
/// flipped, etc.), i.e. the caller should refresh systemd's STATUS=.
fn check_and_rebuild(route_config: &RwLock<ConfigTable>, health: &mut HealthChecker) -> bool {
    let mut rc = route_config.write().expect("lock poisoned");
    let mut rebuild = false;

    if rc.has_unresolved_macs() {
        debug!("Trying to resolve {} neighbors", rc.unresolved_macs_count());

        for config in rc.configs_mut() {
            neigh::resolve_macs(&mut config.servers);
        }

        rebuild = true;
    }

    debug!("sending health checks");

    if health.check(&mut rc) {
        rebuild = true;
    }

    if rebuild {
        info!("rebuild fallback servers");

        rc.rebuild_fallback_servers();
    }

    rebuild
}

/// Render the sender-identity suffix for a signal-delivery log line.
/// With the `extended-siginfo` feature enabled, signal-hook exposes the
/// sender's pid and uid via `Origin`; formatted as ` from pid N uid M`.
/// Falls back to empty when the kernel didn't attach siginfo (rare —
/// only kernel-generated signals like SIGSEGV typically lack a sender).
fn format_sender(origin: &Origin) -> String {
    match &origin.process {
        Some(p) => format!(" from pid {} uid {}", p.pid, p.uid),
        None => String::new(),
    }
}
