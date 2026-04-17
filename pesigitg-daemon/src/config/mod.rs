// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

pub mod daemon;
pub mod retry;
pub mod route;

use std::sync::{Arc, RwLock};
use std::time::Instant;

use log::{debug, error, info, warn};
use pesigitg_common::DEFAULT_ROUTE_CONFIG;
use sd_notify::NotifyState;

use crate::args::Args;
use crate::neigh;
use crate::utils::{notify_ready, systemd_notify};

use daemon::FileConfig;
use route::ConfigTable;

pub(crate) fn reload_config(args: &Arc<RwLock<Args>>, route_config: &Arc<RwLock<ConfigTable>>) {
    debug!("reload_config: starting");
    let reload_start = Instant::now();

    // Pair RELOADING=1 with MONOTONIC_USEC so systemd can track reload duration.
    match NotifyState::monotonic_usec_now() {
        Ok(ts) => {
            systemd_notify!(NotifyState::Reloading, ts);
        }
        Err(_) => {
            systemd_notify!(NotifyState::Reloading);
        }
    }

    let config_path = args.read().expect("lock poisoned").config.clone();
    if let Some(ref path) = config_path {
        match FileConfig::from_file(path) {
            Ok(fc) => {
                let mut a = args.write().expect("lock poisoned");
                a.ports = fc.ports;
                a.interface = fc.interface;
                a.queues = fc.queues;

                info!(
                    "config reloaded: interface='{}', ports={:?}, queues={}",
                    a.interface, a.ports, a.queues
                );
            }
            Err(e) => {
                error!("failed to reload config: {}; keeping current settings", e);
            }
        }
    }

    let rc_path = args.read().expect("lock poisoned").routeconfig.clone();
    let new_rc = match rc_path {
        Some(ref path) => ConfigTable::from_file(path),
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

            log_draining_servers(&rc);

            *route_config.write().expect("lock poisoned") = rc;
        }
        Err(e) => {
            error!(
                "failed to reload route config: {}; keeping current settings",
                e
            );
        }
    }

    notify_ready(&build_status(
        &args.read().expect("lock poisoned"),
        &route_config.read().expect("lock poisoned"),
    ));

    debug!("reload_config: complete in {:.2?}", reload_start.elapsed());
}

/// Build a single-line status string for systemd `STATUS=`.
///
/// Surfaces the listening interface/ports/queues plus live backend
/// health so `systemctl status pesigitgd` reflects runtime state.
pub(crate) fn build_status(args: &Args, rc: &ConfigTable) -> String {
    let mut total = 0usize;
    let mut healthy = 0usize;
    let mut draining = 0usize;

    for config in rc.configs() {
        for s in &config.servers {
            total += 1;
            if s.healthy {
                healthy += 1;
            }
            if s.draining {
                draining += 1;
            }
        }
    }

    let mut out = format!(
        "{} {:?} q={}; backends {}/{} healthy",
        args.interface, args.ports, args.queues, healthy, total,
    );
    if draining > 0 {
        out.push_str(&format!(", {draining} draining"));
    }
    out
}

/// Log a warning for each server marked as draining.
pub(crate) fn log_draining_servers(table: &ConfigTable) {
    for config in table.configs() {
        for server in &config.servers {
            if server.draining {
                warn!(
                    "server {} is draining (config_id={})",
                    server, config.config_id
                );
            }
        }
    }
}
