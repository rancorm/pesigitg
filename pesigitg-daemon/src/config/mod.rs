pub mod daemon;
pub mod route;

use std::sync::{Arc, RwLock};

use log::{error, info};
use pesigitg_common::DEFAULT_ROUTE_CONFIG;

use crate::args::Args;
use crate::neigh;
use crate::utils::{notify_ready, systemd_notify};

use daemon::FileConfig;
use route::ConfigTable;

pub(crate) fn reload_config(args: &mut Args, route_config: &Arc<RwLock<ConfigTable>>) {
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
