//! Lightweight UDP health probes for backend QUIC servers.
//!
//! Sends a QUIC probe packet to each backend and expects any UDP
//! response. After [`FAILURE_THRESHOLD`] consecutive probe failures a
//! server is marked unhealthy, which removes it from both the CID and
//! fallback routing paths.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use log::{info, warn};

use crate::config::route::ConfigTable;

/// Consecutive probe failures before marking a server as down.
const FAILURE_THRESHOLD: u32 = 3;

/// Per-probe receive timeout.
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

struct ServerHealth {
    consecutive_failures: u32,
    healthy: bool,
}

pub struct HealthChecker {
    state: HashMap<IpAddr, ServerHealth>,
    port: u16,
}

impl HealthChecker {
    pub fn new(port: u16) -> Self {
        HealthChecker {
            state: HashMap::new(),
            port,
        }
    }

    /// Probe all servers and update MACs for any that changed state.
    /// Returns `true` if the caller should rebuild fallback servers.
    pub fn check(&mut self, config: &mut ConfigTable) -> bool {
        // Phase 1: probe each unique address exactly once.
        let mut probes: HashMap<IpAddr, bool> = HashMap::new();

        for rc in config.configs() {
            for server in &rc.servers {
                probes
                    .entry(server.address)
                    .or_insert_with(|| self.probe(server.address, self.port));
            }
        }

        // Phase 2: update per-address health state, log transitions.
        let mut changed = false;

        for (&addr, &ok) in &probes {
            let s = self.state.entry(addr).or_insert(ServerHealth {
                consecutive_failures: 0,
                healthy: true,
            });

            if ok {
                s.consecutive_failures = 0;
                
                if !s.healthy {
                    info!("{} is back up", addr);
 
                    s.healthy = true;
                    changed = true;
                }
            } else {
                s.consecutive_failures += 1;

                if s.healthy && s.consecutive_failures >= FAILURE_THRESHOLD {
                    warn!("{} is down ({} consecutive probe failures)", 
                        addr, FAILURE_THRESHOLD
                    );
 
                    s.healthy = false;
                    changed = true;
                }
            }
        }

        // Phase 3: sync healthy flag on server structs.
        if changed {
            for rc in config.configs_mut() {
                for server in &mut rc.servers {
                    if let Some(s) = self.state.get(&server.address) {
                        server.healthy = s.healthy;
                    }
                }
            }
        }

        changed
    } 

    /// Probe a QUIC endpoint using Quinn
    fn probe(&mut self, addr: IpAddr, port: u16) -> bool {
        // Needs to be implemented. Quinn or s2n-quic, which ever
        // is lighter.

        true
    }
}
