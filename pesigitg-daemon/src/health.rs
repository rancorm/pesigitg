//! Lightweight UDP health probes for backend QUIC servers.
//!
//! Sends a QUIC Version Negotiation trigger packet to each backend and
//! expects any UDP response.  After [`FAILURE_THRESHOLD`] consecutive
//! probe failures a server is marked down by clearing its MAC address,
//! which removes it from both the CID and fallback routing paths.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use log::{info, warn};

use crate::config::route::ConfigTable;

/// Consecutive probe failures before marking a server as down.
const FAILURE_THRESHOLD: u32 = 3;

/// Per-probe receive timeout.
const PROBE_TIMEOUT: Duration = Duration::from_millis(200);

/// QUIC long header with version 0 — any compliant QUIC server responds
/// with a Version Negotiation packet, proving the process is alive.
const PROBE_PACKET: [u8; 15] = [
    0xC0,                                               // long header form
    0x00, 0x00, 0x00, 0x00,                             // version = 0
    0x08,                                               // DCID length = 8
    0x70, 0x65, 0x73, 0x69, 0x67, 0x69, 0x74, 0x67,    // DCID = "pesigitg"
    0x00,                                               // SCID length = 0
];

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
                    .or_insert_with(|| self.probe(server.address));
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
                    info!("health: {} is back up", addr);
                    s.healthy = true;
                    changed = true;
                }
            } else {
                s.consecutive_failures += 1;
                if s.healthy && s.consecutive_failures >= FAILURE_THRESHOLD {
                    warn!(
                        "health: {} is down ({} consecutive probe failures)",
                        addr, FAILURE_THRESHOLD
                    );
                    s.healthy = false;
                    changed = true;
                }
            }
        }

        // Phase 3: clear MACs for unhealthy servers.
        if changed {
            for rc in config.configs_mut() {
                for server in &mut rc.servers {
                    if let Some(s) = self.state.get(&server.address) {
                        if !s.healthy && server.mac.is_some() {
                            server.mac = None;
                        }
                    }
                }
            }
        }

        changed
    }

    /// Send a QUIC version probe and wait for any UDP response.
    fn probe(&self, addr: IpAddr) -> bool {
        let unspec = match addr {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };

        let Ok(sock) = UdpSocket::bind(SocketAddr::new(unspec, 0)) else {
            return false;
        };
        if sock.connect(SocketAddr::new(addr, self.port)).is_err() {
            return false;
        }
        let _ = sock.set_read_timeout(Some(PROBE_TIMEOUT));
        if sock.send(&PROBE_PACKET).is_err() {
            return false;
        }

        let mut buf = [0u8; 64];
        sock.recv(&mut buf).is_ok()
    }
}
