//! Lightweight UDP health probes for backend QUIC servers.
//!
//! Sends a QUIC Version Negotiation trigger packet to each backend and
//! expects any UDP response.  After [`FAILURE_THRESHOLD`] consecutive
//! probe failures a server is marked down by clearing its MAC address,
//! which removes it from both the CID and fallback routing paths.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use rand::RngExt;
use log::{info, warn};

use crate::config::route::ConfigTable;

/// Consecutive probe failures before marking a server as down.
const FAILURE_THRESHOLD: u32 = 3;

/// Per-probe receive timeout.
const PROBE_TIMEOUT: Duration = Duration::from_millis(200);

// ClientHello
const CLIENT_HELLO: &[u8] = &[
    0x16,0x03,0x01,0x00,0xdc,
    0x01,0x00,0x00,0xd8,
    0x03,0x03,

    // Random (32 bytes)
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,

    // Session ID len
    0x00,

    // cipher suites len
    0x00,0x02,
    0x13,0x01, // TLS_AES_128_GCM_SHA256

    // Compression
    0x01,0x00,

    // Extensions len (minimal, not perfect but works for probing)
    0x00,0x14,

    // Supported_versions
    0x00,0x2b,
    0x00,0x03,
    0x02,
    0x03,0x04,

    // SNI (example.com)
    0x00,0x00,
    0x00,0x0e,
    0x00,0x0c,
    0x00,
    0x00,0x09,
    b'e',b'x',b'a',b'm',b'p',b'l',b'e',b'.',b'c',b'o',b'm',
];

struct ServerHealth {
    consecutive_failures: u32,
    healthy: bool,
}

pub struct HealthChecker {
    state: HashMap<IpAddr, ServerHealth>,
    port: u16,
}

fn encode_varint(v: usize, out: &mut Vec<u8>) {
    if v < 64 {
        out.push(v as u8);
    } else if v < 16384 {
        out.push(((v >> 8) as u8) | 0x40);
        out.push(v as u8);
    } else {
        panic!("too large for this probe");
    }
}

fn build_quic_probe(dcid: [u8; 8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1200);

    // Quic header
    // Initial + fixed bit
    buf.push(0xC3); 

    // Version
    buf.extend_from_slice(&[0, 0, 0, 1]);

    buf.push(8);
    buf.extend_from_slice(&dcid);

    buf.push(0);    // SCID len
    buf.push(0x00); // Token len

    // Placeholder for length
    let len_pos = buf.len();
    buf.push(0);

    // Packet number
    buf.push(0x00);

    // Crypto Frame
    buf.push(0x06);

    encode_varint(0, &mut buf); // Offset
    encode_varint(CLIENT_HELLO.len(), &mut buf);

    buf.extend_from_slice(CLIENT_HELLO);

    // Padding
    while buf.len() < 1200 {
        buf.push(0);
    }

    // Fix length after padding
    let payload_len = buf.len() - (len_pos + 1);
    buf[len_pos] = payload_len as u8;

    buf
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

    // Assume build_quic_probe is defined as before:
    // fn build_quic_probe(dcid: [u8; 8]) -> Vec<u8>
    fn probe(&mut self, addr: IpAddr, port: u16) -> bool {
        // Bind to an unspecified address
        let unspec = match addr {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };

        let sock = match UdpSocket::bind(SocketAddr::new(unspec, 0)) {
            Ok(s) => s,
            Err(_) => return false,
        };

        if sock.connect(SocketAddr::new(addr, port)).is_err() {
            return false;
        }

        let _ = sock.set_read_timeout(Some(PROBE_TIMEOUT));

        // Generate a random 8-byte DCID per probe
        let mut rng = rand::rng();
        let mut dcid = [0u8; 8];
        rng.fill(&mut dcid);

        // Build the full QUIC probe packet
        let packet = build_quic_probe(dcid);

        // Send the packet
        if sock.send(&packet).is_err() {
            return false;
        }

        // Receive response (QUIC Initial responses are ≥1200 bytes)
        let mut buf = [0u8; 1500];
        sock.recv(&mut buf).is_ok()
    }
}
