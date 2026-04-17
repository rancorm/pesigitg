// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! QUIC health probes for backend servers.
//!
//! Performs a QUIC handshake (via quinn) to each backend and considers
//! it healthy if the connection succeeds. After [`FAILURE_THRESHOLD`]
//! consecutive probe failures a server is marked unhealthy, which
//! removes it from both the CID and fallback routing paths.
//!
//! Each backend is probed on its own schedule. Healthy servers are
//! probed every [`PROBE_INTERVAL`]; once a server transitions to
//! unhealthy, subsequent probes back off according to
//! [`BACKOFF_SCHEDULE`] so long-dead backends stop burning handshakes
//! while still allowing automatic recovery.
//!
//! All due backends are probed concurrently using a single-threaded
//! tokio runtime, keeping total probe time close to one timeout period.
//!
//! Only the first configured listening port is used for probes. In the
//! typical deployment each backend runs a single QUIC server instance
//! whose reachability is the same on every port the LB advertises, so
//! probing one port is sufficient and avoids multiplying probe load.
//! Backends that expose different health on different ports are not
//! supported.

use core::fmt;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use quinn::Endpoint;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::runtime::Runtime;

use crate::config::route::ConfigTable;

/// Consecutive probe failures before marking a server as down.
const FAILURE_THRESHOLD: u32 = 3;

/// Per-probe timeout (connect + TLS handshake).
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Probe cadence while a server is healthy (or still within the
/// failure threshold window).
const PROBE_INTERVAL: Duration = Duration::from_secs(5);

/// Backoff applied to probes after a server is marked unhealthy. The
/// Nth entry is used after N failures past [`FAILURE_THRESHOLD`]; once
/// the schedule is exhausted the final entry is used as a cap.
const BACKOFF_SCHEDULE: &[Duration] = &[
    Duration::from_secs(10),
    Duration::from_secs(30),
    Duration::from_secs(60),
    Duration::from_secs(300),
];

struct ServerHealth {
    consecutive_failures: u32,
    healthy: bool,
    next_probe_at: Instant,
}

pub struct HealthChecker {
    state: HashMap<IpAddr, ServerHealth>,
    port: u16,
    runtime: Runtime,
    endpoint_v4: Endpoint,
    endpoint_v6: Endpoint,
}

/// Certificate verifier that accepts any certificate.
/// Used for internal health probes where TLS verification is unnecessary.
#[derive(Debug)]
struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

impl HealthChecker {
    pub fn new(port: u16) -> anyhow::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let _guard = runtime.enter();

        let client_config = Self::client_config()?;

        let mut endpoint_v4 = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
        endpoint_v4.set_default_client_config(client_config.clone());

        let mut endpoint_v6 = Endpoint::client("[::]:0".parse().unwrap())?;
        endpoint_v6.set_default_client_config(client_config);

        Ok(HealthChecker {
            state: HashMap::new(),
            port,
            runtime,
            endpoint_v4,
            endpoint_v6,
        })
    }

    fn client_config() -> anyhow::Result<quinn::ClientConfig> {
        let provider = rustls::crypto::ring::default_provider();

        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| anyhow::anyhow!("TLS config: {e}"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth();

        tls.alpn_protocols = vec![
            b"h3".to_vec(),
            b"hq-interop".to_vec(),
            b"hq-29".to_vec(),
        ];

        let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| anyhow::anyhow!("QUIC client config: {e}"))?;

        Ok(quinn::ClientConfig::new(Arc::new(quic_config)))
    }

    /// Reset all backoff timers so unhealthy servers are re-probed on the
    /// next `check()` call. Called on SIGHUP so operators don't have to
    /// wait out the exponential backoff after fixing a backend.
    pub fn reset_backoff(&mut self) {
        let now = Instant::now();
        for s in self.state.values_mut() {
            s.next_probe_at = now;
        }
    }

    /// Probe due servers and update health flags for any that changed state.
    /// Returns `true` if the caller should rebuild fallback servers.
    pub fn check(&mut self, config: &mut ConfigTable) -> bool {
        let now = Instant::now();

        // Phase 1: collect unique addresses, ensure state exists, and
        // pick the ones whose next probe is due.
        let all_addrs: HashSet<IpAddr> = config
            .configs()
            .flat_map(|rc| rc.servers.iter().map(|s| s.address))
            .collect();

        let mut due: Vec<IpAddr> = Vec::with_capacity(all_addrs.len());

        for &addr in &all_addrs {
            let s = self.state.entry(addr).or_insert(ServerHealth {
                consecutive_failures: 0,
                healthy: false,
                next_probe_at: now,
            });

            if now >= s.next_probe_at {
                due.push(addr);
            }
        }

        if due.is_empty() {
            debug!("no backends due for probing ({} tracked)", all_addrs.len());
            return false;
        }

        debug!("probing {} of {} backend(s)", due.len(), all_addrs.len());
        let batch_start = Instant::now();
        let probes = self.probe_all(&due);
        debug!("probe batch complete in {:.2?}", batch_start.elapsed());

        // Phase 2: update per-address health state, log transitions.
        let mut changed = false;

        for (&addr, &ok) in &probes {
            let s = self.state.get_mut(&addr).expect("state inserted above");

            if ok {
                s.consecutive_failures = 0;
                s.next_probe_at = now + PROBE_INTERVAL;

                if !s.healthy {
                    info!("{} is back up", addr);

                    s.healthy = true;
                    changed = true;
                }
            } else {
                s.consecutive_failures += 1;
                s.next_probe_at = now + Self::backoff_for(s.consecutive_failures);

                if s.healthy && s.consecutive_failures >= FAILURE_THRESHOLD {
                    warn!(
                        "{} is down ({} consecutive probe failures)",
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

    /// Returns the delay until the next probe for a server with the
    /// given number of consecutive failures. Entries past the end of
    /// [`BACKOFF_SCHEDULE`] are clamped to the final entry.
    fn backoff_for(failures: u32) -> Duration {
        if failures < FAILURE_THRESHOLD {
            PROBE_INTERVAL
        } else {
            let idx = (failures - FAILURE_THRESHOLD) as usize;
            BACKOFF_SCHEDULE[idx.min(BACKOFF_SCHEDULE.len() - 1)]
        }
    }

    /// Probe all addresses concurrently and return results.
    fn probe_all(&self, addrs: &[IpAddr]) -> HashMap<IpAddr, bool> {
        let port = self.port;
        let ep_v4 = self.endpoint_v4.clone();
        let ep_v6 = self.endpoint_v6.clone();

        self.runtime.block_on(async {
            let mut handles = Vec::with_capacity(addrs.len());

            for &addr in addrs {
                let ep = match addr {
                    IpAddr::V4(_) => ep_v4.clone(),
                    IpAddr::V6(_) => ep_v6.clone(),
                };

                handles.push(tokio::spawn(async move {
                    let target = SocketAddr::new(addr, port);

                    let ok = match tokio::time::timeout(PROBE_TIMEOUT, async {
                        ep.connect(target, "health").ok()?.await.ok()
                    })
                    .await
                    {
                        Ok(Some(conn)) => {
                            conn.close(0u32.into(), b"probe");
                            true
                        }
                        _ => false,
                    };

                    debug!("health probe {} -> {}", target, if ok { "ok" } else { "fail" });
                    (addr, ok)
                }));
            }

            let mut results = HashMap::with_capacity(handles.len());

            for handle in handles {
                if let Ok((addr, ok)) = handle.await {
                    results.insert(addr, ok);
                }
            }

            results
        })
    }
}

impl fmt::Display for ServerHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "failures: {} / healthy: {}", self.consecutive_failures, self.healthy)?;

        Ok(())
    }
}

impl fmt::Display for HealthChecker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "HealthChecker:")?;
        writeln!(f, "  Port: {}", self.port)?;
        writeln!(f, "  Endpoint v4: {:?}", self.endpoint_v4)?;
        writeln!(f, "  Endpoint v6: {:?}", self.endpoint_v6)?;
        writeln!(f, "  Servers:")?;

        for (ip, health) in &self.state {
            writeln!(f, "    {} -> {}", ip, health)?;
        }

        Ok(())
    }
}
