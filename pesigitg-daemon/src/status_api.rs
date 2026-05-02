// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! Unix-domain JSON status API.
//!
//! Exposes read-only endpoints for monitoring and automation:
//!   GET /health  → liveness probe (status, uptime, worker counts)
//!   GET /version → build identifiers (version, build date, rustc, target)
//!   GET /stats   → aggregated counters, uptime
//!   GET /config  → live daemon args + route table
//!
//! One request per connection. No auth — access is gated by filesystem
//! permissions on the socket.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use arc_swap::ArcSwap;
use log::{debug, info, warn};
use serde::Serialize;
use serde_json::{Value, json};

use pesigitg_common::hex::encode as hex_encode;
use pesigitg_common::mac::format as format_mac;

use crate::args::Args;
use crate::config::retry::{RetryConfig, RetryMode};
use crate::config::route::{ConfigTable, Encryption, RouteConfig, Server};
use crate::stats::{Snapshot, StatsTable};
use crate::threading::WorkerHealth;

const MAX_REQUEST_BYTES: usize = 256;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONCURRENT: usize = 4;
const SOCKET_MODE: u32 = 0o660;

pub struct StatusApi {
    path: PathBuf,
    shutdown: Arc<AtomicBool>,
    listener_fd: RawFd,
    accept_thread: Option<JoinHandle<()>>,
}

impl StatusApi {
    pub fn spawn(
        path: PathBuf,
        args: Arc<RwLock<Args>>,
        route_config: Arc<ArcSwap<ConfigTable>>,
        stats: Arc<StatsTable>,
        worker_health: Arc<WorkerHealth>,
        epoch: Instant,
    ) -> Result<Self> {
        // Ensure parent dir exists. Under systemd this is created by
        // RuntimeDirectory=, but manual invocations bypass that.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("status socket: create parent {}", parent.display()))?;
        }

        // Remove stale socket left by a prior run (e.g. ungraceful exit).
        match std::fs::remove_file(&path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(anyhow!(
                    "status socket: failed to remove stale {}: {}",
                    path.display(),
                    e
                ));
            }
        }

        let listener = UnixListener::bind(&path)
            .with_context(|| format!("status socket: bind {}", path.display()))?;

        // Enforce mode explicitly — bind honors umask, which may be tighter
        // or looser than we want.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(SOCKET_MODE))
            .with_context(|| format!("status socket: chmod {}", path.display()))?;

        let listener_fd = listener.as_raw_fd();
        let shutdown = Arc::new(AtomicBool::new(false));

        let accept_thread = {
            let shutdown = Arc::clone(&shutdown);
            thread::Builder::new()
                .name("status-api".into())
                .spawn(move || {
                    accept_loop(
                        listener,
                        shutdown,
                        args,
                        route_config,
                        stats,
                        worker_health,
                        epoch,
                    );
                })
                .context("status socket: spawn accept thread")?
        };

        info!("status API listening on {}", path.display());

        Ok(Self {
            path,
            shutdown,
            listener_fd,
            accept_thread: Some(accept_thread),
        })
    }

    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);

        // Kick blocking accept() out with an EOF-like error so the thread
        // can observe the shutdown flag and exit.
        unsafe {
            libc::shutdown(self.listener_fd, libc::SHUT_RDWR);
        }

        if let Some(h) = self.accept_thread.take() {
            let _ = h.join();
        }

        match std::fs::remove_file(&self.path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!("status API: unlink {}: {}", self.path.display(), e),
        }
    }
}

impl Drop for StatusApi {
    fn drop(&mut self) {
        if self.accept_thread.is_some() {
            self.shutdown();
        }
    }
}

fn accept_loop(
    listener: UnixListener,
    shutdown: Arc<AtomicBool>,
    args: Arc<RwLock<Args>>,
    route_config: Arc<ArcSwap<ConfigTable>>,
    stats: Arc<StatsTable>,
    worker_health: Arc<WorkerHealth>,
    epoch: Instant,
) {
    let active = Arc::new(AtomicUsize::new(0));

    for stream in listener.incoming() {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                warn!("status API accept: {}", e);
                continue;
            }
        };

        let current = active.fetch_add(1, Ordering::SeqCst);
        if current >= MAX_CONCURRENT {
            active.fetch_sub(1, Ordering::SeqCst);
            debug!("status API: busy, rejecting connection");
            let _ = write_response(&stream, &json!({"error": "busy"}));
            continue;
        }

        let args = Arc::clone(&args);
        let route_config = Arc::clone(&route_config);
        let stats = Arc::clone(&stats);
        let worker_health = Arc::clone(&worker_health);
        let active_c = Arc::clone(&active);

        let spawn = thread::Builder::new()
            .name("status-api-conn".into())
            .spawn(move || {
                handle_connection(stream, &args, &route_config, &stats, &worker_health, epoch);
                active_c.fetch_sub(1, Ordering::SeqCst);
            });

        if let Err(e) = spawn {
            active.fetch_sub(1, Ordering::SeqCst);
            warn!("status API: spawn handler: {}", e);
        }
    }

    debug!("status API accept loop exiting");
}

fn handle_connection(
    mut stream: UnixStream,
    args: &Arc<RwLock<Args>>,
    route_config: &Arc<ArcSwap<ConfigTable>>,
    stats: &Arc<StatsTable>,
    worker_health: &Arc<WorkerHealth>,
    epoch: Instant,
) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

    let mut buf = [0u8; MAX_REQUEST_BYTES];
    let mut len = 0usize;
    loop {
        if len == buf.len() {
            debug!("status API: request too long");
            let _ = write_response(&stream, &json!({"error": "request too long"}));
            return;
        }
        match stream.read(&mut buf[len..]) {
            Ok(0) => break,
            Ok(n) => {
                len += n;
                if buf[..len].contains(&b'\n') {
                    break;
                }
            }
            Err(e) => {
                debug!("status API: read: {}", e);
                return;
            }
        }
    }

    let request = std::str::from_utf8(&buf[..len])
        .unwrap_or("")
        .split(['\n', '\r'])
        .next()
        .unwrap_or("")
        .trim();

    let response = match request {
        "GET /" => json!({"endpoints": ["/health", "/version", "/stats", "/config"]}),
        "GET /health" => build_health_response(worker_health, epoch),
        "GET /version" => build_version_response(),
        "GET /stats" => build_stats_response(stats, epoch),
        "GET /config" => build_config_response(args, route_config),
        _ => json!({"error": "unknown endpoint"}),
    };

    if let Err(e) = write_response(&stream, &response) {
        debug!("status API: write: {}", e);
    }
}

fn write_response(mut stream: &UnixStream, value: &Value) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    bytes.push(b'\n');
    stream.write_all(&bytes)
}

// ----- Stats DTOs -----

#[derive(Serialize)]
struct StatsResponse {
    uptime_secs: u64,
    #[serde(flatten)]
    snapshot: SnapshotView,
}

#[derive(Serialize)]
struct SnapshotView {
    rx_packets: u64,
    forwarded: u64,
    cid_routed: u64,
    cid_by_config: BTreeMap<u8, u64>,
    fallback_routed: u64,
    cid_unroutable: u64,
    draining_forwarded: u64,
    icmp_forwarded: u64,
    passed: u64,
    pending_fill_peak: u64,
    retry: RetryView,
}

#[derive(Serialize)]
struct RetryView {
    initials_seen: u64,
    issued: u64,
    token_validated: u64,
    token_invalid: u64,
    token_expired: u64,
    parse_error: u64,
}

impl From<&Snapshot> for SnapshotView {
    fn from(s: &Snapshot) -> Self {
        let cid_by_config: BTreeMap<u8, u64> = s
            .cid_by_config
            .iter()
            .enumerate()
            .filter_map(|(i, &n)| (n > 0).then_some((i as u8, n)))
            .collect();
        SnapshotView {
            rx_packets: s.rx_packets,
            forwarded: s.forwarded,
            cid_routed: s.cid_routed,
            cid_by_config,
            fallback_routed: s.fallback_routed,
            cid_unroutable: s.cid_unroutable,
            draining_forwarded: s.draining_forwarded,
            icmp_forwarded: s.icmp_forwarded,
            passed: s.passed,
            pending_fill_peak: s.pending_fill_peak,
            retry: RetryView {
                initials_seen: s.retry_initials_seen,
                issued: s.retry_issued,
                token_validated: s.retry_token_validated,
                token_invalid: s.retry_token_invalid,
                token_expired: s.retry_token_expired,
                parse_error: s.retry_parse_error,
            },
        }
    }
}

// ----- Version DTO -----

#[derive(Serialize)]
struct VersionResponse {
    name: &'static str,
    version: &'static str,
    build_date: &'static str,
    rustc_version: &'static str,
    target: &'static str,
}

fn build_version_response() -> Value {
    let resp = VersionResponse {
        name: pesigitg_common::PROC_NAME,
        version: env!("CARGO_PKG_VERSION"),
        build_date: env!("BUILD_DATE"),
        rustc_version: env!("RUSTC_VERSION"),
        target: env!("TARGET"),
    };
    serde_json::to_value(&resp).unwrap_or(Value::Null)
}

// ----- Health DTO -----

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    uptime_secs: u64,
    workers_alive: usize,
    workers_expected: usize,
}

fn build_health_response(worker_health: &WorkerHealth, epoch: Instant) -> Value {
    let alive = worker_health.alive.load(Ordering::Relaxed);
    let expected = worker_health.expected;
    let status = if alive >= expected { "ok" } else { "degraded" };

    let resp = HealthResponse {
        status,
        uptime_secs: epoch.elapsed().as_secs(),
        workers_alive: alive,
        workers_expected: expected,
    };
    serde_json::to_value(&resp).unwrap_or(Value::Null)
}

fn build_stats_response(stats: &StatsTable, epoch: Instant) -> Value {
    let snap = stats.aggregate();
    let resp = StatsResponse {
        uptime_secs: epoch.elapsed().as_secs(),
        snapshot: SnapshotView::from(&snap),
    };
    serde_json::to_value(&resp).unwrap_or(Value::Null)
}

// ----- Config DTOs -----

#[derive(Serialize)]
struct ConfigResponse {
    daemon: DaemonView,
    route: RouteView,
}

#[derive(Serialize)]
struct DaemonView {
    interface: String,
    ports: Vec<u16>,
    queues: u32,
    config_path: Option<String>,
    route_config_path: Option<String>,
    status_socket_path: Option<String>,
    foreground: bool,
}

#[derive(Serialize)]
struct RouteView {
    path: String,
    configs: Vec<RouteConfigView>,
    fallback_pool: Vec<String>,
    /// QUIC Retry service settings, including key age. Absent when the
    /// route config has no `[retry]` section.
    #[serde(skip_serializing_if = "Option::is_none")]
    retry: Option<RetryConfigView>,
}

#[derive(Serialize)]
struct RouteConfigView {
    config_id: u8,
    encryption: &'static str,
    server_id_length: u8,
    nonce_length: u8,
    /// Seconds since this slot's QUIC-LB encryption key was loaded.
    /// `None` for [`Encryption::Plaintext`] (no key to age) and during
    /// the brief window before the first reload finishes.
    #[serde(skip_serializing_if = "Option::is_none")]
    key_age_secs: Option<u64>,
    servers: Vec<ServerView>,
}

#[derive(Serialize)]
struct RetryConfigView {
    enabled: bool,
    mode: &'static str,
    ports: Vec<u16>,
    token_lifetime_secs: u64,
    /// Seconds since the current `token_key` was loaded. Preserved
    /// across reloads when the key bytes don't change.
    key_age_secs: u64,
}

#[derive(Serialize)]
struct ServerView {
    id: String,
    address: String,
    mac: Option<String>,
    healthy: bool,
    draining: bool,
    /// Healthy↔unhealthy flips since daemon startup, post-warmup.
    transitions: u32,
    /// Seconds since the server entered its current `healthy` state.
    /// `None` until the first probe completes after startup or SIGHUP.
    state_since_secs: Option<u64>,
}

fn encryption_name(e: &Encryption) -> &'static str {
    match e {
        Encryption::Plaintext => "plaintext",
        Encryption::SinglePass { .. } => "single_pass",
        Encryption::FourPass { .. } => "four_pass",
    }
}

fn retry_mode_name(m: RetryMode) -> &'static str {
    match m {
        RetryMode::Observe => "observe",
        RetryMode::Always => "always",
        RetryMode::Load => "load",
    }
}

impl RetryConfigView {
    fn from_retry(rc: &RetryConfig, now: Instant) -> Self {
        RetryConfigView {
            enabled: rc.enabled,
            mode: retry_mode_name(rc.mode),
            ports: rc.ports.clone(),
            token_lifetime_secs: rc.token_lifetime_ms / 1_000,
            key_age_secs: now.saturating_duration_since(rc.loaded_at).as_secs(),
        }
    }
}

impl From<&Server> for ServerView {
    fn from(s: &Server) -> Self {
        let now = Instant::now();
        ServerView {
            id: hex_encode(&s.id),
            address: s.address.to_string(),
            mac: s.mac.as_ref().map(format_mac),
            healthy: s.healthy,
            draining: s.draining,
            transitions: s.transitions,
            state_since_secs: s
                .state_since
                .map(|t| now.saturating_duration_since(t).as_secs()),
        }
    }
}

impl RouteConfigView {
    fn from_route(rc: &RouteConfig, loaded_at: Option<Instant>, now: Instant) -> Self {
        // Plaintext slots have no key to age. For encrypted slots,
        // report seconds since `loaded_at` (preserved across reloads
        // that don't change the key bytes — see
        // `ConfigTable::inherit_ages_from`).
        let key_age_secs = match rc.encryption {
            Encryption::Plaintext => None,
            _ => loaded_at.map(|t| now.saturating_duration_since(t).as_secs()),
        };
        RouteConfigView {
            config_id: rc.config_id,
            encryption: encryption_name(&rc.encryption),
            server_id_length: rc.server_id_length,
            nonce_length: rc.nonce_length,
            key_age_secs,
            servers: rc.servers.iter().map(ServerView::from).collect(),
        }
    }
}

fn path_str(p: &Path) -> String {
    p.display().to_string()
}

fn build_config_response(
    args: &Arc<RwLock<Args>>,
    route_config: &Arc<ArcSwap<ConfigTable>>,
) -> Value {
    let a = args.read().expect("lock poisoned");
    let rc = route_config.load();

    let daemon = DaemonView {
        interface: a.interface.clone(),
        ports: a.ports.clone(),
        queues: a.queues,
        config_path: a.config.as_deref().map(path_str),
        route_config_path: a.routeconfig.as_deref().map(path_str),
        status_socket_path: a.status_socket.as_deref().map(path_str),
        foreground: a.foreground,
    };

    let now = Instant::now();
    let route = RouteView {
        path: rc.path.display().to_string(),
        configs: rc
            .configs()
            .map(|cfg| RouteConfigView::from_route(cfg, rc.loaded_at(cfg.config_id), now))
            .collect(),
        fallback_pool: rc
            .fallback_servers
            .iter()
            .map(|s| s.address.to_string())
            .collect(),
        retry: rc
            .retry
            .as_ref()
            .map(|r| RetryConfigView::from_retry(r, now)),
    };

    serde_json::to_value(ConfigResponse { daemon, route }).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    use aes::Aes128;
    use aes::cipher::KeyInit;
    use aes::cipher::generic_array::GenericArray;

    fn fixture_args() -> Args {
        Args {
            ports: vec![443, 4433],
            interface: "lo".into(),
            queues: 2,
            config: Some(PathBuf::from("/etc/pesigitgd.toml")),
            routeconfig: Some(PathBuf::from("/etc/pesigitgd-route.toml")),
            status_socket: Some(PathBuf::from("/run/pesigitgd.sock")),
            #[cfg(debug_assertions)]
            ebpf_obj: None,
            foreground: true,
        }
    }

    fn fixture_table() -> ConfigTable {
        ConfigTable::from_str(
            r#"
[[configs]]
config_id = 0
server_id_length = 2
nonce_length = 5

[[configs.servers]]
id = "0001"
address = "10.0.0.1"

[[configs.servers]]
id = "0002"
address = "2001:db8::1"
"#,
        )
        .unwrap()
    }

    fn worker_health(alive: usize, expected: usize) -> Arc<WorkerHealth> {
        Arc::new(WorkerHealth {
            expected,
            alive: AtomicUsize::new(alive),
        })
    }

    // ---------- DTO conversions ----------

    #[test]
    fn snapshot_view_filters_zero_cid_configs() {
        let snap = Snapshot {
            cid_by_config: [3, 0, 5, 0, 0, 0, 1],
            ..Snapshot::default()
        };
        let view = SnapshotView::from(&snap);
        assert_eq!(view.cid_by_config.len(), 3);
        assert_eq!(view.cid_by_config[&0], 3);
        assert_eq!(view.cid_by_config[&2], 5);
        assert_eq!(view.cid_by_config[&6], 1);
    }

    #[test]
    fn snapshot_view_omits_cid_by_config_when_all_zero() {
        let view = SnapshotView::from(&Snapshot::default());
        assert!(view.cid_by_config.is_empty());
    }

    #[test]
    fn snapshot_view_preserves_top_level_counters() {
        let snap = Snapshot {
            rx_packets: 10,
            forwarded: 9,
            cid_routed: 4,
            fallback_routed: 3,
            cid_unroutable: 1,
            draining_forwarded: 1,
            icmp_forwarded: 0,
            passed: 1,
            pending_fill_peak: 7,
            ..Snapshot::default()
        };

        let view = SnapshotView::from(&snap);
        assert_eq!(view.rx_packets, 10);
        assert_eq!(view.forwarded, 9);
        assert_eq!(view.cid_routed, 4);
        assert_eq!(view.fallback_routed, 3);
        assert_eq!(view.cid_unroutable, 1);
        assert_eq!(view.draining_forwarded, 1);
        assert_eq!(view.icmp_forwarded, 0);
        assert_eq!(view.passed, 1);
        assert_eq!(view.pending_fill_peak, 7);
    }

    #[test]
    fn snapshot_view_nests_retry_subtree() {
        let snap = Snapshot {
            retry_initials_seen: 5,
            retry_issued: 4,
            retry_token_validated: 3,
            retry_token_invalid: 2,
            retry_token_expired: 1,
            retry_parse_error: 1,
            ..Snapshot::default()
        };

        let value = serde_json::to_value(SnapshotView::from(&snap)).unwrap();
        let retry = &value["retry"];
        assert_eq!(retry["initials_seen"], 5);
        assert_eq!(retry["issued"], 4);
        assert_eq!(retry["token_validated"], 3);
        assert_eq!(retry["token_invalid"], 2);
        assert_eq!(retry["token_expired"], 1);
        assert_eq!(retry["parse_error"], 1);
    }

    #[test]
    fn version_response_uses_compile_time_constants() {
        let v = build_version_response();
        assert_eq!(v["name"], pesigitg_common::PROC_NAME);
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(v["build_date"], env!("BUILD_DATE"));
        assert_eq!(v["rustc_version"], env!("RUSTC_VERSION"));
        assert_eq!(v["target"], env!("TARGET"));
    }

    #[test]
    fn health_response_status_ok_when_alive_meets_expected() {
        let wh = worker_health(4, 4);
        let v = build_health_response(&wh, Instant::now());
        assert_eq!(v["status"], "ok");
        assert_eq!(v["workers_alive"], 4);
        assert_eq!(v["workers_expected"], 4);
    }

    #[test]
    fn health_response_status_ok_when_alive_exceeds_expected() {
        // Documents the `alive >= expected` rule: spurious extras don't
        // get reported as degraded.
        let wh = worker_health(5, 4);
        let v = build_health_response(&wh, Instant::now());
        assert_eq!(v["status"], "ok");
    }

    #[test]
    fn health_response_status_degraded_when_alive_below_expected() {
        let wh = worker_health(2, 4);
        let v = build_health_response(&wh, Instant::now());
        assert_eq!(v["status"], "degraded");
        assert_eq!(v["workers_alive"], 2);
    }

    #[test]
    fn encryption_name_maps_three_variants() {
        let key = [0u8; 16];
        let cipher = Aes128::new(GenericArray::from_slice(&key));
        assert_eq!(encryption_name(&Encryption::Plaintext), "plaintext");
        assert_eq!(
            encryption_name(&Encryption::SinglePass {
                key,
                cipher: cipher.clone(),
            }),
            "single_pass"
        );
        assert_eq!(
            encryption_name(&Encryption::FourPass { key, cipher }),
            "four_pass"
        );
    }

    #[test]
    fn config_response_serializes_args_and_route() {
        let args = Arc::new(RwLock::new(fixture_args()));
        let table = Arc::new(ArcSwap::from_pointee(fixture_table()));
        let v = build_config_response(&args, &table);

        assert_eq!(v["daemon"]["interface"], "lo");
        assert_eq!(v["daemon"]["ports"], json!([443, 4433]));
        assert_eq!(v["daemon"]["queues"], 2);
        assert_eq!(v["daemon"]["foreground"], true);
        assert_eq!(v["daemon"]["status_socket_path"], "/run/pesigitgd.sock");

        let configs = v["route"]["configs"].as_array().unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0]["config_id"], 0);
        assert_eq!(configs[0]["encryption"], "plaintext");

        let servers = configs[0]["servers"].as_array().unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0]["id"], "0001");
        assert_eq!(servers[0]["address"], "10.0.0.1");
    }

    // ---------- handle_connection over a UnixStream pair ----------

    fn drive_handle_connection(request: &[u8]) -> Value {
        let (server, client) = UnixStream::pair().unwrap();
        let args = Arc::new(RwLock::new(fixture_args()));
        let table = Arc::new(ArcSwap::from_pointee(fixture_table()));
        let stats = Arc::new(StatsTable::new(1));
        let wh = worker_health(1, 1);
        let epoch = Instant::now();

        let handle = thread::spawn(move || {
            handle_connection(server, &args, &table, &stats, &wh, epoch);
        });

        // Write in a thread so ECONNRESET from the server closing early
        // (e.g., on oversized requests) doesn't poison the read side.
        let req = request.to_vec();
        let mut write_client = client.try_clone().unwrap();
        let writer = thread::spawn(move || {
            let _ = write_client.write_all(&req);
            let _ = write_client.shutdown(std::net::Shutdown::Write);
        });

        let mut read_client = client;
        let mut buf = Vec::new();
        read_client.read_to_end(&mut buf).unwrap();
        let _ = writer.join();
        handle.join().unwrap();

        let line = buf.split(|&b| b == b'\n').next().unwrap();
        serde_json::from_slice(line).expect("response is JSON")
    }

    #[test]
    fn handle_connection_root_lists_endpoints() {
        let v = drive_handle_connection(b"GET /\n");
        let endpoints = v["endpoints"].as_array().unwrap();
        assert!(endpoints.iter().any(|e| e == "/health"));
        assert!(endpoints.iter().any(|e| e == "/version"));
        assert!(endpoints.iter().any(|e| e == "/stats"));
        assert!(endpoints.iter().any(|e| e == "/config"));
    }

    #[test]
    fn handle_connection_unknown_endpoint() {
        let v = drive_handle_connection(b"GET /nope\n");
        assert_eq!(v["error"], "unknown endpoint");
    }

    #[test]
    fn handle_connection_request_too_long() {
        // Exactly MAX_REQUEST_BYTES with no newline fills the buffer;
        // the next loop iteration reports truncation. Writing any more
        // would leave unread bytes in the recv queue and race a RST.
        let req = vec![b'A'; MAX_REQUEST_BYTES];
        let v = drive_handle_connection(&req);
        assert_eq!(v["error"], "request too long");
    }

    #[test]
    fn handle_connection_handles_crlf_terminator() {
        let v = drive_handle_connection(b"GET /\r\n");
        assert!(v["endpoints"].is_array());
    }

    #[test]
    fn handle_connection_dispatches_version() {
        let v = drive_handle_connection(b"GET /version\n");
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    }
}
