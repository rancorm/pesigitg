// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! Unix-domain JSON status API.
//!
//! Exposes two read-only endpoints for monitoring and automation:
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

use anyhow::{anyhow, Context, Result};
use log::{debug, info, warn};
use serde::Serialize;
use serde_json::{json, Value};

use pesigitg_common::hex::encode as hex_encode;
use pesigitg_common::mac::format as format_mac;

use crate::args::Args;
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
        route_config: Arc<RwLock<ConfigTable>>,
        stats: Arc<StatsTable>,
        worker_health: Arc<WorkerHealth>,
        epoch: Instant,
    ) -> Result<Self> {
        // Ensure parent dir exists. Under systemd this is created by
        // RuntimeDirectory=, but manual invocations bypass that.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("status socket: create parent {}", parent.display())
            })?;
        }

        // Remove stale socket left by a prior run (e.g. ungraceful exit).
        match std::fs::remove_file(&path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(anyhow!(
                "status socket: failed to remove stale {}: {}", path.display(), e
            )),
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
                        listener, shutdown, args, route_config, stats,
                        worker_health, epoch,
                    );
                })
                .context("status socket: spawn accept thread")?
        };

        info!("status API listening on {}", path.display());

        Ok(Self { path, shutdown, listener_fd, accept_thread: Some(accept_thread) })
    }

    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);

        // Kick blocking accept() out with an EOF-like error so the thread
        // can observe the shutdown flag and exit.
        unsafe { libc::shutdown(self.listener_fd, libc::SHUT_RDWR); }

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
    route_config: Arc<RwLock<ConfigTable>>,
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
                handle_connection(
                    stream, &args, &route_config, &stats, &worker_health, epoch,
                );
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
    route_config: &Arc<RwLock<ConfigTable>>,
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
        "GET /" => json!({"endpoints": ["/health", "/stats", "/config"]}),
        "GET /health" => build_health_response(worker_health, epoch),
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
        let cid_by_config: BTreeMap<u8, u64> = s.cid_by_config.iter().enumerate()
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
}

#[derive(Serialize)]
struct RouteConfigView {
    config_id: u8,
    encryption: &'static str,
    server_id_length: u8,
    nonce_length: u8,
    servers: Vec<ServerView>,
}

#[derive(Serialize)]
struct ServerView {
    id: String,
    address: String,
    mac: Option<String>,
    healthy: bool,
    draining: bool,
}

fn encryption_name(e: &Encryption) -> &'static str {
    match e {
        Encryption::Plaintext => "plaintext",
        Encryption::SinglePass { .. } => "single_pass",
        Encryption::FourPass { .. } => "four_pass",
    }
}

impl From<&Server> for ServerView {
    fn from(s: &Server) -> Self {
        ServerView {
            id: hex_encode(&s.id),
            address: s.address.to_string(),
            mac: s.mac.as_ref().map(format_mac),
            healthy: s.healthy,
            draining: s.draining,
        }
    }
}

impl From<&RouteConfig> for RouteConfigView {
    fn from(rc: &RouteConfig) -> Self {
        RouteConfigView {
            config_id: rc.config_id,
            encryption: encryption_name(&rc.encryption),
            server_id_length: rc.server_id_length,
            nonce_length: rc.nonce_length,
            servers: rc.servers.iter().map(ServerView::from).collect(),
        }
    }
}

fn path_str(p: &Path) -> String {
    p.display().to_string()
}

fn build_config_response(
    args: &Arc<RwLock<Args>>,
    route_config: &Arc<RwLock<ConfigTable>>,
) -> Value {
    let a = args.read().unwrap();
    let rc = route_config.read().unwrap();

    let daemon = DaemonView {
        interface: a.interface.clone(),
        ports: a.ports.clone(),
        queues: a.queues,
        config_path: a.config.as_deref().map(path_str),
        route_config_path: a.routeconfig.as_deref().map(path_str),
        status_socket_path: a.status_socket.as_deref().map(path_str),
        foreground: a.foreground,
    };

    let route = RouteView {
        path: rc.path.display().to_string(),
        configs: rc.configs().map(RouteConfigView::from).collect(),
        fallback_pool: rc.fallback_servers.iter().map(|s| s.address.to_string()).collect(),
    };

    serde_json::to_value(ConfigResponse { daemon, route }).unwrap_or(Value::Null)
}
