// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! welman — Minimal HTTP/3 server with QUIC-LB compliant Connection IDs.
//!
//! Named after Welman Matrix from ReBoot — the father who spent most of the
//! series trapped in a read-only format.  Fitting for a server that just
//! hands back responses.
//!
//! A test backend for pesigitgd integration testing.  Accepts HTTP/3
//! connections via Quinn + h3, generates CIDs that the load balancer can
//! decrypt, and serves a minimal diagnostic page.
//!
//! Usage:
//!     welman --config lb.toml --server-id 000001 [--listen 0.0.0.0:443]
//!
//! The config file uses the same format as pesigitgd's lb.toml.
//! --server-id selects which server identity this instance uses for CID
//! generation (hex string matching a server id in the config).

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use quic_lb_cid::{Encryption, QuicLbCidGenerator};
use quinn::Endpoint;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::signal;

#[derive(serde::Deserialize)]
struct ConfigFile {
    #[serde(default)]
    configs: Vec<RawConfig>,

    // Support flat (non-nested) lb.toml layout as well: top-level fields
    // are silently captured so serde doesn't reject unknown keys.
    #[serde(default)]
    config_id: Option<u8>,
    #[serde(default)]
    first_octet_encodes_cid_length: Option<bool>,
    #[serde(default)]
    server_id_length: Option<u8>,
    #[serde(default)]
    nonce_length: Option<u8>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    servers: Vec<RawServer>,
}

#[derive(serde::Deserialize)]
struct RawConfig {
    config_id: u8,
    #[serde(default)]
    first_octet_encodes_cid_length: bool,
    server_id_length: u8,
    nonce_length: u8,
    key: Option<String>,
    #[serde(default)]
    servers: Vec<RawServer>,
}

#[derive(serde::Deserialize)]
struct RawServer {
    id: String,
    #[allow(dead_code)]
    address: String,
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();

    if s.len() % 2 != 0 {
        bail!("odd number of hex characters");
    }
    
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| anyhow::anyhow!("invalid hex at position {i}"))
        })
        .collect()
}

/// Resolved parameters for CID generation.
struct CidGenParams {
    config_id: u8,
    server_id: Vec<u8>,
    nonce_length: u8,
    encryption: Encryption,
    encode_cid_length: bool,
}

/// Build encryption mode from key + lengths.
fn make_encryption(key_hex: &Option<String>, sid_len: u8, nonce_len: u8) -> Result<Encryption> {
    match key_hex {
        None => Ok(Encryption::Plaintext),
        Some(hex) => {
            let key_bytes = hex_decode(hex).context("parsing key")?;

            if key_bytes.len() != 16 {
                bail!("key must be 16 bytes, got {}", key_bytes.len());
            }

            let mut key = [0u8; 16];
            key.copy_from_slice(&key_bytes);

            if sid_len as u16 + nonce_len as u16 == 16 {
                Ok(Encryption::SinglePass { key })
            } else {
                Ok(Encryption::FourPass { key })
            }
        }
    }
}

/// Find the config entry containing the requested server_id.
///
/// Supports both nested `[[configs]]` format and the flat top-level layout
/// used by the current lb.toml.
fn resolve_config(path: &str, server_id_hex: &str) -> Result<CidGenParams> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config: {path}"))?;
    let file: ConfigFile = toml::from_str(&text)
        .with_context(|| format!("parsing config: {path}"))?;

    let server_id = hex_decode(server_id_hex).context("parsing --server-id")?;

    // Try nested [[configs]] first.
    for raw in &file.configs {
        if raw.server_id_length as usize != server_id.len() {
            continue;
        }
        
        let has_server = raw.servers.iter().any(|s| {
            hex_decode(&s.id).map_or(false, |id| id == server_id)
        });

        if !has_server {
            continue;
        }

        return Ok(CidGenParams {
            config_id: raw.config_id,
            server_id,
            nonce_length: raw.nonce_length,
            encryption: make_encryption(&raw.key, raw.server_id_length, raw.nonce_length)?,
            encode_cid_length: raw.first_octet_encodes_cid_length,
        });
    }

    // Fall back to flat top-level layout.
    if let (Some(config_id), Some(sid_len), Some(nonce_len)) =
        (file.config_id, file.server_id_length, file.nonce_length)
    {
        if sid_len as usize == server_id.len() {
            let has_server = file.servers.iter().any(|s| {
                hex_decode(&s.id).map_or(false, |id| id == server_id)
            });

            if has_server {
                return Ok(CidGenParams {
                    config_id,
                    server_id,
                    nonce_length: nonce_len,
                    encryption: make_encryption(&file.key, sid_len, nonce_len)?,
                    encode_cid_length: file.first_octet_encodes_cid_length.unwrap_or(false),
                });
            }
        }
    }

    bail!("server_id {server_id_hex} not found in any config in {path}");
}

fn generate_self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivatePkcs8KeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .context("generating self-signed cert")?;
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    
    Ok((vec![cert_der], key_der))
}

struct Args {
    config_path: String,
    server_id: String,
    listen: SocketAddr,
}

fn parse_args() -> Result<Args> {
    let mut args = std::env::args().skip(1);
    let mut config_path = None;
    let mut server_id = None;
    let mut listen: SocketAddr = "0.0.0.0:443".parse().unwrap();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => {
                config_path = Some(args.next().context("--config requires a value")?);
            }
            "--server-id" | "-s" => {
                server_id = Some(args.next().context("--server-id requires a value")?);
            }
            "--listen" | "-l" => {
                let val = args.next().context("--listen requires a value")?;
                listen = val.parse().context("invalid listen address")?;
            }
            "--help" | "-h" => {
                eprintln!(
                    "welman — HTTP/3 server with QUIC-LB compliant CIDs\n\n\
                     Usage: welman --config <lb.toml> --server-id <hex>\n\n\
                     Options:\n  \
                       -c, --config <path>      Path to lb.toml config file\n  \
                       -s, --server-id <hex>    Server ID (hex, e.g. 000001)\n  \
                       -l, --listen <addr:port> Listen address (default: 0.0.0.0:443)"
                );
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    Ok(Args {
        config_path: config_path.context("--config is required")?,
        server_id: server_id.context("--server-id is required")?,
        listen,
    })
}

/// Diagnostic info embedded in every response.
#[derive(Clone)]
struct ServerInfo {
    server_id: String,
    config_id: u8,
    cid_len: usize,
    encryption: String,
    listen: SocketAddr,
}

/// Handle a single HTTP/3 request and send a response.
async fn handle_request<T>(
    req: Request<()>,
    mut stream: h3::server::RequestStream<T, Bytes>,
    remote: SocketAddr,
    info: &ServerInfo,
) -> Result<()>
where
    T: h3::quic::BidiStream<Bytes>,
{
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    eprintln!("welman: [{remote}] {method} {path}");

    let (status, body) = match path.as_str() {
        "/" => (StatusCode::OK, build_index_page(remote, info)),
        "/health" => (StatusCode::OK, "OK\n".to_string()),
        _ => (StatusCode::NOT_FOUND, build_404_page(&path)),
    };

    let resp = Response::builder()
        .status(status)
        .header("content-type", content_type_for(&path))
        .header("server", "welman/0.1.0")
        .header("alt-svc", "h3=\":443\"; ma=86400")
        .body(())
        .context("building response")?;

    stream.send_response(resp).await.context("sending response")?;
    stream
        .send_data(Bytes::from(body))
        .await
        .context("sending body")?;
    stream.finish().await.context("finishing stream")?;

    Ok(())
}

fn content_type_for(path: &str) -> &'static str {
    match path {
        "/health" => "text/plain; charset=utf-8",
        _ => "text/html; charset=utf-8",
    }
}

fn build_index_page(remote: SocketAddr, info: &ServerInfo) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>welman — HTTP/3 over QUIC-LB</title>
<style>
  body {{
    font-family: "Berkeley Mono", "SF Mono", "Consolas", monospace;
    background: #0a0a0a; color: #c0c0c0;
    max-width: 640px; margin: 4rem auto; padding: 0 1rem;
    line-height: 1.6;
  }}
  h1 {{ color: #e0e0e0; font-size: 1.4rem; }}
  .label {{ color: #707070; }}
  .value {{ color: #44cc88; }}
  hr {{ border: none; border-top: 1px solid #222; margin: 1.5rem 0; }}
  a {{ color: #5588cc; }}
</style>
</head>
<body>
<h1>welman</h1>
<p>HTTP/3 test server with QUIC-LB compliant Connection IDs.</p>
<hr>
<p><span class="label">client:</span> <span class="value">{remote}</span></p>
<p><span class="label">server_id:</span> <span class="value">{sid}</span></p>
<p><span class="label">config_id:</span> <span class="value">{cid}</span></p>
<p><span class="label">cid_length:</span> <span class="value">{cid_len}</span></p>
<p><span class="label">encryption:</span> <span class="value">{enc}</span></p>
<p><span class="label">listen:</span> <span class="value">{listen}</span></p>
<p><span class="label">protocol:</span> <span class="value">HTTP/3 (RFC 9114) over QUIC (RFC 9000)</span></p>
<hr>
<p><span class="label">Named after <a href="https://reboot.fandom.com/wiki/Welman_Matrix">Welman Matrix</a>
— the father trapped in a read-only format.</span></p>
</body>
</html>
"#,
        remote = remote,
        sid = info.server_id,
        cid = info.config_id,
        cid_len = info.cid_len,
        enc = info.encryption,
        listen = info.listen,
    )
}

fn build_404_page(path: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>404</title>
<style>
  body {{
    font-family: monospace; background: #0a0a0a; color: #c0c0c0;
    max-width: 640px; margin: 4rem auto; padding: 0 1rem;
  }}
</style>
</head>
<body>
<h1>404</h1>
<p>{path} — not found. Try <a href="/" style="color:#5588cc">/</a>
or <a href="/health" style="color:#5588cc">/health</a>.</p>
</body>
</html>
"#,
        path = path,
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;
    let params = resolve_config(&args.config_path, &args.server_id)?;
    let enc_label = match &params.encryption {
        Encryption::Plaintext => "plaintext",
        Encryption::SinglePass { .. } => "single-pass AES-ECB",
        Encryption::FourPass { .. } => "four-pass Feistel",
    };
    let cid_len = 1 + params.server_id.len() + params.nonce_length as usize;

    eprintln!(
        "welman: config_id={}, server_id={}, cid_len={cid_len}, \
         encryption={enc_label}, listen={}",
        params.config_id, args.server_id, args.listen,
    );

    let info = ServerInfo {
        server_id: args.server_id.clone(),
        config_id: params.config_id,
        cid_len,
        encryption: enc_label.to_string(),
        listen: args.listen,
    };

    // TLS
    let (certs, key) = generate_self_signed_cert()?;
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key.into())
        .context("TLS config")?;
    tls_config.max_early_data_size = u32::MAX;
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    // Quinn transport
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)).unwrap(),
    ));
    transport.max_concurrent_bidi_streams(128u32.into());
    transport.max_concurrent_uni_streams(128u32.into());

    // Server config
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .context("QUIC crypto config")?,
    ));
    server_config.transport_config(Arc::new(transport));

    // Endpoint with QUIC-LB CID generator
    let config_id = params.config_id;
    let server_id = params.server_id;
    let nonce_length = params.nonce_length;
    let encryption = params.encryption;
    let encode_cid_length = params.encode_cid_length;

    // Endpoint config
    let mut ep_config = quinn::EndpointConfig::default();
    ep_config.cid_generator(move || {
        Box::new(QuicLbCidGenerator::new(
            config_id,
            server_id.clone(),
            nonce_length,
            encryption.clone(),
            encode_cid_length,
        ))
    });

    // Socket and endpoint
    let socket = UdpSocket::bind(args.listen)
        .context("binding UDP socket")?;
    let endpoint = Endpoint::new(
        ep_config,
        Some(server_config),
        socket,
        quinn::default_runtime()
            .ok_or_else(|| anyhow::anyhow!("no async runtime"))?,
    )
    .context("creating endpoint")?;

    eprintln!("welman: listening on {}", endpoint.local_addr()?);
    eprintln!("welman: serving HTTP/3 (h3) with QUIC-LB CIDs");

    // Accept loop
    let info = Arc::new(info);

    let accept_loop = async {
        while let Some(incoming) = endpoint.accept().await {
            let info = info.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(incoming, &info).await {
                    eprintln!("welman: connection error: {:#}", e);
                }
            });
        }
    };

    tokio::select! {
        _ = accept_loop => {}
        _ = signal::ctrl_c() => {
            eprintln!("\nwelman: shutting down");
        }
    }

    endpoint.close(0u32.into(), b"bye");

    Ok(())
}

async fn handle_connection(incoming: quinn::Incoming, info: &ServerInfo) -> Result<()> {
    let conn = incoming.await.context("accepting QUIC connection")?;
    let remote = conn.remote_address();

    eprintln!("welman: [{remote}] new HTTP/3 connection");

    // Wrap Quinn connection for h3.
    let h3_conn = h3_quinn::Connection::new(conn);
    let mut h3 = h3::server::builder()
        .build(h3_conn)
        .await
        .context("HTTP/3 handshake")?;

    // Accept HTTP/3 requests on this connection.
    loop {
        match h3.accept().await {
            Ok(Some(resolver)) => {
                let info = info.clone();

                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            let remote = remote;

                            if let Err(e) = handle_request(req, stream, remote, &info).await {
                                eprintln!("welman: [{remote}] request error: {:#}", e);
                            }
                        }
                        Err(e) => {
                            eprintln!("welman: [{remote}] resolve error: {}", e);
                        }
                    }
                });
            }
            Ok(None) => {
                eprintln!("welman: [{remote}] connection closed");
                
                return Ok(());
            }
            Err(e) => {
                let msg = e.to_string();

                if msg.contains("aborted by peer") || msg.contains("H3_NO_ERROR") {
                        eprintln!("welman: [{remote}] connection closed by client");
                } else {
                        eprintln!("welman: [{remote}] accept error: {}", e);
                }

                return Ok(());
            }
        }
    }
}
