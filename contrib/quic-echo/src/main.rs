//! quic-echo — Minimal QUIC echo server with QUIC-LB compliant Connection IDs.
//!
//! A test backend for pesigitgd integration testing. Accepts QUIC connections,
//! echoes stream data back to the client, and generates CIDs that the load
//! balancer can decrypt to route packets to this server.
//!
//! Usage:
//!     quic-echo --config lb.toml --server-id 000001 [--listen 0.0.0.0:443]
//!
//! The config file uses the same [[configs]] format as pesigitgd's lb.toml.
//! --server-id selects which server identity this instance uses for CID
//! generation (hex string matching a server id in the config).

mod cid_gen;

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use quinn::Endpoint;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::signal;

use cid_gen::{Encryption, QuicLbCidGenerator};

// ---------------------------------------------------------------------------
// Config parsing (reuses lb.toml format)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct ConfigFile {
    #[serde(default)]
    configs: Vec<RawConfig>,
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

/// Find the config entry containing the requested server_id.
fn resolve_config(path: &str, server_id_hex: &str) -> Result<CidGenParams> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config: {path}"))?;
    let file: ConfigFile = toml::from_str(&text)
        .with_context(|| format!("parsing config: {path}"))?;

    let server_id = hex_decode(server_id_hex)
        .context("parsing --server-id")?;

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

        let encryption = match &raw.key {
            None => Encryption::Plaintext,
            Some(hex) => {
                let key_bytes = hex_decode(hex).context("parsing key")?;
                if key_bytes.len() != 16 {
                    bail!("key must be 16 bytes, got {}", key_bytes.len());
                }
                let mut key = [0u8; 16];
                key.copy_from_slice(&key_bytes);

                let sum = raw.server_id_length as u16 + raw.nonce_length as u16;
                if sum == 16 {
                    Encryption::SinglePass { key }
                } else {
                    Encryption::FourPass { key }
                }
            }
        };

        return Ok(CidGenParams {
            config_id: raw.config_id,
            server_id,
            nonce_length: raw.nonce_length,
            encryption,
            encode_cid_length: raw.first_octet_encodes_cid_length,
        });
    }

    bail!("server_id {server_id_hex} not found in any config in {path}");
}

// ---------------------------------------------------------------------------
// TLS (self-signed for testing)
// ---------------------------------------------------------------------------

fn generate_self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivatePkcs8KeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .context("generating self-signed cert")?;
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    Ok((vec![cert_der], key_der))
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

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
                    "quic-echo — QUIC echo server with QUIC-LB compliant CIDs\n\n\
                     Usage: quic-echo --config <lb.toml> --server-id <hex>\n\n\
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

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

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
        "quic-echo: config_id={}, server_id={}, cid_len={cid_len}, \
         encryption={enc_label}, listen={}",
        params.config_id, args.server_id, args.listen,
    );

    // -- TLS --
    let (certs, key) = generate_self_signed_cert()?;
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key.into())
        .context("TLS config")?;
    tls_config.alpn_protocols = vec![b"hq-interop".to_vec(), b"hq-29".to_vec()];

    // -- Quinn transport --
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)).unwrap(),
    ));

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .context("QUIC crypto config")?,
    ));
    server_config.transport_config(Arc::new(transport));

    // -- Endpoint with QUIC-LB CID generator --
    //
    // Quinn calls the factory once per connection to get a fresh generator
    // instance. We clone the config params into the closure.
    let config_id = params.config_id;
    let server_id = params.server_id;
    let nonce_length = params.nonce_length;
    let encryption = params.encryption;
    let encode_cid_length = params.encode_cid_length;

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

    let socket = UdpSocket::bind(args.listen).context("binding UDP socket")?;
    let endpoint = Endpoint::new(
        ep_config,
        Some(server_config),
        socket,
        quinn::default_runtime()
            .ok_or_else(|| anyhow::anyhow!("no async runtime"))?,
    )
    .context("creating endpoint")?;

    eprintln!("quic-echo: listening on {}", endpoint.local_addr()?);

    // -- Accept loop --
    let accept_loop = async {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                if let Err(e) = handle_connection(incoming).await {
                    eprintln!("quic-echo: connection error: {e:#}");
                }
            });
        }
    };

    tokio::select! {
        _ = accept_loop => {}
        _ = signal::ctrl_c() => {
            eprintln!("\nquic-echo: shutting down");
        }
    }

    endpoint.close(0u32.into(), b"bye");
    
    Ok(())
}

async fn handle_connection(incoming: quinn::Incoming) -> Result<()> {
    let conn = incoming.await.context("accepting connection")?;
    let remote = conn.remote_address();

    eprintln!("quic-echo: new connection from {remote}");

    loop {
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                tokio::spawn(async move {
                    match recv.read_to_end(64 * 1024).await {
                        Ok(data) => {
                            eprintln!("quic-echo: [{remote}] echo {len} bytes", len = data.len());
                            let _ = send.write_all(&data).await;
                            let _ = send.finish();
                        }
                        Err(e) => {
                            eprintln!("quic-echo: [{remote}] recv error: {e}");
                        }
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                eprintln!("quic-echo: [{remote}] closed");
                return Ok(());
            }
            Err(e) => return Err(e).context("accepting stream"),
        }
    }
}
