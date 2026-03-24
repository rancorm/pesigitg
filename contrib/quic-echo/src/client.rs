//! quic-echo-client — Minimal QUIC echo client for testing quic-echo-server
//! and pesigitgd load balancer routing.
//!
//! Usage:
//!     quic-echo-client --connect 127.0.0.1:443 [--count 10] [--message "hello"]
//!
//! Connects over QUIC, sends a message on a bidirectional stream, reads the
//! echo back, and prints the result. Accepts any server certificate (for
//! testing with self-signed certs).

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use quinn::Endpoint;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

// ---------------------------------------------------------------------------
// Insecure cert verifier (for self-signed test certs)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct InsecureCertVerifier;

impl ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
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
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

struct Args {
    connect: SocketAddr,
    count: usize,
    message: String,
}

fn parse_args() -> Result<Args> {
    let mut args = std::env::args().skip(1);
    let mut connect = None;
    let mut count = 1usize;
    let mut message = String::from("hello");

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--connect" | "-c" => {
                let val = args.next().context("--connect requires a value")?;
                connect = Some(val.parse().context("invalid connect address")?);
            }
            "--count" | "-n" => {
                let val = args.next().context("--count requires a value")?;
                count = val.parse().context("invalid count")?;
            }
            "--message" | "-m" => {
                message = args.next().context("--message requires a value")?;
            }
            "--help" | "-h" => {
                eprintln!(
                    "quic-echo-client — QUIC echo client\n\n\
                     Usage: quic-echo-client --connect <ADDR:PORT> [OPTIONS]\n\n\
                     Options:\n  \
                       -c, --connect <ADDR:PORT>  Server address to connect to\n  \
                       -n, --count <N>            Number of echo requests (default: 1)\n  \
                       -m, --message <TEXT>       Message to echo (default: hello)"
                );
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    Ok(Args {
        connect: connect.context("--connect is required")?,
        count,
        message,
    })
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;

    eprintln!("quic-echo-client: connecting to {}", args.connect);

    // -- TLS (trust any cert) --
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"hq-interop".to_vec(), b"hq-29".to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .context("QUIC crypto config")?,
    ));

    // -- Endpoint --
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
        .context("creating endpoint")?;
    endpoint.set_default_client_config(client_config);

    // -- Connect --
    let conn = endpoint
        .connect(args.connect, "localhost")
        .context("initiating connection")?
        .await
        .context("connecting to server")?;

    eprintln!("quic-echo-client: connected");

    // -- Echo loop --
    for i in 0..args.count {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("opening bidirectional stream")?;

        send.write_all(args.message.as_bytes())
            .await
            .context("sending")?;
        send.finish().context("finishing send")?;

        let response = recv.read_to_end(64 * 1024).await.context("receiving")?;
        let text = String::from_utf8_lossy(&response);

        if args.count == 1 {
            println!("{text}");
        } else {
            println!("[{}/{}] {text}", i + 1, args.count);
        }
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    Ok(())
}
