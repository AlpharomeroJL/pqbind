// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Make one TCP connection and one TLS 1.3 handshake offering exactly one key exchange group, and say how it ended.
//!
//! The probe tests key exchange only. It does NOT validate certificates: the verifier below accepts any certificate and any
//! signature, so a successful attempt says nothing about who the server is, and the output says "certificate not validated".

use std::cell::Cell;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use super::classify::{GroupResult, Outcome, ProbeGroup, alert_name, group_name_for_code, snake_head};
use super::kx;

/// A certificate verifier that accepts everything. The probe never validates certificates (see the module comment).
#[derive(Debug)]
struct AcceptAnyCertificate {
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for AcceptAnyCertificate {
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
        self.schemes.clone()
    }
}

/// A TLS 1.3 client configuration that offers `group` alone and accepts any certificate.
fn client_config(group: ProbeGroup) -> Result<ClientConfig, rustls::Error> {
    let provider = kx::provider_with_groups(vec![kx::group_for(group)]);
    let schemes = provider.signature_verification_algorithms.supported_schemes();
    Ok(ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate { schemes }))
        .with_no_client_auth())
}

/// A short fixed label for an I/O error kind. Never the error's text.
fn io_kind(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::ConnectionRefused => "connection_refused",
        io::ErrorKind::ConnectionReset => "connection_reset",
        io::ErrorKind::ConnectionAborted => "connection_aborted",
        io::ErrorKind::NotConnected => "not_connected",
        io::ErrorKind::AddrNotAvailable => "address_not_available",
        io::ErrorKind::NetworkUnreachable => "network_unreachable",
        io::ErrorKind::HostUnreachable => "host_unreachable",
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::BrokenPipe => "broken_pipe",
        io::ErrorKind::UnexpectedEof => "unexpected_eof",
        io::ErrorKind::TimedOut => "timed_out",
        io::ErrorKind::InvalidData => "invalid_data",
        _ => "io_error",
    }
}

/// The outcome of a failed TCP connect.
fn outcome_for_connect_error(error: &io::Error) -> Outcome {
    if error.kind() == io::ErrorKind::TimedOut { Outcome::TimedOut } else { Outcome::Error { kind: io_kind(error.kind()).to_owned() } }
}

/// The outcome of a failed handshake: a TLS alert from the server, a close with no alert, or something else.
fn outcome_for_handshake_error(error: &io::Error) -> Outcome {
    let tls_error = error.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>());
    if let Some(tls_error) = tls_error {
        return match tls_error {
            rustls::Error::AlertReceived(alert) => Outcome::Rejected { alert: alert_name(u8::from(*alert)) },
            other => Outcome::Error { kind: format!("tls_{}", snake_head(&format!("{other:?}"))) },
        };
    }
    match error.kind() {
        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe => {
            Outcome::Reset
        }
        io::ErrorKind::TimedOut => Outcome::TimedOut,
        other => Outcome::Error { kind: io_kind(other).to_owned() },
    }
}

/// Resolve the host. On failure the outcome that every group of this host gets.
pub async fn resolve(host: &str, port: u16, limit: Duration) -> Result<Vec<SocketAddr>, Outcome> {
    match timeout(limit, lookup_host((host, port))).await {
        Err(_) => Err(Outcome::Error { kind: "dns_timeout".to_owned() }),
        Ok(Err(_)) => Err(Outcome::Error { kind: "dns".to_owned() }),
        Ok(Ok(addresses)) => {
            let addresses: Vec<SocketAddr> = addresses.collect();
            if addresses.is_empty() { Err(Outcome::Error { kind: "dns".to_owned() }) } else { Ok(addresses) }
        }
    }
}

/// Connect to the first address that answers; on failure, the error of the last one tried.
async fn connect_any(addresses: &[SocketAddr]) -> Result<TcpStream, io::Error> {
    let mut last = io::Error::from(io::ErrorKind::NotConnected);
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last = error,
        }
    }
    Err(last)
}

/// One attempt, without the time limit. `connected` is set as soon as the TCP connection is up.
async fn attempt(addresses: &[SocketAddr], name: &ServerName<'static>, group: ProbeGroup, connected: &Cell<bool>) -> Outcome {
    let Ok(config) = client_config(group) else {
        return Outcome::Error { kind: "client_config".to_owned() };
    };
    let tcp = match connect_any(addresses).await {
        Ok(stream) => stream,
        Err(error) => return outcome_for_connect_error(&error),
    };
    connected.set(true);
    match TlsConnector::from(Arc::new(config)).connect(name.clone(), tcp).await {
        Ok(stream) => {
            let negotiated =
                stream.get_ref().1.negotiated_key_exchange_group().map(|negotiated| group_name_for_code(u16::from(negotiated.name())));
            Outcome::Accepted { negotiated }
        }
        Err(error) => outcome_for_handshake_error(&error),
    }
}

/// Try one group against one host: connect, handshake, and give up after `limit` for the whole attempt.
pub async fn probe_group(addresses: &[SocketAddr], name: &ServerName<'static>, group: ProbeGroup, limit: Duration) -> GroupResult {
    let started = Instant::now();
    let connected = Cell::new(false);
    let outcome = match timeout(limit, attempt(addresses, name, group, &connected)).await {
        Ok(outcome) => outcome,
        Err(_) => Outcome::TimedOut,
    };
    GroupResult::new(group, outcome, connected.get(), elapsed_ms(started))
}

/// Milliseconds since `started`, saturating.
pub fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
