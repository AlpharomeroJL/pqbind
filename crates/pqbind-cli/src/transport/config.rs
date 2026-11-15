// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Build the TLS 1.3 configurations, the QUIC endpoints and the TLS acceptor and connector the transports use.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::RootCertStore;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::cert::Tls;
use crate::common::{CliResult, fail};

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn server_tls_config(tls: &Tls) -> CliResult<rustls::ServerConfig> {
    rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(fail("TLS 1.3 setup"))?
        .with_no_client_auth()
        .with_single_cert(vec![tls.certificate()], tls.private_key())
        .map_err(fail("the server certificate"))
}

fn client_tls_config(roots: RootCertStore) -> CliResult<rustls::ClientConfig> {
    Ok(rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(fail("TLS 1.3 setup"))?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// A QUIC server endpoint listening on `listen`.
pub(super) fn quic_server_endpoint(tls: &Tls, listen: SocketAddr) -> CliResult<Endpoint> {
    let crypto = QuicServerConfig::try_from(server_tls_config(tls)?).map_err(fail("QUIC server setup"))?;
    Endpoint::server(ServerConfig::with_crypto(Arc::new(crypto)), listen).map_err(fail("cannot listen"))
}

/// A QUIC client endpoint bound to `bind` that trusts `roots`.
pub(super) fn quic_client_endpoint(roots: RootCertStore, bind: SocketAddr) -> CliResult<Endpoint> {
    let crypto = QuicClientConfig::try_from(client_tls_config(roots)?).map_err(fail("QUIC client setup"))?;
    let mut endpoint = Endpoint::client(bind).map_err(fail("cannot open a client socket"))?;
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(crypto)));
    Ok(endpoint)
}

/// A TLS 1.3 acceptor that serves `tls`.
pub(super) fn tls_acceptor(tls: &Tls) -> CliResult<TlsAcceptor> {
    Ok(TlsAcceptor::from(Arc::new(server_tls_config(tls)?)))
}

/// A TLS 1.3 connector that trusts `roots`.
pub(super) fn tls_connector(roots: RootCertStore) -> CliResult<TlsConnector> {
    Ok(TlsConnector::from(Arc::new(client_tls_config(roots)?)))
}

/// The local address a client socket binds to for a connection to `remote`: loopback for a loopback target (so no firewall prompt is
/// triggered), the unspecified address of the same family otherwise.
pub(super) fn client_bind_for(remote: SocketAddr) -> SocketAddr {
    let ip = match (remote.ip().to_canonical(), remote.ip().to_canonical().is_loopback()) {
        (IpAddr::V4(_), true) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        (IpAddr::V4(_), false) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        (IpAddr::V6(_), true) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        (IpAddr::V6(_), false) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    SocketAddr::new(ip, 0)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::client_bind_for;

    fn bind(text: &str) -> SocketAddr {
        client_bind_for(text.parse().expect("an address"))
    }

    #[test]
    fn a_loopback_target_binds_loopback_and_any_other_target_binds_the_unspecified_address() {
        assert_eq!(bind("127.0.0.1:4433"), "127.0.0.1:0".parse().expect("address"));
        assert_eq!(bind("[::1]:4433"), "[::1]:0".parse().expect("address"));
        assert_eq!(bind("[::ffff:127.0.0.1]:4433"), "127.0.0.1:0".parse().expect("address"), "a mapped loopback is loopback");
        assert_eq!(bind("192.168.1.5:4433"), "0.0.0.0:0".parse().expect("address"));
        assert_eq!(bind("[2001:db8::1]:4433"), "[::]:0".parse().expect("address"));
    }
}
