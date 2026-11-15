// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Hold the helpers the pqbind integration tests share: in-memory frame channels, a scripted peer, seeded identities, a client and server world, the forging helper, and (behind the adapter features) the loopback TLS, QUIC and iroh setups.

#![allow(dead_code, reason = "each test binary uses only part of this shared module")]

use std::collections::VecDeque;
use std::future::Future;
use std::time::Duration;

use pqbind::proof::{self, Role, Transcript};
use pqbind::{
    Binding, ClientRegistry, EXPORTER_LEN, Enrollment, Error, Established, FrameError, FrameIo, HybridIdentity, MemoryRegistry, PeerId, Pin,
};
use tokio::sync::mpsc;

/// The first byte of a HELLO frame.
pub const HELLO: u8 = 0x01;
/// The first byte of a SERVER_PROOF frame.
pub const SERVER_PROOF: u8 = 0x02;
/// The whole REFUSED frame.
pub const REFUSED: u8 = 0x03;

/// The application label the in-memory tests read their exporter values under.
pub const APP_LABEL: &[u8] = b"test-app/v1";

/// A binding under [`APP_LABEL`] whose exporter value is `exporter` repeated.
pub fn binding(exporter: u8) -> Binding {
    Binding::new(APP_LABEL, [exporter; EXPORTER_LEN]).expect("binding")
}

/// One end of an in-memory channel. Each end has its own binding, so a test can give the two ends the same exporter value (one
/// connection) or different ones (two connections joined by a relay).
pub struct MemoryFrames {
    binding: Binding,
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
}

impl FrameIo for MemoryFrames {
    fn binding(&self) -> &Binding {
        &self.binding
    }

    async fn send(&mut self, frame: &[u8]) -> Result<(), FrameError> {
        self.tx.send(frame.to_vec()).await.map_err(|_| FrameError)
    }

    async fn recv(&mut self) -> Result<Vec<u8>, FrameError> {
        self.rx.recv().await.ok_or(FrameError)
    }
}

/// A connected pair `(client end, server end)` whose ends hold these bindings.
pub fn memory_pair(client: Binding, server: Binding) -> (MemoryFrames, MemoryFrames) {
    let (to_server, from_client) = mpsc::channel(8);
    let (to_client, from_server) = mpsc::channel(8);
    (MemoryFrames { binding: client, tx: to_server, rx: from_server }, MemoryFrames { binding: server, tx: to_client, rx: from_client })
}

/// A connected pair `(client end, server end)` whose ends read these exporter values.
pub fn channel(client_exporter: u8, server_exporter: u8) -> (MemoryFrames, MemoryFrames) {
    memory_pair(binding(client_exporter), binding(server_exporter))
}

/// A channel that returns canned frames and records what was sent.
pub struct Scripted {
    binding: Binding,
    incoming: VecDeque<Vec<u8>>,
    pub sent: Vec<Vec<u8>>,
}

impl Scripted {
    pub fn new(incoming: Vec<Vec<u8>>) -> Self {
        Self { binding: Binding::new(b"fuzz/v1", [5; EXPORTER_LEN]).expect("binding"), incoming: incoming.into(), sent: Vec::new() }
    }
}

impl FrameIo for Scripted {
    fn binding(&self) -> &Binding {
        &self.binding
    }

    async fn send(&mut self, frame: &[u8]) -> Result<(), FrameError> {
        self.sent.push(frame.to_vec());
        Ok(())
    }

    async fn recv(&mut self) -> Result<Vec<u8>, FrameError> {
        self.incoming.pop_front().ok_or(FrameError)
    }
}

/// A single-threaded runtime, for tests that are not `#[tokio::test]` (the property tests).
pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime")
}

/// Fail a test that hangs instead of waiting forever.
pub async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), future).await.expect("the step finished in time")
}

/// The hybrid identity of the seed `[fill; 32]`.
pub fn identity(fill: u8) -> HybridIdentity {
    HybridIdentity::from_seed(&[fill; 32]).expect("seed")
}

/// A transport identity from bytes.
pub fn peer(name: &[u8]) -> PeerId {
    PeerId::new(name).expect("peer id")
}

/// A registry that enrolls `client` for the transport identity `client_id`.
pub fn registry_for(client: &HybridIdentity, client_id: PeerId) -> MemoryRegistry {
    let registry = MemoryRegistry::new();
    registry.enroll(Enrollment { key: client.public(), peer_id: client_id, enrolled_at_unix_millis: 0 });
    registry
}

/// A server, a client enrolled with it, and the two transport identities.
pub struct World {
    pub client: HybridIdentity,
    pub server: HybridIdentity,
    pub server_pin: Pin,
    pub registry: MemoryRegistry,
    pub client_id: PeerId,
    pub server_id: PeerId,
}

pub fn world() -> World {
    let server = identity(2);
    let client = identity(1);
    let client_id = peer(b"client-node");
    World {
        server_pin: server.pin(),
        registry: registry_for(&client, client_id.clone()),
        client,
        server,
        client_id,
        server_id: peer(b"server-node"),
    }
}

/// Run the client and the server of `w` against each other over `ends`, the client holding `pin` and the server `registry`.
pub async fn run(
    w: &World,
    pin: &Pin,
    ends: (MemoryFrames, MemoryFrames),
    registry: &dyn ClientRegistry,
) -> (Result<Established, Error>, Result<Established, Error>) {
    let (mut client_io, mut server_io) = ends;
    tokio::join!(
        pqbind::connect(&mut client_io, &w.client, &w.client_id, &w.server_id, pin),
        pqbind::accept(&mut server_io, &w.server, &w.server_id, &w.client_id, registry),
    )
}

/// What an attacker can build: a hybrid proof whose Ed25519 half comes from `ed_seed` and whose ML-DSA half comes from `ml_dsa_seed`.
/// It rebuilds the signed bytes with the crate's own public functions, so it signs exactly what a real proof signs.
pub fn forged_proof(role: Role, ed_seed: &[u8; 32], ml_dsa_seed: &[u8; 32], transcript: &Transcript<'_>) -> Vec<u8> {
    let signed = pqbind_crypto::hybrid::signed_bytes(&proof::transcript_bytes(role, transcript));
    let classical = pqbind_crypto::sign::SigningKey::from_seed(ed_seed).sign(&signed);
    let post_quantum = pqbind_crypto::hybrid::ml_dsa_key_of_seed(ml_dsa_seed).expect("seed").sign(&signed).expect("sign");
    let mut out = pqbind_crypto::suite::SignatureSuite::Ed25519MlDsa87.id().to_be_bytes().to_vec();
    out.extend_from_slice(&classical.to_bytes());
    out.extend_from_slice(post_quantum.as_bytes());
    out
}

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
        write!(out, "{byte:02x}").expect("writing to a string");
        out
    })
}

/// The bytes of a hex string (either case).
pub fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "hex has an even number of digits");
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16).expect("a hex digit pair"))
        .collect()
}

/// A self-signed TLS certificate for `localhost` and its private key, as DER bytes, shared by the adapter tests.
#[derive(Clone)]
pub struct Tls {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

impl Tls {
    pub fn new() -> Self {
        let made = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("certificate");
        Self { cert_der: made.cert.der().to_vec(), key_der: made.signing_key.serialize_der() }
    }

    /// The transport identity of this certificate, as a peer computes it for the end that presented it.
    pub fn id(&self) -> PeerId {
        PeerId::of_certificate(&self.cert_der)
    }
}

/// Real QUIC over the loopback interface.
#[cfg(feature = "quinn")]
pub mod quinn_net {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use ::quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use ::quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use ::quinn::{ClientConfig, Connection, Endpoint, ServerConfig};

    use super::{Tls, within};

    const LOOPBACK: &str = "127.0.0.1:0";

    fn cert(tls: &Tls) -> CertificateDer<'static> {
        CertificateDer::from(tls.cert_der.clone())
    }

    fn provider() -> Arc<::quinn::rustls::crypto::CryptoProvider> {
        Arc::new(::quinn::rustls::crypto::aws_lc_rs::default_provider())
    }

    fn server_endpoint(tls: &Tls) -> Endpoint {
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(tls.key_der.clone()));
        let rustls_config = ::quinn::rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&::quinn::rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_no_client_auth()
            .with_single_cert(vec![cert(tls)], key)
            .expect("server certificate");
        let config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(rustls_config).expect("QUIC server config")));
        Endpoint::server(config, LOOPBACK.parse().expect("address")).expect("server endpoint")
    }

    fn client_endpoint(trusted: &Tls) -> Endpoint {
        let mut roots = ::quinn::rustls::RootCertStore::empty();
        roots.add(cert(trusted)).expect("trust the certificate");
        let rustls_config = ::quinn::rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&::quinn::rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth();
        let config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_config).expect("QUIC client config")));
        let mut endpoint = Endpoint::client(LOOPBACK.parse().expect("address")).expect("client endpoint");
        endpoint.set_default_client_config(config);
        endpoint
    }

    /// A server endpoint and a client endpoint that trusts `tls`, both on 127.0.0.1.
    pub struct Net {
        pub server: Endpoint,
        pub client: Endpoint,
        pub addr: SocketAddr,
        pub tls: Tls,
    }

    impl Net {
        pub fn new(tls: &Tls) -> Self {
            let server = server_endpoint(tls);
            let addr = server.local_addr().expect("server address");
            assert!(addr.ip().is_loopback(), "the server is bound to loopback only");
            Self { client: client_endpoint(tls), server, addr, tls: tls.clone() }
        }

        /// Open one QUIC connection: `(client end, server end)`.
        pub async fn connection(&self) -> (Connection, Connection) {
            let client = async { self.client.connect(self.addr, "localhost").expect("connect").await.expect("client handshake") };
            let server = async { self.server.accept().await.expect("incoming").await.expect("server handshake") };
            within(async { tokio::join!(client, server) }).await
        }
    }
}

/// Real TLS over TCP on the loopback interface.
#[cfg(feature = "rustls")]
pub mod rustls_net {
    use std::sync::Arc;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

    use super::Tls;

    pub fn cert(tls: &Tls) -> CertificateDer<'static> {
        CertificateDer::from(tls.cert_der.clone())
    }

    pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }

    pub fn private_key(tls: &Tls) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(tls.key_der.clone()))
    }

    pub fn roots(tls: &Tls) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert(tls)).expect("root");
        roots
    }

    pub fn acceptor(tls: &Tls) -> TlsAcceptor {
        let config = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert(tls)], private_key(tls))
            .expect("server config");
        TlsAcceptor::from(Arc::new(config))
    }

    pub fn connector(tls: &Tls) -> TlsConnector {
        let config = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("versions")
            .with_root_certificates(roots(tls))
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    }

    /// One real TLS 1.3 connection over 127.0.0.1: `(client end, server end)`.
    pub async fn tls_pair(tls: &Tls) -> (TlsStream<TcpStream>, TlsStream<TcpStream>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let acceptor = acceptor(tls);
        let connector = connector(tls);
        let client = async {
            let tcp = TcpStream::connect(addr).await.expect("connect");
            let name = ServerName::try_from("localhost").expect("name");
            connector.connect(name, tcp).await.expect("tls client")
        };
        let server = async {
            let (tcp, _) = listener.accept().await.expect("accept");
            acceptor.accept(tcp).await.expect("tls server")
        };
        let (client, server) = tokio::join!(client, server);
        (client.into(), server.into())
    }
}

/// Real iroh QUIC on the loopback interface.
///
/// No test can reach another machine or listen on another interface. Every endpoint is built by [`loopback_endpoint`]: its only
/// socket is bound to 127.0.0.1, the relay is disabled, there is no address lookup (no DNS, no mDNS, no pkarr), port mapping is off
/// and the network report probes are off. The helper also asserts that every bound socket is a loopback address.
#[cfg(feature = "iroh")]
pub mod iroh_net {
    use std::net::Ipv4Addr;

    use iroh::endpoint::{NetReportConfig, PortmapperConfig, presets};
    use iroh::{Endpoint, RelayMode, SecretKey};

    pub const ALPN: &[u8] = b"pqbind-test/iroh/1";

    /// An iroh endpoint that can be reached only on 127.0.0.1: no other socket, no relay, no lookup, no port mapping.
    pub async fn loopback_endpoint(secret: [u8; 32]) -> Endpoint {
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&secret))
            .alpns(vec![ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup()
            .portmapper_config(PortmapperConfig::Disabled)
            .net_report_config(NetReportConfig::minimal())
            .clear_ip_transports()
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .expect("a loopback address")
            .bind()
            .await
            .expect("bind on loopback");
        let sockets = endpoint.bound_sockets();
        assert!(!sockets.is_empty(), "the endpoint has a socket");
        assert!(sockets.iter().all(|socket| socket.ip().is_loopback()), "every socket is on loopback: {sockets:?}");
        endpoint
    }
}
