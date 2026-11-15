// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Teach the whole pqbind flow in one file: two hybrid identities, enrollment and pinning, a real QUIC connection on loopback, the proof exchange, then application data on the same streams.
//!
//! Run it with `cargo run --example quinn_client_server --features quinn`. Everything stays on 127.0.0.1 in one process.

use std::sync::Arc;

use pqbind::adapters::quinn as pq_quinn;
use pqbind::{Enrollment, HybridIdentity, MemoryRegistry, PeerId};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::rustls::crypto::aws_lc_rs::default_provider;
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use quinn::rustls::{ClientConfig as TlsClient, RootCertStore, ServerConfig as TlsServer, version::TLS13};
use quinn::{ClientConfig, Endpoint, ServerConfig};

/// Both ends pass the same label. It is the exporter context and is signed into every proof, so two applications on one transport
/// never share a proof.
const APP_LABEL: &[u8] = b"pqbind-example/v1";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// The lattice signature code keeps large buffers on the stack: ML-DSA-87 key expansion alone needs about 1 MiB in a debug build
// (measured on Windows, see `crates/pqbind-cli/examples/stack_probe.rs`), which is more than the 1 MiB main thread of a Windows
// process has. This example runs on a thread with 4 MiB, a few times the measured need.
fn main() -> Result<()> {
    let runner = std::thread::Builder::new().stack_size(4 * 1024 * 1024).spawn(|| {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|error| error.to_string())?;
        runtime.block_on(run()).map_err(|error| error.to_string())
    })?;
    runner.join().map_err(|_| "the example thread panicked")??;
    Ok(())
}

async fn run() -> Result<()> {
    // 1. Each end makes a hybrid Ed25519 + ML-DSA-87 identity. In real use you make it once and keep its 32-byte seed secret.
    let client_key = HybridIdentity::generate()?;
    let server_key = HybridIdentity::generate()?;

    // 2. Enrollment happens before any connection, outside pqbind (a QR code, an admin, a ticket). The server stores the client's
    //    public key; the client keeps the SHA-384 pin of the server's whole public key. A key is never trusted for arriving.
    //    This client presents no TLS certificate, so the transport identity it is enrolled under is the anonymous one.
    let registry = MemoryRegistry::new();
    registry.enroll(Enrollment { key: client_key.public(), peer_id: PeerId::anonymous(), enrolled_at_unix_millis: 0 });
    let server_pin = server_key.pin();
    println!("enrolled the client; the client pinned the server: {}...", &server_pin.to_hex()[..16]);

    // 3. An ordinary QUIC setup: a self-signed certificate and TLS 1.3. This is the classical authentication that pqbind adds to.
    //    pqbind assumes the key exchange is post-quantum but does not check it. This example does not choose or check a group; a real
    //    deployment must configure a post-quantum group on both ends and confirm it.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let tls_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let provider = Arc::new(default_provider());
    let server_tls = TlsServer::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], tls_key)?;
    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone())?;
    let client_tls =
        TlsClient::builder_with_provider(provider).with_protocol_versions(&[&TLS13])?.with_root_certificates(roots).with_no_client_auth();

    let server_endpoint =
        Endpoint::server(ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls)?)), "127.0.0.1:0".parse()?)?;
    let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    client_endpoint.set_default_client_config(ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls)?)));
    let server_addr = server_endpoint.local_addr()?;
    println!("QUIC server listening on {server_addr}");

    // The transport identity of the server is the SHA-384 of its certificate, which both ends can compute.
    let server_id = PeerId::of_certificate(&cert_der);

    // 4. Run the two ends side by side. Each end proves itself over the connection's own TLS exporter value.
    let server_side = async {
        let connection = server_endpoint.accept().await.ok_or("no incoming connection")?.await?;
        println!("[server] QUIC handshake done");
        // `accept` returns once the client sends its first frame, which is pqbind's HELLO.
        let mut frames = pq_quinn::accept(&connection, APP_LABEL).await?;
        let client_id = pq_quinn::peer_id(&connection); // anonymous: the client sent no certificate
        let established = pqbind::accept(&mut frames, &server_key, &server_id, &client_id, &registry).await?;
        println!("[server] the client proved an enrolled key (pin {}...)", &established.peer_key().pin().to_hex()[..16]);

        // 5. Only now is application data allowed. The same stream carries it: take the raw halves back.
        let (mut recv, mut send) = frames.into_parts();
        let line = recv.read_to_end(1024).await?;
        println!("[server] received: {}", String::from_utf8_lossy(&line).trim_end());
        send.write_all(b"hello client, you are authenticated\n").await?;
        send.finish()?;
        connection.closed().await; // keep the connection until the client has read the reply
        Result::Ok(())
    };
    let client_side = async {
        let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
        println!("[client] QUIC handshake done");
        let mut frames = pq_quinn::open(&connection, APP_LABEL).await?;
        let server_id = pq_quinn::peer_id(&connection); // the certificate hash the TLS handshake authenticated
        let established = pqbind::connect(&mut frames, &client_key, &PeerId::anonymous(), &server_id, &server_pin).await?;
        println!("[client] the server proved the pinned key (pin {}...)", &established.peer_key().pin().to_hex()[..16]);

        let (mut recv, mut send) = frames.into_parts();
        send.write_all(b"hello server, this is the enrolled client\n").await?;
        send.finish()?;
        let line = recv.read_to_end(1024).await?;
        println!("[client] received: {}", String::from_utf8_lossy(&line).trim_end());
        connection.close(0_u8.into(), b"done");
        Result::Ok(())
    };
    let (server_done, client_done) = tokio::join!(server_side, client_side);
    server_done?;
    client_done?;
    println!("done: both ends authenticated before any application byte was sent");
    Ok(())
}
