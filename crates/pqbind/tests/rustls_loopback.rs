#![cfg(feature = "rustls")]
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Prove the rustls adapter over real TLS 1.3 on the loopback interface: the honest pair, the stolen TLS key, refusals, exporter properties and peer identities.

mod common;

use std::sync::Arc;

use common::rustls_net::{self, tls_pair};
use common::{Tls, identity};
use pqbind::adapters::rustls::{frames, peer_id};
use pqbind::{ClientRegistry, Error, Established, FrameIo, HybridIdentity, MemoryRegistry, PeerId, Pin, accept, connect};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

const APP: &[u8] = b"rustls-test/v1";

/// A client enrolled for the anonymous transport identity (it presents no certificate), and the server's identity and pin.
struct World {
    client: HybridIdentity,
    server: HybridIdentity,
    server_pin: Pin,
    registry: MemoryRegistry,
}

fn world() -> World {
    let server = identity(2);
    let client = identity(1);
    World { registry: common::registry_for(&client, PeerId::anonymous()), server_pin: server.pin(), client, server }
}

type Ends = (Result<Established, Error>, Result<Established, Error>);

/// Run the handshake over a fresh TLS connection. `server` is the hybrid identity the server end uses.
async fn handshake(
    tls: &Tls,
    w: &World,
    server: &HybridIdentity,
    client_label: &[u8],
    server_label: &[u8],
    registry: &dyn ClientRegistry,
) -> Ends {
    let (client_tls, server_tls) = tls_pair(tls).await;
    let client_peer = peer_id(&server_tls);
    let server_peer = peer_id(&client_tls);
    let mut client_io = frames(client_tls, client_label).expect("client frames");
    let mut server_io = frames(server_tls, server_label).expect("server frames");
    let (anonymous, server_id) = (PeerId::anonymous(), tls.id());
    tokio::join!(
        connect(&mut client_io, &w.client, &anonymous, &server_peer, &w.server_pin),
        accept(&mut server_io, server, &server_id, &client_peer, registry),
    )
}

#[tokio::test]
async fn a_tls_1_2_connection_is_refused_because_its_exporter_is_not_bound_to_the_whole_handshake() {
    let tls = Tls::new();
    let server_config = rustls::ServerConfig::builder_with_provider(rustls_net::provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(vec![rustls_net::cert(&tls)], rustls_net::private_key(&tls))
        .expect("server config");
    let client_config = rustls::ClientConfig::builder_with_provider(rustls_net::provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("versions")
        .with_root_certificates(rustls_net::roots(&tls))
        .with_no_client_auth();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let connector = TlsConnector::from(Arc::new(client_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let client = async {
        let tcp = TcpStream::connect(addr).await.expect("connect");
        connector.connect(ServerName::try_from("localhost").expect("name"), tcp).await.expect("tls 1.2 client")
    };
    let server = async {
        let (tcp, _) = listener.accept().await.expect("accept");
        acceptor.accept(tcp).await.expect("tls 1.2 server")
    };
    let (client, server) = tokio::join!(client, server);
    let (client, server): (TlsStream<TcpStream>, TlsStream<TcpStream>) = (client.into(), server.into());
    // The connection really is TLS 1.2, so the refusal below is about the version and not about a failed handshake.
    assert_eq!(client.get_ref().1.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_2));
    assert_eq!(frames(client, APP).err(), Some(Error::Unsupported));
    assert_eq!(frames(server, APP).err(), Some(Error::Unsupported));
}

#[tokio::test]
async fn the_honest_pair_authenticates_and_then_carries_application_bytes_both_ways() {
    let tls = Tls::new();
    let w = world();
    let (client_tls, server_tls) = tls_pair(&tls).await;
    let client_peer = peer_id(&server_tls);
    let server_peer = peer_id(&client_tls);
    let mut client_io = frames(client_tls, APP).expect("client frames");
    let mut server_io = frames(server_tls, APP).expect("server frames");
    let (anonymous, server_id) = (PeerId::anonymous(), tls.id());
    let (client_side, server_side) = tokio::join!(
        connect(&mut client_io, &w.client, &anonymous, &server_peer, &w.server_pin),
        accept(&mut server_io, &w.server, &server_id, &client_peer, &w.registry),
    );
    let client_side = client_side.expect("the client accepts the server");
    let server_side = server_side.expect("the server accepts the client");
    assert_eq!(client_side.peer_key(), &w.server.public());
    assert_eq!(client_side.peer_id(), &tls.id());
    assert_eq!(server_side.peer_key(), &w.client.public());
    assert_eq!(server_side.peer_id(), &PeerId::anonymous());

    // Application data on the same streams, after the handshake.
    let (mut client_read, mut client_write) = client_io.into_parts();
    let (mut server_read, mut server_write) = server_io.into_parts();
    client_write.write_all(b"ping from the client").await.expect("write");
    client_write.flush().await.expect("flush");
    let mut got = [0_u8; 20];
    server_read.read_exact(&mut got).await.expect("read");
    assert_eq!(&got, b"ping from the client");
    server_write.write_all(b"pong from the server").await.expect("write");
    server_write.flush().await.expect("flush");
    client_read.read_exact(&mut got).await.expect("read");
    assert_eq!(&got, b"pong from the server");
}

#[tokio::test]
async fn an_attacker_with_the_stolen_tls_key_but_a_different_hybrid_identity_fails_the_pin() {
    let tls = Tls::new();
    let w = world();
    let attacker = identity(9);

    // The attacker holds the same TLS certificate and private key, so the TLS handshake completes for the client. It then answers
    // the client's HELLO with a proof made by its own hybrid key, which carries its own pin.
    let (client_tls, server_tls) = tls_pair(&tls).await;
    let server_peer = peer_id(&client_tls);
    let mut client_io = frames(client_tls, APP).expect("client frames");
    let mut attacker_io = frames(server_tls, APP).expect("attacker frames");
    let anonymous = PeerId::anonymous();
    let (client_side, ()) = tokio::join!(connect(&mut client_io, &w.client, &anonymous, &server_peer, &w.server_pin), async {
        let hello = attacker_io.recv().await.expect("hello");
        assert_eq!(hello.first(), Some(&0x01));
        let (client_pin, attacker_pin) = (w.client.pin(), attacker.pin());
        let server_id = tls.id();
        let transcript = pqbind::Transcript {
            binding: attacker_io.binding(),
            client_id: &anonymous,
            server_id: &server_id,
            client_pin: &client_pin,
            server_pin: &attacker_pin,
        };
        let proof = pqbind::proof::prove(pqbind::Role::Server, &attacker, &transcript).expect("proof");
        let mut reply = vec![0x02];
        reply.extend_from_slice(attacker.public().as_bytes());
        reply.extend_from_slice(&proof);
        attacker_io.send(&reply).await.expect("send");
    });
    assert_eq!(client_side.err(), Some(Error::ServerIdentity));

    // An attacker that runs the real `accept` is refused instead: the client's proof names the pinned key, not the attacker's.
    let (client_side, _) = handshake(&tls, &w, &attacker, APP, APP, &w.registry).await;
    assert_eq!(client_side.err(), Some(Error::Refused));

    // The positive control: the same setup with the real hybrid identity succeeds.
    let (client_side, server_side) = handshake(&tls, &w, &w.server, APP, APP, &w.registry).await;
    client_side.expect("the real server is accepted");
    server_side.expect("the client is accepted");
}

#[tokio::test]
async fn a_client_that_is_not_enrolled_is_refused_and_both_ends_see_it() {
    let tls = Tls::new();
    let w = world();
    let (client_side, server_side) = handshake(&tls, &w, &w.server, APP, APP, &MemoryRegistry::new()).await;
    assert_eq!(server_side.err(), Some(Error::Refused));
    assert_eq!(client_side.err(), Some(Error::Refused));
}

#[tokio::test]
async fn the_two_ends_read_equal_exporter_values_and_two_connections_read_different_ones() {
    let tls = Tls::new();
    let (client_a, server_a) = tls_pair(&tls).await;
    let (client_b, server_b) = tls_pair(&tls).await;
    let client_a = frames(client_a, APP).expect("frames");
    let server_a = frames(server_a, APP).expect("frames");
    let client_b = frames(client_b, APP).expect("frames");
    let server_b = frames(server_b, APP).expect("frames");
    assert_eq!(client_a.binding().exporter(), server_a.binding().exporter());
    assert_eq!(client_b.binding().exporter(), server_b.binding().exporter());
    assert_ne!(client_a.binding().exporter(), client_b.binding().exporter());
    assert_ne!(client_a.binding().exporter(), &[0_u8; pqbind::EXPORTER_LEN], "the value is not left empty");
}

#[tokio::test]
async fn different_application_labels_fail_the_handshake_on_both_ends() {
    let tls = Tls::new();
    let w = world();
    let (client_side, server_side) = handshake(&tls, &w, &w.server, b"app-one/v1", b"app-two/v1", &w.registry).await;
    assert_eq!(server_side.err(), Some(Error::Refused));
    assert_eq!(client_side.err(), Some(Error::Refused));
}

#[tokio::test]
async fn peer_id_is_anonymous_without_a_client_certificate_and_the_certificate_hash_for_the_server() {
    let tls = Tls::new();
    let (client_tls, server_tls) = tls_pair(&tls).await;
    assert_eq!(peer_id(&server_tls), PeerId::anonymous(), "the client presented no certificate");
    assert_eq!(peer_id(&client_tls), PeerId::of_certificate(&tls.cert_der));
    assert!(!peer_id(&client_tls).is_anonymous());
}

#[tokio::test]
async fn an_empty_application_label_is_refused_before_any_bytes_move() {
    let tls = Tls::new();
    let (client_tls, _server_tls) = tls_pair(&tls).await;
    assert_eq!(frames(client_tls, b"").err(), Some(Error::InvalidInput));
}

// A TLS 1.2 refusal test is not written: it needs a TLS 1.2 pair, which needs the rustls `tls12` feature, and the workspace
// builds rustls without it. `frames` returns `Error::Unsupported` for any version other than TLS 1.3.
