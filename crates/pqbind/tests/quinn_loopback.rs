// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Prove the quinn adapter over real QUIC on the loopback interface: the honest pair, a stolen TLS key, refusals, the exporter properties and the peer identity.

#![cfg(feature = "quinn")]

mod common;

use common::quinn_net::Net;
use common::{Tls, identity, within};
use pqbind::adapters::quinn as pq_quinn;
use pqbind::proof::{self, Role, Transcript};
use pqbind::{ClientRegistry, Error, Established, FrameIo, HybridIdentity, MemoryRegistry, PeerId, Pin};

const LABEL: &[u8] = b"quinn-test/v1";

/// The client has no TLS certificate, so its transport identity is anonymous; enroll it that way.
fn registry_with(client: &HybridIdentity) -> MemoryRegistry {
    common::registry_for(client, PeerId::anonymous())
}

type Outcome = Result<Established, Error>;

/// Run the pqbind handshake over one fresh connection, with these app labels, and return the results of both ends.
async fn handshake(
    net: &Net,
    client: &HybridIdentity,
    server: &HybridIdentity,
    pin: &Pin,
    registry: &dyn ClientRegistry,
    labels: (&[u8], &[u8]),
) -> (Outcome, Outcome) {
    let (client_conn, server_conn) = net.connection().await;
    let client_side = async {
        let mut frames = pq_quinn::open(&client_conn, labels.0).await?;
        pqbind::connect(&mut frames, client, &PeerId::anonymous(), &pq_quinn::peer_id(&client_conn), pin).await
    };
    let server_side = async {
        let mut frames = pq_quinn::accept(&server_conn, labels.1).await?;
        pqbind::accept(&mut frames, server, &net.tls.id(), &pq_quinn::peer_id(&server_conn), registry).await
    };
    within(async { tokio::join!(client_side, server_side) }).await
}

#[tokio::test]
async fn an_honest_pair_authenticates_and_the_same_streams_carry_application_data() {
    let tls = Tls::new();
    let net = Net::new(&tls);
    let (client_key, server_key) = (identity(1), identity(2));
    let registry = registry_with(&client_key);
    let (client_conn, server_conn) = net.connection().await;

    let client_side = async {
        let mut frames = pq_quinn::open(&client_conn, LABEL).await?;
        let established =
            pqbind::connect(&mut frames, &client_key, &PeerId::anonymous(), &pq_quinn::peer_id(&client_conn), &server_key.pin()).await?;
        Ok::<_, Error>((established, frames.into_parts()))
    };
    let server_side = async {
        let mut frames = pq_quinn::accept(&server_conn, LABEL).await?;
        let established = pqbind::accept(&mut frames, &server_key, &tls.id(), &pq_quinn::peer_id(&server_conn), &registry).await?;
        Ok::<_, Error>((established, frames.into_parts()))
    };
    let (client_result, server_result) = within(async { tokio::join!(client_side, server_side) }).await;
    let (client_established, (mut client_recv, mut client_send)) = client_result.expect("the client accepts the server");
    let (server_established, (mut server_recv, mut server_send)) = server_result.expect("the server accepts the client");

    assert_eq!(client_established.peer_key(), &server_key.public());
    assert_eq!(client_established.peer_id(), &tls.id());
    assert_eq!(server_established.peer_key(), &client_key.public());
    assert!(server_established.peer_id().is_anonymous());

    // The same streams still work after the handshake, both ways.
    within(async {
        client_send.write_all(b"ping").await.expect("client write");
        let mut got = [0_u8; 4];
        server_recv.read_exact(&mut got).await.expect("server read");
        assert_eq!(&got, b"ping");
        server_send.write_all(b"pong!").await.expect("server write");
        let mut got = [0_u8; 5];
        client_recv.read_exact(&mut got).await.expect("client read");
        assert_eq!(&got, b"pong!");
    })
    .await;
}

#[tokio::test]
async fn a_stolen_tls_key_without_the_hybrid_key_is_caught_by_the_client() {
    let tls = Tls::new();
    let (client_key, real_server, attacker) = (identity(1), identity(2), identity(3));
    let registry = registry_with(&client_key);
    let pin = real_server.pin();

    // Sanity check: the real hybrid identity on the same TLS setup succeeds.
    let net = Net::new(&tls);
    let (client_side, server_side) = handshake(&net, &client_key, &real_server, &pin, &registry, (LABEL, LABEL)).await;
    client_side.expect("the real server is accepted");
    server_side.expect("the server accepts the client");

    // The attacker holds the stolen TLS certificate and key but a different hybrid identity. TLS completes; pqbind does not.
    // An attacker running the honest pqbind code cannot even verify the client's HELLO, which signs the real server's pin: refused.
    let net = Net::new(&tls);
    let (client_side, _) = handshake(&net, &client_key, &attacker, &pin, &registry, (LABEL, LABEL)).await;
    assert_eq!(client_side.err(), Some(Error::Refused));

    // An attacker that skips verification and answers with a proof of its own key: the client's pin check catches it.
    let net = Net::new(&tls);
    let (client_conn, server_conn) = net.connection().await;
    let client_side = async {
        let mut frames = pq_quinn::open(&client_conn, LABEL).await?;
        pqbind::connect(&mut frames, &client_key, &PeerId::anonymous(), &pq_quinn::peer_id(&client_conn), &pin).await
    };
    let attacker_side = async {
        let mut frames = pq_quinn::accept(&server_conn, LABEL).await.expect("accept");
        frames.recv().await.expect("hello");
        let (client_pin, attacker_pin) = (client_key.pin(), attacker.pin());
        let (client_id, server_id) = (pq_quinn::peer_id(&server_conn), net.tls.id());
        let transcript = Transcript {
            binding: frames.binding(),
            client_id: &client_id,
            server_id: &server_id,
            client_pin: &client_pin,
            server_pin: &attacker_pin,
        };
        let proof = proof::prove(Role::Server, &attacker, &transcript).expect("proof");
        let mut reply = vec![0x02];
        reply.extend_from_slice(attacker.public().as_bytes());
        reply.extend_from_slice(&proof);
        frames.send(&reply).await.expect("send");
    };
    let (client_side, ()) = within(async { tokio::join!(client_side, attacker_side) }).await;
    assert_eq!(client_side.err(), Some(Error::ServerIdentity));
}

#[tokio::test]
async fn a_client_that_is_not_enrolled_is_refused_on_both_ends() {
    let net = Net::new(&Tls::new());
    let (client_key, server_key) = (identity(1), identity(2));
    let (client_side, server_side) =
        handshake(&net, &client_key, &server_key, &server_key.pin(), &MemoryRegistry::new(), (LABEL, LABEL)).await;
    assert_eq!(server_side.err(), Some(Error::Refused));
    assert_eq!(client_side.err(), Some(Error::Refused));
}

#[tokio::test]
async fn the_two_ends_of_a_connection_read_equal_exporter_values_and_two_connections_differ() {
    let net = Net::new(&Tls::new());

    async fn read_both(net: &Net) -> ([u8; 64], [u8; 64]) {
        let (client_conn, server_conn) = net.connection().await;
        let mut client_frames = pq_quinn::open(&client_conn, LABEL).await.expect("open");
        // The server sees the stream only once the client writes on it.
        client_frames.send(b"hello").await.expect("first frame");
        let server_frames = within(pq_quinn::accept(&server_conn, LABEL)).await.expect("accept");
        (*client_frames.binding().exporter(), *server_frames.binding().exporter())
    }

    let (client_one, server_one) = read_both(&net).await;
    let (client_two, server_two) = read_both(&net).await;
    assert_eq!(client_one, server_one, "one connection, one value");
    assert_eq!(client_two, server_two, "one connection, one value");
    assert_ne!(client_one, client_two, "two connections to one server read different values");
    assert_ne!(client_one, [0_u8; 64], "the value is not left blank");
}

#[tokio::test]
async fn different_app_labels_fail_the_handshake_on_both_ends() {
    let net = Net::new(&Tls::new());
    let (client_key, server_key) = (identity(1), identity(2));
    let registry = registry_with(&client_key);
    let (client_side, server_side) =
        handshake(&net, &client_key, &server_key, &server_key.pin(), &registry, (b"quinn-test/a", b"quinn-test/b")).await;
    assert_eq!(server_side.err(), Some(Error::Refused));
    assert_eq!(client_side.err(), Some(Error::Refused));
}

#[tokio::test]
async fn peer_id_is_anonymous_without_a_certificate_and_the_certificate_hash_with_one() {
    let tls = Tls::new();
    let net = Net::new(&tls);
    let (client_conn, server_conn) = net.connection().await;
    assert_eq!(pq_quinn::peer_id(&server_conn), PeerId::anonymous(), "the client presented no certificate");
    assert!(pq_quinn::peer_id(&server_conn).is_anonymous());
    assert_eq!(pq_quinn::peer_id(&client_conn), PeerId::of_certificate(&tls.cert_der));
    assert_eq!(pq_quinn::peer_id(&client_conn), tls.id());
}
