// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Run the whole pqbind handshake over real iroh QUIC connections on the loopback interface: an honest pair succeeds, a wrong hybrid identity is refused.
//!
//! No test here can reach another machine or listen on another interface. Every endpoint is built by [`loopback_endpoint`]: its only
//! socket is bound to 127.0.0.1, the relay is disabled, there is no address lookup (no DNS, no mDNS, no pkarr), port mapping is off
//! and the network report probes are off. The helper also asserts that every bound socket is a loopback address.

#![cfg(feature = "iroh")]

mod common;

use std::time::Duration;

use common::identity;
use common::iroh_net::{ALPN, loopback_endpoint};
use iroh::{Endpoint, EndpointAddr};
use pqbind::adapters::iroh as adapter;
use pqbind::{Enrollment, Error, Established, HybridIdentity, MemoryRegistry, PeerId, Pin, PublicIdentity};

const LABEL: &[u8] = b"pqbind-test/iroh-adapter/v1";
const WAIT: Duration = Duration::from_secs(60);
const LINGER: Duration = Duration::from_secs(10);

/// What one end saw: the result of the pqbind handshake, and the application bytes it received afterwards (only after success).
struct End {
    established: Result<Established, Error>,
    app_data: Option<Vec<u8>>,
}

impl End {
    /// The error the handshake ended in, if it failed.
    fn error(&self) -> Option<Error> {
        self.established.as_ref().err().copied()
    }
}

struct Outcome {
    server: End,
    client: End,
    server_node: PeerId,
    client_node: PeerId,
}

async fn serve(endpoint: Endpoint, me: HybridIdentity, registry: MemoryRegistry) -> End {
    let incoming = endpoint.accept().await.expect("an incoming connection");
    let connection = incoming.await.expect("the QUIC handshake");
    let mut io = adapter::accept(&connection, LABEL).await.expect("the stream");
    let established = pqbind::accept(&mut io, &me, &adapter::own_id(&endpoint), &adapter::peer_id(&connection), &registry).await;
    let mut app_data = None;
    if established.is_ok() {
        // After the handshake the same streams carry application data.
        let (mut reader, mut writer) = io.into_parts();
        let mut ping = [0_u8; 4];
        reader.read_exact(&mut ping).await.expect("application data from the client");
        writer.write_all(b"pong").await.expect("the reply");
        app_data = Some(ping.to_vec());
    }
    // Keep the connection until the client has read everything and closed it: dropping the last handle would cut unsent data.
    let _ = tokio::time::timeout(LINGER, connection.closed()).await;
    End { established, app_data }
}

async fn dial(endpoint: Endpoint, server: EndpointAddr, me: HybridIdentity, server_pin: Pin) -> End {
    let connection = endpoint.connect(server, ALPN).await.expect("the QUIC handshake");
    let mut io = adapter::open(&connection, LABEL).await.expect("the stream");
    let established = pqbind::connect(&mut io, &me, &adapter::own_id(&endpoint), &adapter::peer_id(&connection), &server_pin).await;
    let mut app_data = None;
    if established.is_ok() {
        let (mut reader, mut writer) = io.into_parts();
        writer.write_all(b"ping").await.expect("application data to the server");
        let mut pong = [0_u8; 4];
        reader.read_exact(&mut pong).await.expect("the reply");
        app_data = Some(pong.to_vec());
    }
    connection.close(0_u32.into(), b"done");
    End { established, app_data }
}

/// One server and one client on loopback. `enroll` is given the client's iroh node id and returns what the server's registry holds.
async fn run(
    server_hybrid: HybridIdentity,
    client_hybrid: HybridIdentity,
    pin_the_client_holds: Pin,
    enroll: impl FnOnce(&PeerId) -> Option<Enrollment>,
) -> Outcome {
    tokio::time::timeout(WAIT, async {
        let server_endpoint = loopback_endpoint([0xA1; 32]).await;
        let client_endpoint = loopback_endpoint([0xB2; 32]).await;
        let server_node = adapter::own_id(&server_endpoint);
        let client_node = adapter::own_id(&client_endpoint);
        let registry = MemoryRegistry::new();
        if let Some(enrollment) = enroll(&client_node) {
            registry.enroll(enrollment);
        }
        let server_addr = server_endpoint.bound_sockets().into_iter().next().expect("a server socket");
        let target = EndpointAddr::new(server_endpoint.id()).with_ip_addr(server_addr);

        let server = tokio::spawn(serve(server_endpoint.clone(), server_hybrid, registry));
        let client = dial(client_endpoint.clone(), target, client_hybrid, pin_the_client_holds).await;
        let server = server.await.expect("the server task");
        client_endpoint.close().await;
        server_endpoint.close().await;
        Outcome { server, client, server_node, client_node }
    })
    .await
    .expect("the exchange finished in time")
}

fn enrolled(key: PublicIdentity, node: PeerId) -> Option<Enrollment> {
    Some(Enrollment { key, peer_id: node, enrolled_at_unix_millis: 0 })
}

fn assert_nothing_crossed(outcome: &Outcome) {
    assert!(outcome.server.app_data.is_none(), "the server got no application data");
    assert!(outcome.client.app_data.is_none(), "the client got no application data");
}

#[tokio::test]
async fn an_honest_pair_authenticates_each_other_over_iroh_and_then_exchanges_data() {
    let (server, client) = (identity(1), identity(2));
    let (server_public, client_public, pin) = (server.public(), client.public(), server.pin());
    let outcome = run(server, client, pin, |node| enrolled(client_public.clone(), node.clone())).await;

    let on_server = outcome.server.established.expect("the server accepts the client");
    let on_client = outcome.client.established.expect("the client accepts the server");
    assert_eq!(on_server.peer_key(), &client_public);
    assert_eq!(on_client.peer_key(), &server_public);
    assert_eq!(on_server.peer_id(), &outcome.client_node, "the server saw the client's iroh node id");
    assert_eq!(on_client.peer_id(), &outcome.server_node, "the client saw the server's iroh node id");
    assert_eq!(outcome.client_node.as_bytes().len(), 32);
    assert_ne!(outcome.client_node, outcome.server_node);
    assert_eq!(outcome.server.app_data.as_deref(), Some(b"ping".as_slice()));
    assert_eq!(outcome.client.app_data.as_deref(), Some(b"pong".as_slice()));
}

#[tokio::test]
async fn a_client_whose_hybrid_key_is_not_enrolled_is_refused_before_any_application_data() {
    let (server, stranger, other) = (identity(1), identity(3), identity(4));
    let pin = server.pin();
    // Only a different key is enrolled for this node, so the stranger's valid proof is still refused.
    let outcome = run(server, stranger, pin, |node| enrolled(other.public(), node.clone())).await;
    assert_eq!(outcome.server.error(), Some(Error::Refused));
    assert_eq!(outcome.client.error(), Some(Error::Refused));
    assert_nothing_crossed(&outcome);
}

#[tokio::test]
async fn an_enrolled_hybrid_key_used_from_another_iroh_node_is_refused() {
    let (server, client) = (identity(1), identity(2));
    let (client_public, pin) = (client.public(), server.pin());
    // The key is enrolled, but for a different node id than the one this client connects from.
    let elsewhere = PeerId::new([0x5A_u8; 32].as_slice()).expect("an identity");
    let outcome = run(server, client, pin, |_| enrolled(client_public, elsewhere)).await;
    assert_eq!(outcome.server.error(), Some(Error::Refused));
    assert_eq!(outcome.client.error(), Some(Error::Refused));
    assert_nothing_crossed(&outcome);
}

#[tokio::test]
async fn a_client_that_pinned_another_server_key_does_not_get_through() {
    let (server, client, impostor) = (identity(1), identity(2), identity(9));
    let client_public = client.public();
    // The client holds the pin of a different server key, as if it reached an impostor of the server it enrolled with.
    let outcome = run(server, client, impostor.pin(), |node| enrolled(client_public.clone(), node.clone())).await;
    assert!(matches!(outcome.client.error(), Some(Error::Refused | Error::ServerIdentity)), "the client must not accept");
    assert_eq!(outcome.server.error(), Some(Error::Refused));
    assert_nothing_crossed(&outcome);
}
