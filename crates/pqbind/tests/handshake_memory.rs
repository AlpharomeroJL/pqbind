// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Prove the handshake end to end over an in-memory channel: the honest pair, every refusal, and the replay, relay and malformed-frame cases.

mod common;

use common::{HELLO, REFUSED, SERVER_PROOF, binding, channel, identity, peer, run, world};
use pqbind::{Error, FrameIo, MemoryRegistry, PublicIdentity, accept, connect};

#[tokio::test]
async fn an_enrolled_client_and_the_pinned_server_authenticate_each_other() {
    let w = world();
    let (client_side, server_side) = run(&w, &w.server_pin, channel(7, 7), &w.registry).await;
    let client_side = client_side.expect("the client accepts the server");
    let server_side = server_side.expect("the server accepts the client");
    assert_eq!(client_side.peer_key(), &w.server.public());
    assert_eq!(client_side.peer_id(), &w.server_id);
    assert_eq!(server_side.peer_key(), &w.client.public());
    assert_eq!(server_side.peer_id(), &w.client_id);
}

#[tokio::test]
async fn a_client_that_was_never_enrolled_is_refused_and_both_ends_see_it() {
    let w = world();
    let (client_side, server_side) = run(&w, &w.server_pin, channel(7, 7), &MemoryRegistry::new()).await;
    assert_eq!(server_side.err(), Some(Error::Refused));
    assert_eq!(client_side.err(), Some(Error::Refused));
}

#[tokio::test]
async fn a_revoked_client_is_refused() {
    let w = world();
    assert!(w.registry.revoke(&w.client.public(), &w.client_id));
    let (client_side, server_side) = run(&w, &w.server_pin, channel(7, 7), &w.registry).await;
    assert_eq!(server_side.err(), Some(Error::Refused));
    assert_eq!(client_side.err(), Some(Error::Refused));
}

#[tokio::test]
async fn an_enrolled_key_used_from_another_transport_identity_is_refused() {
    let mut w = world();
    // The key is enrolled for "client-node"; the transport now says the connection comes from "someone-else".
    w.client_id = peer(b"someone-else");
    let (client_side, server_side) = run(&w, &w.server_pin, channel(7, 7), &w.registry).await;
    assert_eq!(server_side.err(), Some(Error::Refused));
    assert_eq!(client_side.err(), Some(Error::Refused));
}

#[tokio::test]
async fn a_client_that_pinned_a_different_key_is_refused_by_the_real_server_before_it_proves_itself() {
    // Both pins are inside the signed transcript, so the real server sees a proof made for another server key and refuses it. The
    // server therefore never proves itself to a client that pinned something else. (An attacker that presents its own key instead
    // is caught by the client's own pin check; see `attack_stolen_classical_key.rs`.)
    let w = world();
    let other_pin = identity(9).pin();
    let (client_side, server_side) = run(&w, &other_pin, channel(7, 7), &w.registry).await;
    assert_eq!(server_side.err(), Some(Error::Refused));
    assert_eq!(client_side.err(), Some(Error::Refused));
}

#[tokio::test]
async fn a_proof_made_on_another_connection_is_refused() {
    // The two ends read different exporter values: they are two connections, as when a relay sits between a client and a server.
    let w = world();
    let (client_side, server_side) = run(&w, &w.server_pin, channel(7, 8), &w.registry).await;
    assert_eq!(server_side.err(), Some(Error::Refused));
    assert_eq!(client_side.err(), Some(Error::Refused));
}

#[tokio::test]
async fn a_server_proof_recorded_on_one_connection_does_not_verify_on_another() {
    let w = world();
    // Session A (exporter value 1): the attacker recorded the real server's whole SERVER_PROOF frame, the server's public key and its
    // proof for that connection. It is rebuilt here from the same functions the server uses.
    let transcript = pqbind::Transcript {
        binding: &binding(1),
        client_id: &w.client_id,
        server_id: &w.server_id,
        client_pin: &w.client.pin(),
        server_pin: &w.server_pin,
    };
    let proof_a = pqbind::proof::prove(pqbind::Role::Server, &w.server, &transcript).expect("proof");
    let mut replay = vec![SERVER_PROOF];
    replay.extend_from_slice(w.server.public().as_bytes());
    replay.extend_from_slice(&proof_a);

    // Session B: a different connection (exporter value 2). The attacker answers the client's HELLO with the recorded frame.
    let (mut client_b, mut attacker_b) = channel(2, 2);
    let (client_result, ()) = tokio::join!(connect(&mut client_b, &w.client, &w.client_id, &w.server_id, &w.server_pin), async {
        attacker_b.recv().await.expect("the client's hello");
        attacker_b.send(&replay).await.expect("replay");
    });
    assert_eq!(client_result.err(), Some(Error::ServerIdentity));
}

#[tokio::test]
async fn a_frame_that_is_not_a_hello_gets_the_same_refusal_as_an_unknown_key() {
    let w = world();
    // An unenrolled but well-formed client.
    let stranger = identity(5);
    let (mut stranger_io, mut server_io) = channel(7, 7);
    let (stranger_result, server_result) = tokio::join!(
        connect(&mut stranger_io, &stranger, &w.client_id, &w.server_id, &w.server_pin),
        accept(&mut server_io, &w.server, &w.server_id, &w.client_id, &w.registry),
    );
    assert_eq!(stranger_result.err(), Some(Error::Refused));
    assert_eq!(server_result.err(), Some(Error::Refused));

    // A frame that is not a well-formed hello at all.
    let (mut garbage_io, mut server_io) = channel(7, 7);
    let (refusal, server_result) = tokio::join!(
        async {
            garbage_io.send(&[HELLO, 1, 2, 3]).await.expect("send");
            garbage_io.recv().await.expect("a reply")
        },
        accept(&mut server_io, &w.server, &w.server_id, &w.client_id, &w.registry),
    );
    assert_eq!(server_result.err(), Some(Error::Malformed), "the server knows locally that it was malformed");
    assert_eq!(refusal, vec![REFUSED], "the peer is told the same single frame as for an unknown key");
}

#[tokio::test]
async fn a_client_refuses_replies_that_are_not_a_server_proof() {
    let w = world();
    for reply in [vec![], vec![SERVER_PROOF], vec![0x77; 5], vec![REFUSED, 0], vec![SERVER_PROOF; 7320]] {
        let (mut client_io, mut attacker) = channel(7, 7);
        let (result, ()) = tokio::join!(connect(&mut client_io, &w.client, &w.client_id, &w.server_id, &w.server_pin), async {
            attacker.recv().await.expect("hello");
            attacker.send(&reply).await.expect("reply");
        });
        let error = result.expect_err("an error");
        assert!(matches!(error, Error::Malformed | Error::ServerIdentity), "reply {reply:?} gave {error:?}");
    }
}

#[tokio::test]
async fn a_client_that_gets_the_refusal_frame_reports_a_refusal() {
    let w = world();
    let (mut client_io, mut attacker) = channel(7, 7);
    let (result, ()) = tokio::join!(connect(&mut client_io, &w.client, &w.client_id, &w.server_id, &w.server_pin), async {
        attacker.recv().await.expect("hello");
        attacker.send(&[REFUSED]).await.expect("reply");
    });
    assert_eq!(result.err(), Some(Error::Refused));
}

#[tokio::test]
async fn a_closed_channel_is_an_io_error_on_both_ends() {
    let w = world();
    let (mut client_io, server_io) = channel(7, 7);
    drop(server_io);
    assert_eq!(connect(&mut client_io, &w.client, &w.client_id, &w.server_id, &w.server_pin).await.err(), Some(Error::Io));
    let (client_io, mut server_io) = channel(7, 7);
    drop(client_io);
    assert_eq!(accept(&mut server_io, &w.server, &w.server_id, &w.client_id, &w.registry).await.err(), Some(Error::Io));
}

#[test]
fn a_public_identity_that_is_not_canonical_cannot_be_used_as_a_peer_key() {
    let public = identity(4).public();
    let mut padded = public.as_bytes().to_vec();
    padded.push(0);
    assert_eq!(PublicIdentity::from_bytes(&padded), Err(Error::Malformed));
}
