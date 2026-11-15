// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Prove the headline claim: an attacker who holds a peer's classical (Ed25519) private key still cannot pass as that peer, with a positive control that shows the forging helper is itself correct.
//!
//! The attacker here has everything a quantum computer gives against a classical identity: the victim's Ed25519 private key, the
//! victim's public key (public anyway), the exporter value of the session it is in, and every pin. What it lacks is the ML-DSA half,
//! which is derived from the victim's seed and is not recoverable from the Ed25519 key.

use pqbind::proof::{self, Role, Transcript};
use pqbind::{Binding, EXPORTER_LEN, Enrollment, Error, FrameError, FrameIo, HybridIdentity, MemoryRegistry, PeerId, Pin, accept, connect};
use tokio::sync::mpsc;

const HELLO: u8 = 0x01;
const SERVER_PROOF: u8 = 0x02;

struct MemoryFrames {
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

fn channel() -> (MemoryFrames, MemoryFrames) {
    let (to_server, from_client) = mpsc::channel(8);
    let (to_client, from_server) = mpsc::channel(8);
    let binding = || Binding::new(b"test-app/v1", [3; EXPORTER_LEN]).expect("binding");
    (
        MemoryFrames { binding: binding(), tx: to_server, rx: from_server },
        MemoryFrames { binding: binding(), tx: to_client, rx: from_client },
    )
}

/// What an attacker can build: a hybrid proof whose Ed25519 half comes from `ed_seed` and whose ML-DSA half comes from `ml_dsa_seed`.
/// It rebuilds the signed bytes with the crate's own public functions, so it signs exactly what a real proof signs.
fn forged_proof(role: Role, ed_seed: &[u8; 32], ml_dsa_seed: &[u8; 32], transcript: &Transcript<'_>) -> Vec<u8> {
    let signed = pqbind_crypto::hybrid::signed_bytes(&proof::transcript_bytes(role, transcript));
    let classical = pqbind_crypto::sign::SigningKey::from_seed(ed_seed).sign(&signed);
    let post_quantum = pqbind_crypto::hybrid::ml_dsa_key_of_seed(ml_dsa_seed).expect("seed").sign(&signed).expect("sign");
    let mut out = pqbind_crypto::suite::SignatureSuite::Ed25519MlDsa87.id().to_be_bytes().to_vec();
    out.extend_from_slice(&classical.to_bytes());
    out.extend_from_slice(post_quantum.as_bytes());
    out
}

const VICTIM_SEED: [u8; 32] = [0x11; 32];
const ATTACKER_SEED: [u8; 32] = [0x66; 32];

fn victim() -> HybridIdentity {
    HybridIdentity::from_seed(&VICTIM_SEED).expect("seed")
}

#[test]
fn the_forging_helper_reproduces_a_real_proof_when_it_has_both_halves() {
    // The positive control: with the victim's whole seed, the helper must give byte for byte the proof the real identity gives.
    // Without this, an attack that fails could be failing because the helper is wrong.
    let victim = victim();
    let server = HybridIdentity::from_seed(&[0x22; 32]).expect("seed");
    let (client_id, server_id) = (PeerId::new(b"c").expect("id"), PeerId::new(b"s").expect("id"));
    let binding = Binding::new(b"test-app/v1", [3; EXPORTER_LEN]).expect("binding");
    let (client_pin, server_pin) = (victim.pin(), server.pin());
    let transcript =
        Transcript { binding: &binding, client_id: &client_id, server_id: &server_id, client_pin: &client_pin, server_pin: &server_pin };
    for role in [Role::Client, Role::Server] {
        let real = proof::prove(role, &victim, &transcript).expect("proof");
        assert_eq!(forged_proof(role, &VICTIM_SEED, &VICTIM_SEED, &transcript), real, "{role:?}");
        proof::verify(role, &victim.public(), &real, &transcript).expect("the real proof verifies");
    }
}

#[tokio::test]
async fn an_attacker_with_the_servers_ed25519_key_but_not_its_ml_dsa_key_cannot_pass_as_the_server() {
    let client = HybridIdentity::from_seed(&[0x22; 32]).expect("seed");
    let server = victim();
    let (client_id, server_id) = (PeerId::new(b"client-node").expect("id"), PeerId::new(b"server-node").expect("id"));
    let pin = server.pin();

    for (name, ml_dsa_seed, expected) in [
        ("attacker with only the Ed25519 half", ATTACKER_SEED, Some(Error::ServerIdentity)),
        // The positive control of the same scenario: an attacker who also has the ML-DSA half is the server, and must get in.
        ("control: attacker with both halves", VICTIM_SEED, None),
    ] {
        let (mut client_io, mut attacker_io) = channel();
        let (result, ()) = tokio::join!(connect(&mut client_io, &client, &client_id, &server_id, &pin), async {
            let hello = attacker_io.recv().await.expect("hello");
            assert_eq!(hello.first(), Some(&HELLO));
            let (client_pin, server_pin) = (client.pin(), server.pin());
            let transcript = Transcript {
                binding: attacker_io.binding(),
                client_id: &client_id,
                server_id: &server_id,
                client_pin: &client_pin,
                server_pin: &server_pin,
            };
            let proof = forged_proof(Role::Server, &VICTIM_SEED, &ml_dsa_seed, &transcript);
            // The server's public key is public, so the attacker presents the real one, which carries the real pin.
            let mut frame = vec![SERVER_PROOF];
            frame.extend_from_slice(server.public().as_bytes());
            frame.extend_from_slice(&proof);
            attacker_io.send(&frame).await.expect("send");
        });
        assert_eq!(result.err(), expected, "{name}");
    }
}

#[tokio::test]
async fn an_attacker_with_the_clients_ed25519_key_but_not_its_ml_dsa_key_cannot_pass_as_the_client() {
    let server = HybridIdentity::from_seed(&[0x22; 32]).expect("seed");
    let client = victim();
    let (client_id, server_id) = (PeerId::new(b"client-node").expect("id"), PeerId::new(b"server-node").expect("id"));
    let registry = MemoryRegistry::new();
    registry.enroll(Enrollment { key: client.public(), peer_id: client_id.clone(), enrolled_at_unix_millis: 0 });

    for (name, ml_dsa_seed, accepted) in
        [("attacker with only the Ed25519 half", ATTACKER_SEED, false), ("control: attacker with both halves", VICTIM_SEED, true)]
    {
        let (mut attacker_io, mut server_io) = channel();
        let (server_result, ()) = tokio::join!(accept(&mut server_io, &server, &server_id, &client_id, &registry), async {
            let (client_pin, server_pin) = (client.pin(), server.pin());
            let transcript = Transcript {
                binding: attacker_io.binding(),
                client_id: &client_id,
                server_id: &server_id,
                client_pin: &client_pin,
                server_pin: &server_pin,
            };
            let proof = forged_proof(Role::Client, &VICTIM_SEED, &ml_dsa_seed, &transcript);
            let mut frame = vec![HELLO];
            frame.extend_from_slice(client.public().as_bytes());
            frame.extend_from_slice(&proof);
            attacker_io.send(&frame).await.expect("send");
            // Whatever the server answers, the attacker reads it so the channel does not close early.
            let _ = attacker_io.recv().await;
        });
        assert_eq!(server_result.is_ok(), accepted, "{name}: {server_result:?}");
        if !accepted {
            assert_eq!(server_result.err(), Some(Error::Refused), "{name}");
        }
    }
}

#[tokio::test]
async fn an_attacker_who_substitutes_its_own_hybrid_key_for_the_servers_fails_the_pin() {
    // The other way to try: present the attacker's own whole key. The pin the client holds is of the real server's key.
    let client = HybridIdentity::from_seed(&[0x22; 32]).expect("seed");
    let server = victim();
    let attacker = HybridIdentity::from_seed(&ATTACKER_SEED).expect("seed");
    let (client_id, server_id) = (PeerId::new(b"c").expect("id"), PeerId::new(b"s").expect("id"));
    let pin: Pin = server.pin();
    let (mut client_io, mut attacker_io) = channel();
    let (result, ()) = tokio::join!(connect(&mut client_io, &client, &client_id, &server_id, &pin), async {
        attacker_io.recv().await.expect("hello");
        let (client_pin, attacker_pin) = (client.pin(), attacker.pin());
        let transcript = Transcript {
            binding: attacker_io.binding(),
            client_id: &client_id,
            server_id: &server_id,
            client_pin: &client_pin,
            server_pin: &attacker_pin,
        };
        let proof = proof::prove(Role::Server, &attacker, &transcript).expect("proof");
        let mut frame = vec![SERVER_PROOF];
        frame.extend_from_slice(attacker.public().as_bytes());
        frame.extend_from_slice(&proof);
        attacker_io.send(&frame).await.expect("send");
    });
    assert_eq!(result.err(), Some(Error::ServerIdentity));
}
