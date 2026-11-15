// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Play the attackers of the demo: a server impersonator, a client impersonator and a relay, each holding only the classical keys.
//!
//! The attackers build frames by hand with the library's own public functions, so they sign exactly what a real proof signs.

use pqbind::proof::{self, Role, Transcript};
use pqbind::{FrameIo, PeerId, PublicIdentity};
use pqbind_crypto::hybrid::PUBLIC_KEY_LEN;

use super::LABEL;
use super::cast::Cast;
use crate::common::{CliError, CliResult};
use crate::transport::{Link, Raw};

/// The first byte of the frames the attackers build by hand (the same values the handshake uses).
const HELLO: u8 = 0x01;
const SERVER_PROOF: u8 = 0x02;
const REFUSED: u8 = 0x03;

/// What an attacker did, and what keeps its connection open until the scenario is over.
pub struct Attack {
    /// Whether the attacker's own code ran to the end.
    pub outcome: CliResult<()>,
    note: Option<String>,
    _link: Option<Link>,
}

impl Attack {
    fn failed(error: impl Into<CliError>) -> Self {
        Self { outcome: Err(error.into()), note: None, _link: None }
    }

    /// The lines that describe the attack: `done` when it ran, the failure otherwise, and the attacker's note when there is one.
    pub fn lines(&self, done: &str) -> Vec<String> {
        let first = match &self.outcome {
            Ok(()) => done.to_owned(),
            Err(error) => format!("the attacker's own code failed: {error}"),
        };
        let mut lines = vec![first];
        if let Some(note) = &self.note {
            lines.push(note.clone());
        }
        lines
    }
}

/// What an attacker can build: a hybrid proof whose Ed25519 half comes from `ed_seed` and whose ML-DSA half comes from `ml_dsa_seed`.
/// It rebuilds the signed bytes with the library's own public functions, so it signs exactly what a real proof signs.
fn forged_proof(role: Role, ed_seed: &[u8; 32], ml_dsa_seed: &[u8; 32], transcript: &Transcript<'_>) -> CliResult<Vec<u8>> {
    let signed = pqbind_crypto::hybrid::signed_bytes(&proof::transcript_bytes(role, transcript));
    let classical = pqbind_crypto::sign::SigningKey::from_seed(ed_seed).sign(&signed);
    let post_quantum = pqbind_crypto::hybrid::ml_dsa_key_of_seed(ml_dsa_seed)?.sign(&signed)?;
    let mut out = pqbind_crypto::suite::SignatureSuite::Ed25519MlDsa87.id().to_be_bytes().to_vec();
    out.extend_from_slice(&classical.to_bytes());
    out.extend_from_slice(post_quantum.as_bytes());
    Ok(out)
}

/// The server impersonator: it holds the server's TLS key and Ed25519 key, not its ML-DSA key.
pub async fn forge_as_server(raw: Raw, cast: &Cast) -> Attack {
    let mut link = match raw.server_frames(LABEL).await {
        Ok(link) => link,
        Err(error) => return Attack::failed(error),
    };
    let outcome = forge_server_reply(&mut link, cast).await;
    Attack { outcome, note: None, _link: Some(link) }
}

async fn forge_server_reply(link: &mut Link, cast: &Cast) -> CliResult<()> {
    let hello = link.frames.recv().await.map_err(|_| CliError::new("the client sent no HELLO"))?;
    let key_bytes = match (hello.first(), hello.get(1..1 + PUBLIC_KEY_LEN)) {
        (Some(&HELLO), Some(bytes)) => bytes,
        _ => return Err(CliError::new("the first frame is not a HELLO")),
    };
    let client_pin = PublicIdentity::from_bytes(key_bytes)?.pin();
    let server_pin = cast.server.pin();
    let server_id = cast.tls.id();
    let proof = {
        let transcript = Transcript {
            binding: link.frames.binding(),
            client_id: &link.peer,
            server_id: &server_id,
            client_pin: &client_pin,
            server_pin: &server_pin,
        };
        forged_proof(Role::Server, &cast.server_seed, &cast.attacker_seed, &transcript)?
    };
    // The server's public key is public, so the attacker presents the real one, which carries the real pin.
    let mut frame = vec![SERVER_PROOF];
    frame.extend_from_slice(cast.server.public().as_bytes());
    frame.extend_from_slice(&proof);
    link.frames.send(&frame).await.map_err(|_| CliError::new("the forged reply could not be sent"))
}

/// The client impersonator: it holds an enrolled client's Ed25519 key, not its ML-DSA key.
pub async fn forge_as_client(raw: Raw, cast: &Cast) -> Attack {
    let mut link = match raw.client_frames(LABEL).await {
        Ok(link) => link,
        Err(error) => return Attack::failed(error),
    };
    let (outcome, note) = match forge_client_hello(&mut link, cast).await {
        Ok(reply) => (
            Ok(()),
            Some(if reply == [REFUSED] {
                "the server answered with the single REFUSED frame".to_owned()
            } else {
                "the server sent something else".to_owned()
            }),
        ),
        Err(error) => (Err(error), None),
    };
    Attack { outcome, note, _link: Some(link) }
}

async fn forge_client_hello(link: &mut Link, cast: &Cast) -> CliResult<Vec<u8>> {
    let client_pin = cast.client.pin();
    let server_pin = cast.server.pin();
    let client_id = PeerId::anonymous();
    let proof = {
        let transcript = Transcript {
            binding: link.frames.binding(),
            client_id: &client_id,
            server_id: &link.peer,
            client_pin: &client_pin,
            server_pin: &server_pin,
        };
        forged_proof(Role::Client, &cast.client_seed, &cast.attacker_seed, &transcript)?
    };
    let mut frame = vec![HELLO];
    frame.extend_from_slice(cast.client.public().as_bytes());
    frame.extend_from_slice(&proof);
    link.frames.send(&frame).await.map_err(|_| CliError::new("the forged HELLO could not be sent"))?;
    link.frames.recv().await.map_err(|_| CliError::new("the server closed without answering"))
}

/// The relay: it terminates TLS for the client with the stolen certificate key, opens its own connection to the real server and copies
/// frames between the two. It never runs pqbind `accept` or `connect`.
pub async fn relay(inbound: Raw, outbound: Raw) -> Attack {
    let mut from_client = match inbound.server_frames(LABEL).await {
        Ok(link) => link,
        Err(error) => return Attack::failed(error),
    };
    let mut to_server = match outbound.client_frames(LABEL).await {
        Ok(link) => link,
        Err(error) => return Attack { outcome: Err(error.into()), note: None, _link: Some(from_client) },
    };
    let copied = copy_two_frames(&mut from_client, &mut to_server).await;
    let (outcome, note) = match copied {
        Ok(sizes) => (
            Ok(()),
            Some(format!(
                "the relay copied the client's frame ({} byte(s)) to the server and the server's answer ({} byte(s)) back",
                sizes.0, sizes.1
            )),
        ),
        Err(error) => (Err(error), None),
    };
    Attack { outcome, note, _link: Some(from_client) }
}

async fn copy_two_frames(from_client: &mut Link, to_server: &mut Link) -> CliResult<(usize, usize)> {
    let lost = |_| CliError::new("a relayed frame was lost");
    let hello = from_client.frames.recv().await.map_err(lost)?;
    to_server.frames.send(&hello).await.map_err(lost)?;
    let reply = to_server.frames.recv().await.map_err(lost)?;
    from_client.frames.send(&reply).await.map_err(lost)?;
    Ok((hello.len(), reply.len()))
}
