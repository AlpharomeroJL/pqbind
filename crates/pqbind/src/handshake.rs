// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Run the proof exchange after the transport handshake: hello, server proof or refusal, before any application data.
//!
//! ```text
//! client -> server   HELLO         0x01 | client public key | client proof
//! server -> client   SERVER_PROOF  0x02 | server public key | server proof        (or)
//! server -> client   REFUSED       0x03
//! ```
//!
//! - The server accepts a client only if the proof verifies **and** the key is enrolled for that transport identity. It checks both
//!   whatever the first one answered, and every refusal is the same single `REFUSED` frame, so the answer says nothing about which
//!   check failed. The server proves itself only after the client passed.
//! - The client accepts a server only if the key it sends has the pin the client holds **and** the proof verifies. A client that cannot
//!   verify the server stops before sending any application data.
//! - Keys in these frames are never trusted because they were sent: trust comes from the enrolled registry and the pin.
//!
//! Neither end may send application data until its call returns `Ok`.

use pqbind_crypto::hybrid::{PUBLIC_KEY_LEN, SIGNATURE_LEN};

use crate::binding::Binding;
use crate::error::Error;
use crate::frame::FrameIo;
use crate::identity::{HybridIdentity, PeerId, Pin, PublicIdentity};
use crate::proof::{self, Role, Transcript};
use crate::trust::ClientRegistry;

const HELLO: u8 = 0x01;
const SERVER_PROOF: u8 = 0x02;
const REFUSED: u8 = 0x03;

/// The length of a HELLO or SERVER_PROOF frame: the tag, a public key and a proof.
const KEY_AND_PROOF_FRAME_LEN: usize = 1 + PUBLIC_KEY_LEN + SIGNATURE_LEN;

/// The peer a successful handshake authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Established {
    peer_key: PublicIdentity,
    peer_id: PeerId,
}

impl Established {
    /// The peer's hybrid public key: the enrolled client's on a server, the pinned server's on a client.
    #[must_use]
    pub const fn peer_key(&self) -> &PublicIdentity {
        &self.peer_key
    }

    /// The peer's transport identity, as the caller gave it.
    #[must_use]
    pub const fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }
}

fn key_and_proof_frame(tag: u8, key: &PublicIdentity, proof: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(KEY_AND_PROOF_FRAME_LEN);
    frame.push(tag);
    frame.extend_from_slice(key.as_bytes());
    frame.extend_from_slice(proof);
    frame
}

/// The key bytes and proof bytes of a frame that opens with `tag` and has exactly the right length.
fn split_key_and_proof(frame: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    if frame.len() != KEY_AND_PROOF_FRAME_LEN || frame.first() != Some(&tag) {
        return None;
    }
    frame.get(1..)?.split_at_checked(PUBLIC_KEY_LEN)
}

fn transcript<'a>(
    binding: &'a Binding,
    client_id: &'a PeerId,
    server_id: &'a PeerId,
    client_pin: &'a Pin,
    server_pin: &'a Pin,
) -> Transcript<'a> {
    Transcript { binding, client_id, server_id, client_pin, server_pin }
}

/// Authenticate to a server as the client.
///
/// `own_id` and `server_id` are the transport identities of the two ends as the transport authenticated them (the empty
/// [`PeerId::anonymous`] for an end it did not). `server_pin` is the pin of the server's hybrid key, from enrollment.
///
/// # Errors
///
/// [`Error::Refused`] when the server refused this client, [`Error::ServerIdentity`] when the server's key is not the pinned one or its
/// proof does not verify, [`Error::Malformed`] for a reply that is not a handshake frame, and [`Error::Io`] when the transport fails.
pub async fn connect<F: FrameIo>(
    io: &mut F,
    me: &HybridIdentity,
    own_id: &PeerId,
    server_id: &PeerId,
    server_pin: &Pin,
) -> Result<Established, Error> {
    let my_public = me.public();
    let my_pin = Pin::of(&my_public);
    let hello = {
        let transcript = transcript(io.binding(), own_id, server_id, &my_pin, server_pin);
        let proof = proof::prove(Role::Client, me, &transcript)?;
        key_and_proof_frame(HELLO, &my_public, &proof)
    };
    io.send(&hello).await?;

    let reply = io.recv().await?;
    if reply.as_slice() == [REFUSED] {
        return Err(Error::Refused);
    }
    let (key_bytes, proof_bytes) = split_key_and_proof(&reply, SERVER_PROOF).ok_or(Error::Malformed)?;
    let server_key = PublicIdentity::from_bytes(key_bytes).map_err(|_| Error::ServerIdentity)?;
    if Pin::of(&server_key) != *server_pin {
        return Err(Error::ServerIdentity);
    }
    let transcript = transcript(io.binding(), own_id, server_id, &my_pin, server_pin);
    proof::verify(Role::Server, &server_key, proof_bytes, &transcript).map_err(|_| Error::ServerIdentity)?;
    Ok(Established { peer_key: server_key, peer_id: server_id.clone() })
}

/// Check a HELLO frame: the shape, the proof and the enrollment. Every failure is a refusal; a frame that is not even a HELLO is
/// reported as malformed to the caller, but the peer is told the same thing either way.
fn check_hello(
    binding: &Binding,
    hello: &[u8],
    own_id: &PeerId,
    client_id: &PeerId,
    my_pin: &Pin,
    registry: &dyn ClientRegistry,
) -> Result<PublicIdentity, Error> {
    let (key_bytes, proof_bytes) = split_key_and_proof(hello, HELLO).ok_or(Error::Malformed)?;
    let client_key = PublicIdentity::from_bytes(key_bytes)?;
    let client_pin = Pin::of(&client_key);
    let transcript = transcript(binding, client_id, own_id, &client_pin, my_pin);
    // Both checks run whatever the first one answered, so timing does not tell an unknown key from a bad proof.
    let proof_ok = proof::verify(Role::Client, &client_key, proof_bytes, &transcript).is_ok();
    let enrolled = registry.is_enrolled(&client_key, client_id);
    if proof_ok & enrolled { Ok(client_key) } else { Err(Error::Refused) }
}

/// Authenticate a client as the server.
///
/// `own_id` and `client_id` are the transport identities of the two ends as the transport authenticated them. `registry` says which
/// clients are enrolled.
///
/// # Errors
///
/// [`Error::Refused`] when the client's key is not enrolled for `client_id` or its proof does not verify, [`Error::Malformed`] when the
/// first frame is not a well-formed HELLO, and [`Error::Io`] when the transport fails. In every refusal the peer receives the same
/// single `REFUSED` frame.
pub async fn accept<F: FrameIo>(
    io: &mut F,
    me: &HybridIdentity,
    own_id: &PeerId,
    client_id: &PeerId,
    registry: &dyn ClientRegistry,
) -> Result<Established, Error> {
    let my_public = me.public();
    let my_pin = Pin::of(&my_public);
    let hello = io.recv().await?;
    let client_key = match check_hello(io.binding(), &hello, own_id, client_id, &my_pin, registry) {
        Ok(key) => key,
        Err(error) => {
            // The peer is told one thing whatever went wrong; a failure to send it changes nothing, the call fails either way.
            let _ = io.send(&[REFUSED]).await;
            return Err(error);
        }
    };
    let client_pin = Pin::of(&client_key);
    let reply = {
        let transcript = transcript(io.binding(), client_id, own_id, &client_pin, &my_pin);
        let proof = proof::prove(Role::Server, me, &transcript)?;
        key_and_proof_frame(SERVER_PROOF, &my_public, &proof)
    };
    io.send(&reply).await?;
    Ok(Established { peer_key: client_key, peer_id: client_id.clone() })
}
