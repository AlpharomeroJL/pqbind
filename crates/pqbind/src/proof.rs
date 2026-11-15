// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Build what a proof signs (role label, application label, both transport identities, both key pins, the exporter value), sign it and verify it, per role.
//!
//! ```text
//! role label | u8 len, application label | u16 len, client id | u16 len, server id | client pin 48 | server pin 48 | exporter 64
//! ```
//!
//! - The two roles sign under different labels, so a server's proof is never a client's proof.
//! - Both transport identities are inside, always in client-then-server order and length-prefixed, so a proof holds for one pair of
//!   peers and the boundary between two identities cannot be moved.
//! - Both keys' pins are inside, so a proof also names the keys of the exchange.
//! - The exporter value is unique to one session, so a proof made on another connection does not verify.
//!
//! The bytes are then signed by the hybrid key, which signs them under its own label with SHA-512, with both halves required.

use pqbind_crypto::hybrid::HybridSignature;

use crate::binding::Binding;
use crate::error::Error;
use crate::identity::{HybridIdentity, PeerId, Pin, PublicIdentity};

/// The label a client's proof signs under.
const CLIENT_LABEL: &[u8] = b"pqbind/proof/client/v1\0";

/// The label a server's proof signs under.
const SERVER_LABEL: &[u8] = b"pqbind/proof/server/v1\0";

/// Which end of the connection a proof is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The end that opened the connection and sends the first proof.
    Client,
    /// The end that accepted the connection.
    Server,
}

impl Role {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::Client => CLIENT_LABEL,
            Self::Server => SERVER_LABEL,
        }
    }
}

/// Everything a proof binds, borrowed from the connection and the two ends.
#[derive(Debug, Clone, Copy)]
pub struct Transcript<'a> {
    /// The exporter value of this connection and the application label.
    pub binding: &'a Binding,
    /// The transport identity of the client.
    pub client_id: &'a PeerId,
    /// The transport identity of the server.
    pub server_id: &'a PeerId,
    /// The pin of the client's hybrid key.
    pub client_pin: &'a Pin,
    /// The pin of the server's hybrid key.
    pub server_pin: &'a Pin,
}

fn put_id(out: &mut Vec<u8>, id: &PeerId) {
    // An identity is at most `MAX_PEER_ID_LEN` (1024) bytes, so it always fits in two bytes.
    let len = u16::try_from(id.as_bytes().len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(id.as_bytes());
}

/// The bytes a `role` proof signs over `transcript`. Public so an independent verifier or a test harness can reproduce them.
#[must_use]
pub fn transcript_bytes(role: Role, transcript: &Transcript<'_>) -> Vec<u8> {
    let app_label = transcript.binding.app_label();
    let mut out = Vec::with_capacity(160 + app_label.len() + transcript.client_id.as_bytes().len() + transcript.server_id.as_bytes().len());
    out.extend_from_slice(role.label());
    // The label is at most 255 bytes (checked by `Binding`), so its length fits in one byte.
    out.push(u8::try_from(app_label.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(app_label);
    put_id(&mut out, transcript.client_id);
    put_id(&mut out, transcript.server_id);
    out.extend_from_slice(transcript.client_pin.as_bytes());
    out.extend_from_slice(transcript.server_pin.as_bytes());
    out.extend_from_slice(transcript.binding.exporter());
    out
}

/// The encoded proof of `identity` for `role` over `transcript`.
///
/// # Errors
///
/// [`Error::Crypto`] when the key cannot sign.
pub fn prove(role: Role, identity: &HybridIdentity, transcript: &Transcript<'_>) -> Result<Vec<u8>, Error> {
    let message = transcript_bytes(role, transcript);
    Ok(identity.signing_key().sign(&message)?.to_bytes())
}

/// Check that `proof` is `signer`'s proof for `role` over `transcript`. Both halves of the hybrid signature must verify.
///
/// # Errors
///
/// [`Error::ProofInvalid`] for a proof of the wrong size or form, or one that does not verify: it was made by another key, on
/// another connection, for another pair of peers, another application label or the other role.
pub fn verify(role: Role, signer: &PublicIdentity, proof: &[u8], transcript: &Transcript<'_>) -> Result<(), Error> {
    let signature = HybridSignature::from_slice(proof).map_err(|_| Error::ProofInvalid)?;
    let message = transcript_bytes(role, transcript);
    signer.verifying_key().verify(&message, &signature).map_err(|_| Error::ProofInvalid)
}
