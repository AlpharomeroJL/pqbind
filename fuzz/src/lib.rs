// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Hold what the fuzz targets share: a scripted frame channel, fixed identities, a runtime to drive the handshake, and helpers that shape a fuzz input into a frame.

use std::collections::VecDeque;
use std::sync::OnceLock;

use pqbind::{Binding, EXPORTER_LEN, Enrollment, FrameError, FrameIo, HybridIdentity, MemoryRegistry, PeerId, PublicIdentity};
use pqbind_crypto::hybrid::{PUBLIC_KEY_LEN, SIGNATURE_LEN};
use pqbind_crypto::suite::SignatureSuite;
use tokio::runtime::{Builder, Runtime};

/// The first byte of a HELLO frame.
pub const HELLO: u8 = 0x01;
/// The first byte of a SERVER_PROOF frame.
pub const SERVER_PROOF: u8 = 0x02;
/// The whole REFUSED frame.
pub const REFUSED: u8 = 0x03;

/// The length of a HELLO or SERVER_PROOF frame: the tag, a public key and a proof.
pub const SHAPED_LEN: usize = 1 + PUBLIC_KEY_LEN + SIGNATURE_LEN;

/// The length of the proof inside a HELLO or SERVER_PROOF frame.
pub const PROOF_LEN: usize = SIGNATURE_LEN;

/// A channel that returns the frames it was given, in order, and records every frame sent through it.
pub struct Scripted {
    binding: Binding,
    incoming: VecDeque<Vec<u8>>,
    /// Every frame the code under test sent, in order.
    pub sent: Vec<Vec<u8>>,
}

impl Scripted {
    /// A channel whose peer will send `incoming`, one frame per receive, and then close.
    #[must_use]
    pub fn new(incoming: Vec<Vec<u8>>) -> Self {
        let binding = Binding::new(b"fuzz/v1", [5; EXPORTER_LEN]).expect("a fixed, valid binding");
        Self { binding, incoming: incoming.into(), sent: Vec::new() }
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

/// One runtime for the whole process: building one per input would dominate the run time.
pub fn block_on<T>(future: impl Future<Output = T>) -> T {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| Builder::new_current_thread().build().expect("a runtime")).block_on(future)
}

/// The identity of the seed `[fill; 32]`. Each caller below keeps its identity in a static, because making a hybrid key is slow
/// compared with running one input.
fn identity_of(fill: u8) -> HybridIdentity {
    HybridIdentity::from_seed(&[fill; 32]).expect("a seed")
}

/// The server's identity, the one the client side of `client_reply` pins and the server side of `server_hello` runs as.
pub fn server_identity() -> &'static HybridIdentity {
    static KEY: OnceLock<HybridIdentity> = OnceLock::new();
    KEY.get_or_init(|| identity_of(2))
}

/// The client's identity.
pub fn client_identity() -> &'static HybridIdentity {
    static KEY: OnceLock<HybridIdentity> = OnceLock::new();
    KEY.get_or_init(|| identity_of(1))
}

/// A registry in which the client identity is enrolled for the anonymous transport identity, so that in a HELLO built from the client's
/// real key only the proof stands between the frame and acceptance.
pub fn enrolled_registry() -> &'static MemoryRegistry {
    static REGISTRY: OnceLock<MemoryRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let registry = MemoryRegistry::new();
        registry.enroll(Enrollment { key: client_identity().public(), peer_id: PeerId::anonymous(), enrolled_at_unix_millis: 0 });
        registry
    })
}

/// A pool of four valid public keys, for inputs that build a registry list out of real keys.
pub fn key_pool() -> &'static [PublicIdentity] {
    static POOL: OnceLock<Vec<PublicIdentity>> = OnceLock::new();
    POOL.get_or_init(|| (10..14).map(|fill| identity_of(fill).public()).collect())
}

/// `bytes` shaped like an encoded public key: the suite identifier, then `bytes` cut or zero-padded to the rest of the key. It gets a
/// fuzz input past the length and suite checks, to the checks on the two halves behind them.
#[must_use]
pub fn shaped_key(bytes: &[u8]) -> Vec<u8> {
    let mut key = SignatureSuite::Ed25519MlDsa87.id().to_be_bytes().to_vec();
    key.extend_from_slice(bytes);
    key.resize(PUBLIC_KEY_LEN, 0);
    key
}

/// The server's public key, which is public data.
pub fn server_public() -> &'static PublicIdentity {
    static KEY: OnceLock<PublicIdentity> = OnceLock::new();
    KEY.get_or_init(|| server_identity().public())
}

/// A frame of exactly the shape of a HELLO or SERVER_PROOF, built from `tag`, a real public key and `proof_bytes` cut or zero-padded to
/// the proof length. It gets a fuzz input past the shape and key checks, to the proof check behind them.
#[must_use]
pub fn shaped_frame(tag: u8, key: &PublicIdentity, proof_bytes: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(SHAPED_LEN);
    frame.push(tag);
    frame.extend_from_slice(key.as_bytes());
    frame.extend_from_slice(proof_bytes);
    frame.resize(SHAPED_LEN, 0);
    frame
}
