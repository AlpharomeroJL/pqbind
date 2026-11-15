// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Offer the `SecP384r1MLKEM1024` TLS 1.3 key exchange group, which rustls does not ship, and build the single-group crypto providers the probe uses.
//!
//! The group is ported from the author's own VaultScribe `vs-mesh` crate (`hybrid_kx.rs`), with the product-only providers left out.
//! It composes the two groups rustls itself offers (`kx_group::SECP384R1` and `kx_group::MLKEM1024`, both over aws-lc-rs), so nothing
//! here is a primitive. It joins two shares and two secrets in the layout of RFC 10024 (IANA code point 0x11ED), classical part first:
//!
//! ```text
//! client share:  P-384 point 97 | ML-KEM-1024 encapsulation key 1568
//! server share:  P-384 point 97 | ML-KEM-1024 ciphertext 1568
//! secret:        P-384 secret 48 | ML-KEM-1024 secret 32
//! ```

use std::sync::Arc;

use rustls::crypto::aws_lc_rs::{default_provider, kx_group};
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

use super::classify::ProbeGroup;

/// The IANA code point of `SecP384r1MLKEM1024`. rustls has no name for it yet.
const GROUP: NamedGroup = NamedGroup::Unknown(0x11ed);

/// The length of an uncompressed P-384 point, in bytes.
const P384_SHARE_LEN: usize = 97;

/// The length of an ML-KEM-1024 encapsulation key, in bytes.
const MLKEM1024_KEY_LEN: usize = 1568;

/// The length of an ML-KEM-1024 ciphertext, in bytes.
const MLKEM1024_CIPHERTEXT_LEN: usize = 1568;

/// A share of the wrong length.
const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

/// The `SecP384r1MLKEM1024` group.
pub static SECP384R1_MLKEM1024: &dyn SupportedKxGroup = &SecP384r1MlKem1024;

/// The group's implementation.
#[derive(Debug)]
struct SecP384r1MlKem1024;

/// `share` split at the end of the P-384 point, when it holds exactly a point and `post_quantum_len` bytes.
fn split_share(share: &[u8], post_quantum_len: usize) -> Option<(&[u8], &[u8])> {
    if share.len() == P384_SHARE_LEN.saturating_add(post_quantum_len) { share.split_at_checked(P384_SHARE_LEN) } else { None }
}

impl SupportedKxGroup for SecP384r1MlKem1024 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = kx_group::SECP384R1.start()?;
        let post_quantum = kx_group::MLKEM1024.start()?;
        let share = [classical.pub_key(), post_quantum.pub_key()].concat();
        Ok(Box::new(ActiveHybrid { classical, post_quantum, share }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (classical_share, post_quantum_share) = split_share(client_share, MLKEM1024_KEY_LEN).ok_or(INVALID_KEY_SHARE)?;
        let classical = kx_group::SECP384R1.start_and_complete(classical_share)?;
        let post_quantum = kx_group::MLKEM1024.start_and_complete(post_quantum_share)?;
        Ok(CompletedKeyExchange {
            group: GROUP,
            pub_key: [classical.pub_key.as_slice(), post_quantum.pub_key.as_slice()].concat(),
            secret: SharedSecret::from([classical.secret.secret_bytes(), post_quantum.secret.secret_bytes()].concat()),
        })
    }

    fn name(&self) -> NamedGroup {
        GROUP
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

/// A client's side of the exchange, between its key share and the server's.
struct ActiveHybrid {
    classical: Box<dyn ActiveKeyExchange>,
    post_quantum: Box<dyn ActiveKeyExchange>,
    share: Vec<u8>,
}

impl ActiveKeyExchange for ActiveHybrid {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let (classical_share, post_quantum_share) = split_share(peer_pub_key, MLKEM1024_CIPHERTEXT_LEN).ok_or(INVALID_KEY_SHARE)?;
        let classical = self.classical.complete(classical_share)?;
        let post_quantum = self.post_quantum.complete(post_quantum_share)?;
        Ok(SharedSecret::from([classical.secret_bytes(), post_quantum.secret_bytes()].concat()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.share
    }

    fn group(&self) -> NamedGroup {
        GROUP
    }
}

/// The rustls key exchange group for a probe group.
#[must_use]
pub fn group_for(group: ProbeGroup) -> &'static dyn SupportedKxGroup {
    match group {
        ProbeGroup::X25519MlKem768 => kx_group::X25519MLKEM768,
        ProbeGroup::SecP256r1MlKem768 => kx_group::SECP256R1MLKEM768,
        ProbeGroup::SecP384r1MlKem1024 => SECP384R1_MLKEM1024,
        ProbeGroup::MlKem1024 => kx_group::MLKEM1024,
        ProbeGroup::X25519 => kx_group::X25519,
        ProbeGroup::Secp256r1 => kx_group::SECP256R1,
    }
}

/// The aws-lc-rs default provider with its key exchange groups replaced by exactly `groups`. The probe passes one group, so the
/// ClientHello offers that group alone; the tests pass the groups a test server should offer.
#[must_use]
pub fn provider_with_groups(groups: Vec<&'static dyn SupportedKxGroup>) -> Arc<CryptoProvider> {
    let mut provider = default_provider();
    provider.kx_groups = groups;
    Arc::new(provider)
}
