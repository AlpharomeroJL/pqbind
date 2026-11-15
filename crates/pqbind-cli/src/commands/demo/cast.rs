// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Make the people and keys of one demo run, and the registry a server of the demo uses.

use pqbind::{Enrollment, HybridIdentity, MemoryRegistry, PeerId};
use pqbind_crypto::random::random_array;

use crate::common::{CliResult, now_millis};
use crate::transport::Tls;

/// The people and keys of one demo run. Every key is made fresh from the operating system random source.
pub struct Cast {
    pub server_seed: [u8; 32],
    pub client_seed: [u8; 32],
    pub attacker_seed: [u8; 32],
    pub server: HybridIdentity,
    pub client: HybridIdentity,
    pub outsider: HybridIdentity,
    pub attacker: HybridIdentity,
    pub tls: Tls,
}

impl Cast {
    /// A new cast: fresh seeds, the identities they make, an outsider nobody enrolled, and a TLS certificate.
    pub fn new() -> CliResult<Self> {
        let server_seed: [u8; 32] = random_array()?;
        let client_seed: [u8; 32] = random_array()?;
        let attacker_seed: [u8; 32] = random_array()?;
        Ok(Self {
            server: HybridIdentity::from_seed(&server_seed)?,
            client: HybridIdentity::from_seed(&client_seed)?,
            attacker: HybridIdentity::from_seed(&attacker_seed)?,
            outsider: HybridIdentity::generate()?,
            server_seed,
            client_seed,
            attacker_seed,
            tls: Tls::generate()?,
        })
    }

    /// A registry that enrolls `key`, for the transport identity of a client that presents no certificate.
    pub fn registry_with(key: &HybridIdentity) -> MemoryRegistry {
        let registry = MemoryRegistry::new();
        registry.enroll(Enrollment { key: key.public(), peer_id: PeerId::anonymous(), enrolled_at_unix_millis: now_millis() });
        registry
    }
}
