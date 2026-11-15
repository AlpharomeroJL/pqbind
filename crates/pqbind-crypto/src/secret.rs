// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Hold secret output bytes (derived keys) that zeroize on drop and never print.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret bytes returned by a derivation, an unwrap or an open.
///
/// The buffer is zeroized when the value drops. There is deliberately no `Debug`, `Display` or `Clone`: the only way to read
/// the bytes is [`SecretBytes::expose_secret`], which makes every use visible in review.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Take ownership of `bytes` as a secret. The vector is zeroized when the value drops.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Copy `bytes` into a new secret buffer. The caller remains responsible for its own copy.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// A zero-filled secret buffer of `len` bytes, to be filled in place by a primitive.
    pub(crate) fn zeroed(len: usize) -> Self {
        Self(vec![0; len])
    }

    /// The secret bytes. Keep the borrow short and never log or format it.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    /// The secret bytes for a primitive that writes its output in place.
    pub(crate) fn expose_secret_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
