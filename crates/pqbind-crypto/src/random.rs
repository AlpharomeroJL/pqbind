// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Draw key and seed bytes from the operating system random source, failing loudly instead of falling back.
//!
//! Every key and seed this crate makes comes from `SysRng` (`getrandom`: `BCryptGenRandom` on Windows,
//! `getentropy` on macOS and iOS, `getrandom(2)` on Linux and Android). A failure of the source is an error, never a weaker fallback.

use rand::TryRng as _;
use rand::rngs::SysRng;

use crate::CryptoError;

/// Fill `buf` from the operating system random source.
///
/// # Errors
///
/// [`CryptoError::RandomUnavailable`] when the operating system source fails.
pub fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    SysRng.try_fill_bytes(buf).map_err(|_| CryptoError::RandomUnavailable)
}

/// `N` bytes from the operating system random source.
///
/// # Errors
///
/// [`CryptoError::RandomUnavailable`] when the operating system source fails.
pub fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut out = [0_u8; N];
    fill_random(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{fill_random, random_array};

    #[test]
    fn two_draws_differ() {
        let first: [u8; 32] = random_array().expect("random source");
        let mut second = [0_u8; 32];
        fill_random(&mut second).expect("random source");
        assert_ne!(first, second);
    }
}
