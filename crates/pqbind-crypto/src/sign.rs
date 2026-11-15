// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Sign and verify with Ed25519 (RFC 8032), with strict verification and a signing key that zeroizes on drop.
//!
//! Verification is `ed25519-dalek`'s strict mode: a non-canonical `S`, a small-order `R` and a small-order (weak) public key
//! are refused, so a signature cannot be malleated into a second valid one.

use ed25519_dalek::Signer as _;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::random::random_array;
use crate::{CryptoError, SecretBytes};

/// The length of an Ed25519 secret seed, in bytes.
pub const SEED_LEN: usize = 32;

/// The length of an Ed25519 public key, in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// The length of an Ed25519 signature, in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// An Ed25519 signing key.
///
/// The secret is zeroized on drop (the inner `ed25519-dalek` key zeroizes itself). There is no `Debug`, `Display` or `Clone`.
pub struct SigningKey(ed25519_dalek::SigningKey);

// The only field is `ed25519_dalek::SigningKey`, which is `ZeroizeOnDrop` with the workspace's `zeroize` feature.
impl ZeroizeOnDrop for SigningKey {}

impl SigningKey {
    /// The signing key for the 32-byte RFC 8032 secret `seed`.
    #[must_use]
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// A new signing key from the operating system random source.
    ///
    /// # Errors
    ///
    /// [`CryptoError::RandomUnavailable`] when the random source fails.
    pub fn generate() -> Result<Self, CryptoError> {
        let seed = Zeroizing::new(random_array::<SEED_LEN>()?);
        Ok(Self::from_seed(&seed))
    }

    /// The secret seed, for sealing into a key store. Keep the value short-lived.
    #[must_use]
    pub fn to_seed(&self) -> SecretBytes {
        SecretBytes::from_slice(self.0.as_bytes())
    }

    /// The public key that verifies this key's signatures.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    /// The Ed25519 signature of `message`.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message))
    }
}

/// An Ed25519 public key. Public data, so it may be logged and compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    /// Parse a 32-byte compressed Edwards point.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKeyLength`] unless `bytes` is 32 bytes, and [`CryptoError::Malformed`] when they are not a point.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let bytes: &[u8; PUBLIC_KEY_LEN] = bytes.try_into().map_err(|_| CryptoError::InvalidKeyLength)?;
        ed25519_dalek::VerifyingKey::from_bytes(bytes).map(Self).map_err(|_| CryptoError::Malformed)
    }

    /// The 32-byte encoding.
    #[must_use]
    pub fn to_bytes(self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Verify `signature` over `message` strictly.
    ///
    /// # Errors
    ///
    /// [`CryptoError::SignatureInvalid`] when the signature does not verify, is non-canonical or uses a small-order point, or
    /// when this key is a weak (small-order) key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
        self.0.verify_strict(message, &signature.0).map_err(|_| CryptoError::SignatureInvalid)
    }
}

/// An Ed25519 signature (the 32-byte `R` followed by the 32-byte `S`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature(ed25519_dalek::Signature);

impl Signature {
    /// Parse a 64-byte signature. The scalar range is checked at verification.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidLength`] unless `bytes` is 64 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        ed25519_dalek::Signature::from_slice(bytes).map(Self).map_err(|_| CryptoError::InvalidLength)
    }

    /// The 64-byte encoding.
    #[must_use]
    pub fn to_bytes(self) -> [u8; SIGNATURE_LEN] {
        self.0.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::{Signature, SigningKey, VerifyingKey};
    use crate::zeroize_check::wipes_on_drop;

    #[test]
    fn a_generated_key_signs_and_its_seed_restores_it() {
        let key = SigningKey::generate().expect("random source");
        let signature = key.sign(b"statement");
        assert!(key.verifying_key().verify(b"statement", &signature).is_ok());
        let seed: [u8; 32] = key.to_seed().expose_secret().try_into().expect("32 bytes");
        assert_eq!(SigningKey::from_seed(&seed).verifying_key(), key.verifying_key());
    }

    /// The Ed25519 group order `L` as 32 little-endian bytes.
    const GROUP_ORDER: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0x10,
    ];

    #[test]
    fn verification_is_strict_and_refuses_what_plain_verification_would_accept() {
        use ed25519_dalek::Verifier as _;

        // A weak key (the identity point, encoded 01 00 ... 00) with R = identity and S = 0 satisfies the plain verification
        // equation for every message, so only the strict mode refuses it.
        let mut weak_key = [0_u8; 32];
        weak_key[0] = 1;
        let mut forged = [0_u8; 64];
        forged[0] = 1;
        let plain_key = ed25519_dalek::VerifyingKey::from_bytes(&weak_key).expect("the identity decodes");
        let plain_signature = ed25519_dalek::Signature::from_bytes(&forged);
        assert!(plain_key.verify(b"any message", &plain_signature).is_ok(), "plain verification accepts the small-order forgery");
        let key = VerifyingKey::from_bytes(&weak_key).expect("the identity decodes");
        let signature = Signature::from_slice(&forged).expect("64 bytes");
        assert!(matches!(key.verify(b"any message", &signature), Err(crate::CryptoError::SignatureInvalid)));

        // A non-canonical S (S + L) is refused, and the canonical signature over the same message is accepted.
        let signing = SigningKey::from_seed(&[5_u8; 32]);
        let good = signing.sign(b"strict");
        assert!(signing.verifying_key().verify(b"strict", &good).is_ok());
        let mut bytes = good.to_bytes();
        let mut carry = false;
        for (s, l) in bytes[32..].iter_mut().zip(GROUP_ORDER) {
            let (sum, first) = s.overflowing_add(l);
            let (sum, second) = sum.overflowing_add(u8::from(carry));
            *s = sum;
            carry = first || second;
        }
        assert!(!carry, "S + L stays below 2^256");
        let malleated = Signature::from_slice(&bytes).expect("64 bytes");
        assert_ne!(malleated, good);
        assert!(matches!(signing.verifying_key().verify(b"strict", &malleated), Err(crate::CryptoError::SignatureInvalid)));
    }

    #[test]
    fn the_inner_signing_key_wipes_on_drop() {
        // The hand-written `ZeroizeOnDrop` marker above rests on this: the only field wipes itself.
        wipes_on_drop(&SigningKey::from_seed(&[8_u8; 32]).0);
    }
}
