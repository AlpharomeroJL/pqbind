// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Sign and verify with ML-DSA-87 (FIPS 204), with a signing key that zeroizes on drop.
//!
//! The CNSA 2.0 parameter set: the lower ML-DSA sets are not offered. Signing is the deterministic variant with an empty context
//! string, so it needs no random source and cannot fail on one. Callers put their own domain label in the message
//! ([`crate::hybrid`]). This module is the post-quantum half: a trust decision takes both halves, through [`crate::hybrid`] or
//! through the caller requiring both.

use ml_dsa::signature::Signer as _;
use ml_dsa::{EncodedVerifyingKey, MlDsa87, Seed};
use zeroize::{Zeroize as _, ZeroizeOnDrop};

use crate::CryptoError;

/// The length of an ML-DSA seed, in bytes.
pub const SEED_LEN: usize = 32;

/// The length of an ML-DSA-87 public key, in bytes.
pub const PUBLIC_KEY_LEN: usize = 2592;

/// The length of an ML-DSA-87 signature, in bytes.
pub const SIGNATURE_LEN: usize = 4627;

/// The length of `rho`, the public seed that opens a public key, in bytes. What follows it is `t1`.
const RHO_LEN: usize = 32;

/// An ML-DSA-87 signing key.
///
/// The secret is zeroized on drop (the inner key wipes its seed and its expanded form). There is no `Debug`, `Display` or `Clone`.
pub struct MlDsaSigningKey(ml_dsa::SigningKey<MlDsa87>);

// The only field is `ml_dsa::SigningKey`, which is `ZeroizeOnDrop` with the workspace's `zeroize` feature.
impl ZeroizeOnDrop for MlDsaSigningKey {}

impl MlDsaSigningKey {
    /// The signing key expanded from the 32-byte `seed`.
    #[must_use]
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let mut held = Seed::default();
        held.copy_from_slice(seed);
        let key = ml_dsa::SigningKey::<MlDsa87>::from_seed(&held);
        held.as_mut_slice().zeroize();
        Self(key)
    }

    /// The public key that verifies this key's signatures.
    #[must_use]
    pub fn verifying_key(&self) -> MlDsaVerifyingKey {
        MlDsaVerifyingKey::from_inner(ml_dsa::Keypair::verifying_key(&self.0))
    }

    /// The ML-DSA-87 signature of `message`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidParameter`] when the primitive refuses to sign.
    pub fn sign(&self, message: &[u8]) -> Result<MlDsaSignature, CryptoError> {
        let signature = self.0.try_sign(message).map_err(|_| CryptoError::InvalidParameter)?;
        Ok(MlDsaSignature { encoded: signature.encode().to_vec() })
    }
}

/// An ML-DSA-87 public key. Public data, so it may be logged and compared.
#[derive(Clone)]
pub struct MlDsaVerifyingKey {
    inner: ml_dsa::VerifyingKey<MlDsa87>,
    encoded: Vec<u8>,
}

impl MlDsaVerifyingKey {
    /// The key `inner` with its encoding.
    fn from_inner(inner: ml_dsa::VerifyingKey<MlDsa87>) -> Self {
        let encoded = inner.encode().to_vec();
        Self { inner, encoded }
    }

    /// Parse a 2592-byte public key.
    ///
    /// A key whose `t1` is all zero is refused: the verification equation then no longer depends on the key, so anyone can make a
    /// signature that verifies under it. Any 2592 bytes decode, so this is the one key a parser can tell is worthless.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKeyLength`] unless `bytes` is 2592 bytes, and [`CryptoError::Malformed`] for a key with an all-zero
    /// `t1`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let encoded = EncodedVerifyingKey::<MlDsa87>::try_from(bytes).map_err(|_| CryptoError::InvalidKeyLength)?;
        if bytes.iter().skip(RHO_LEN).all(|byte| *byte == 0) {
            return Err(CryptoError::Malformed);
        }
        Ok(Self { inner: ml_dsa::VerifyingKey::<MlDsa87>::decode(&encoded), encoded: bytes.to_vec() })
    }

    /// The 2592-byte encoding.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encoded.clone()
    }

    /// Verify `signature` over `message`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::SignatureInvalid`] when the signature does not decode or does not verify.
    pub fn verify(&self, message: &[u8], signature: &MlDsaSignature) -> Result<(), CryptoError> {
        let decoded = ml_dsa::Signature::<MlDsa87>::try_from(signature.encoded.as_slice()).map_err(|_| CryptoError::SignatureInvalid)?;
        if self.inner.verify_with_context(message, &[], &decoded) { Ok(()) } else { Err(CryptoError::SignatureInvalid) }
    }
}

impl PartialEq for MlDsaVerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.encoded == other.encoded
    }
}

impl Eq for MlDsaVerifyingKey {}

impl std::fmt::Debug for MlDsaVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaVerifyingKey").field("len", &self.encoded.len()).finish_non_exhaustive()
    }
}

/// An ML-DSA-87 signature, as its encoding. It is decoded when it is verified.
#[derive(Clone, PartialEq, Eq)]
pub struct MlDsaSignature {
    encoded: Vec<u8>,
}

impl MlDsaSignature {
    /// Take a 4627-byte signature. Its contents are checked at verification.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidLength`] unless `bytes` is 4627 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() == SIGNATURE_LEN { Ok(Self { encoded: bytes.to_vec() }) } else { Err(CryptoError::InvalidLength) }
    }

    /// The 4627-byte encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

impl std::fmt::Debug for MlDsaSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaSignature").field("len", &self.encoded.len()).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{MlDsaSignature, MlDsaSigningKey, MlDsaVerifyingKey, PUBLIC_KEY_LEN, SIGNATURE_LEN};
    use crate::CryptoError;
    use crate::zeroize_check::wipes_on_drop;

    #[test]
    fn a_key_signs_verifies_and_keeps_its_sizes() {
        let key = MlDsaSigningKey::from_seed(&[3_u8; 32]);
        let signature = key.sign(b"statement").expect("sign");
        assert_eq!(signature.as_bytes().len(), SIGNATURE_LEN);
        let public = key.verifying_key();
        assert_eq!(public.to_bytes().len(), PUBLIC_KEY_LEN);
        assert!(public.verify(b"statement", &signature).is_ok());
        assert_eq!(MlDsaVerifyingKey::from_bytes(&public.to_bytes()).expect("round trip"), public);
        assert_eq!(public.verify(b"another", &signature).err(), Some(CryptoError::SignatureInvalid));
    }

    #[test]
    fn signing_is_deterministic_and_a_seed_restores_the_key() {
        let first = MlDsaSigningKey::from_seed(&[4_u8; 32]);
        let second = MlDsaSigningKey::from_seed(&[4_u8; 32]);
        assert_eq!(first.sign(b"m").expect("sign"), second.sign(b"m").expect("sign"));
        assert_eq!(first.verifying_key(), second.verifying_key());
        assert_ne!(first.verifying_key(), MlDsaSigningKey::from_seed(&[5_u8; 32]).verifying_key());
    }

    #[test]
    fn a_changed_or_cut_signature_and_another_key_are_refused() {
        let key = MlDsaSigningKey::from_seed(&[6_u8; 32]);
        let signature = key.sign(b"m").expect("sign");
        let mut bytes = signature.as_bytes().to_vec();
        bytes[0] ^= 1;
        let changed = MlDsaSignature::from_slice(&bytes).expect("right length");
        assert_eq!(key.verifying_key().verify(b"m", &changed).err(), Some(CryptoError::SignatureInvalid));
        assert_eq!(MlDsaSignature::from_slice(&bytes[1..]).err(), Some(CryptoError::InvalidLength));
        let other = MlDsaSigningKey::from_seed(&[7_u8; 32]).verifying_key();
        assert_eq!(other.verify(b"m", &signature).err(), Some(CryptoError::SignatureInvalid));
        assert_eq!(MlDsaVerifyingKey::from_bytes(&[0_u8; 31]).err(), Some(CryptoError::InvalidKeyLength));
    }

    #[test]
    fn a_public_key_with_an_all_zero_t1_is_refused_whatever_its_rho() {
        assert_eq!(MlDsaVerifyingKey::from_bytes(&[0_u8; PUBLIC_KEY_LEN]).err(), Some(CryptoError::Malformed));
        let mut any_rho = [0_u8; PUBLIC_KEY_LEN];
        any_rho[..32].fill(0xa5);
        assert_eq!(MlDsaVerifyingKey::from_bytes(&any_rho).err(), Some(CryptoError::Malformed));
        any_rho[32] = 1;
        assert!(MlDsaVerifyingKey::from_bytes(&any_rho).is_ok(), "one set bit of t1 is enough for the parser");
    }

    #[test]
    fn the_inner_signing_key_wipes_on_drop() {
        // The hand-written `ZeroizeOnDrop` marker above rests on this: the only field wipes itself.
        wipes_on_drop(&MlDsaSigningKey::from_seed(&[8_u8; 32]).0);
    }
}
