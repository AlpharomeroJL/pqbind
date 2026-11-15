// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Sign and verify with the hybrid Ed25519 and ML-DSA-87 suite, where a signature verifies only when both halves verify.
//!
//! Forging a signature needs a break of Ed25519 and of ML-DSA-87 together. Both halves sign the same
//! bytes, `LABEL | SHA-512(message)`:
//!
//! - The label stops a half being lifted out and passed off as a plain Ed25519 or ML-DSA signature, and a plain signature being
//!   passed off as a half.
//! - The digest keeps what is signed small, so a multi-gigabyte update package is hashed once and never copied.
//!
//! ```text
//! public key: suite ID 2 | Ed25519 public key 32 | ML-DSA-87 public key 2592
//! signature:  suite ID 2 | Ed25519 signature 64 | ML-DSA-87 signature 4627
//! ```
//!
//! One 32-byte seed makes both halves. It is the Ed25519 seed, and the ML-DSA seed is HKDF-SHA384 of it, so one stored seed restores
//! both halves. Recovering the Ed25519 scalar from its public key does not give the seed (the scalar is a SHA-512 output), so a
//! break of Ed25519 reveals nothing of the ML-DSA half.
//!
//! Verification evaluates both halves whatever the first one answered; both must pass.

use sha2::{Digest as _, Sha512};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::kdf::hkdf_sha384;
use crate::mldsa::{self, MlDsaSignature, MlDsaSigningKey, MlDsaVerifyingKey};
use crate::random::random_array;
use crate::sign::{self, Signature, SigningKey, VerifyingKey};
use crate::suite::{self, SUITE_ID_LEN, SignatureSuite};
use crate::{CryptoError, SecretBytes};

/// The domain label both halves sign in front of the digest.
const LABEL: &[u8] = b"pqbind/hybrid-signature/ed25519+ml-dsa-87/v1\0";

/// The HKDF `info` of the ML-DSA seed.
const ML_DSA_SEED_INFO: &[u8] = b"pqbind/hybrid-signature/ml-dsa-87-seed/v1";

/// The name a signed document writes in its `alg` field for this suite.
pub const ALGORITHM: &str = "ed25519+ml-dsa-87";

/// The length of a hybrid seed, in bytes.
pub const SEED_LEN: usize = sign::SEED_LEN;

/// The length of an encoded hybrid public key, in bytes.
pub const PUBLIC_KEY_LEN: usize = SUITE_ID_LEN + sign::PUBLIC_KEY_LEN + mldsa::PUBLIC_KEY_LEN;

/// The length of an encoded hybrid signature, in bytes.
pub const SIGNATURE_LEN: usize = SUITE_ID_LEN + sign::SIGNATURE_LEN + mldsa::SIGNATURE_LEN;

/// What both halves sign: the label and the SHA-512 digest of `message`.
///
/// Public so an independent verifier or a test harness can reproduce exactly what each half signs, for example to build a forged
/// signature whose halves come from different keys.
#[must_use]
pub fn signed_bytes(message: &[u8]) -> Vec<u8> {
    let digest = Sha512::digest(message);
    let mut out = Vec::with_capacity(LABEL.len().saturating_add(digest.len()));
    out.extend_from_slice(LABEL);
    out.extend_from_slice(&digest);
    out
}

/// The ML-DSA signing key of the hybrid seed `seed`.
///
/// # Errors
///
/// [`CryptoError::OutputTooLong`] only if the derivation were asked for more than HKDF gives, which it never is.
pub fn ml_dsa_key_of_seed(seed: &[u8; SEED_LEN]) -> Result<MlDsaSigningKey, CryptoError> {
    let derived = hkdf_sha384(seed, &[], ML_DSA_SEED_INFO, mldsa::SEED_LEN)?;
    let bytes = Zeroizing::new(<[u8; mldsa::SEED_LEN]>::try_from(derived.expose_secret()).map_err(|_| CryptoError::InvalidLength)?);
    Ok(MlDsaSigningKey::from_seed(&bytes))
}

/// A hybrid signing key.
///
/// The secret is zeroized on drop (both halves wipe themselves). There is no `Debug`, `Display` or `Clone`.
pub struct HybridSigningKey {
    suite: SignatureSuite,
    classical: SigningKey,
    post_quantum: MlDsaSigningKey,
}

// Both key fields are `ZeroizeOnDrop`, as `the_halves_wipe_on_drop` checks; the suite is no secret.
impl ZeroizeOnDrop for HybridSigningKey {}

impl HybridSigningKey {
    /// The signing key of the 32-byte `seed`, in the one suite this crate has ([`SignatureSuite::Ed25519MlDsa87`]).
    ///
    /// # Errors
    ///
    /// As [`ml_dsa_key_of_seed`].
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Result<Self, CryptoError> {
        Ok(Self { suite: SignatureSuite::Ed25519MlDsa87, classical: SigningKey::from_seed(seed), post_quantum: ml_dsa_key_of_seed(seed)? })
    }

    /// A new signing key from the operating system random source.
    ///
    /// # Errors
    ///
    /// [`CryptoError::RandomUnavailable`] when the random source fails.
    pub fn generate() -> Result<Self, CryptoError> {
        let seed = Zeroizing::new(random_array::<SEED_LEN>()?);
        Self::from_seed(&seed)
    }

    /// The secret seed, for sealing into a key store. Keep the value short-lived.
    #[must_use]
    pub fn to_seed(&self) -> SecretBytes {
        self.classical.to_seed()
    }

    /// The public key that verifies this key's signatures.
    #[must_use]
    pub fn verifying_key(&self) -> HybridVerifyingKey {
        HybridVerifyingKey { suite: self.suite, classical: self.classical.verifying_key(), post_quantum: self.post_quantum.verifying_key() }
    }

    /// The hybrid signature of `message`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidParameter`] when the ML-DSA primitive refuses to sign.
    pub fn sign(&self, message: &[u8]) -> Result<HybridSignature, CryptoError> {
        let bytes = signed_bytes(message);
        Ok(HybridSignature { suite: self.suite, classical: self.classical.sign(&bytes), post_quantum: self.post_quantum.sign(&bytes)? })
    }
}

/// A hybrid public key: both halves, which a trust root holds together. Public data, so it may be logged and compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridVerifyingKey {
    suite: SignatureSuite,
    classical: VerifyingKey,
    post_quantum: MlDsaVerifyingKey,
}

impl HybridVerifyingKey {
    /// Parse an encoded hybrid public key.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKeyLength`] for a suite this build does not have or the wrong length, and
    /// [`CryptoError::Malformed`] when the Ed25519 half is not a point or the ML-DSA half has an all-zero `t1`
    /// (see [`MlDsaVerifyingKey::from_bytes`]).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let (id, rest) = suite::split_id(bytes).ok_or(CryptoError::InvalidKeyLength)?;
        let suite = SignatureSuite::from_id(id).ok_or(CryptoError::InvalidKeyLength)?;
        let (classical, post_quantum) = rest.split_at_checked(sign::PUBLIC_KEY_LEN).ok_or(CryptoError::InvalidKeyLength)?;
        Ok(Self { suite, classical: VerifyingKey::from_bytes(classical)?, post_quantum: MlDsaVerifyingKey::from_bytes(post_quantum)? })
    }

    /// The encoding: the suite identifier, the Ed25519 half and the ML-DSA half.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_KEY_LEN);
        out.extend_from_slice(&self.suite.id().to_be_bytes());
        out.extend_from_slice(&self.classical.to_bytes());
        out.extend_from_slice(&self.post_quantum.to_bytes());
        out
    }

    /// The suite of this key.
    #[must_use]
    pub const fn suite(&self) -> SignatureSuite {
        self.suite
    }

    /// Verify `signature` over `message`: both halves must verify, under a signature of this key's suite.
    ///
    /// # Errors
    ///
    /// [`CryptoError::SignatureInvalid`] when either half does not verify or the suites differ.
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> Result<(), CryptoError> {
        let bytes = signed_bytes(message);
        let classical = self.classical.verify(&bytes, &signature.classical);
        let post_quantum = self.post_quantum.verify(&bytes, &signature.post_quantum);
        if signature.suite == self.suite && classical.is_ok() && post_quantum.is_ok() { Ok(()) } else { Err(CryptoError::SignatureInvalid) }
    }
}

/// A hybrid signature: both halves, with the suite they belong to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridSignature {
    suite: SignatureSuite,
    classical: Signature,
    post_quantum: MlDsaSignature,
}

impl HybridSignature {
    /// Parse an encoded hybrid signature. The contents of the halves are checked at verification.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidLength`] for a suite this build does not have or the wrong length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        let (id, rest) = suite::split_id(bytes).ok_or(CryptoError::InvalidLength)?;
        let suite = SignatureSuite::from_id(id).ok_or(CryptoError::InvalidLength)?;
        let (classical, post_quantum) = rest.split_at_checked(sign::SIGNATURE_LEN).ok_or(CryptoError::InvalidLength)?;
        Ok(Self { suite, classical: Signature::from_slice(classical)?, post_quantum: MlDsaSignature::from_slice(post_quantum)? })
    }

    /// The encoding: the suite identifier, the Ed25519 half and the ML-DSA half.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGNATURE_LEN);
        out.extend_from_slice(&self.suite.id().to_be_bytes());
        out.extend_from_slice(&self.classical.to_bytes());
        out.extend_from_slice(self.post_quantum.as_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{HybridSignature, HybridSigningKey, HybridVerifyingKey, PUBLIC_KEY_LEN, SIGNATURE_LEN, sign, signed_bytes};
    use crate::CryptoError;
    use crate::mldsa::MlDsaSigningKey;
    use crate::sign::SigningKey;
    use crate::suite::SignatureSuite;
    use crate::zeroize_check::wipes_on_drop;

    fn key(fill: u8) -> HybridSigningKey {
        HybridSigningKey::from_seed(&[fill; 32]).expect("seed")
    }

    #[test]
    fn a_signature_verifies_and_every_encoding_round_trips_at_its_size() {
        let key = key(1);
        let signature = key.sign(b"statement").expect("sign");
        let public = key.verifying_key();
        assert!(public.verify(b"statement", &signature).is_ok());
        assert_eq!(public.to_bytes().len(), PUBLIC_KEY_LEN);
        assert_eq!(signature.to_bytes().len(), SIGNATURE_LEN);
        assert_eq!(public.to_bytes()[..2], SignatureSuite::Ed25519MlDsa87.id().to_be_bytes());
        assert_eq!(signature.to_bytes()[..2], SignatureSuite::Ed25519MlDsa87.id().to_be_bytes());
        assert_eq!(HybridVerifyingKey::from_bytes(&public.to_bytes()).expect("round trip"), public);
        assert_eq!(HybridSignature::from_slice(&signature.to_bytes()).expect("round trip"), signature);
    }

    #[test]
    fn a_seed_restores_the_key() {
        let first = HybridSigningKey::generate().expect("random source");
        let seed: [u8; 32] = first.to_seed().expose_secret().try_into().expect("32 bytes");
        assert_eq!(HybridSigningKey::from_seed(&seed).expect("seed").verifying_key(), first.verifying_key());
    }

    #[test]
    fn tampering_with_the_ed25519_half_alone_fails() {
        let key = key(2);
        let mut bytes = key.sign(b"statement").expect("sign").to_bytes();
        bytes[2] ^= 1;
        let changed = HybridSignature::from_slice(&bytes).expect("right shape");
        assert_eq!(key.verifying_key().verify(b"statement", &changed).err(), Some(CryptoError::SignatureInvalid));
    }

    #[test]
    fn tampering_with_the_ml_dsa_half_alone_fails() {
        let key = key(3);
        let mut bytes = key.sign(b"statement").expect("sign").to_bytes();
        bytes[2 + sign::SIGNATURE_LEN] ^= 1;
        let changed = HybridSignature::from_slice(&bytes).expect("right shape");
        assert_eq!(key.verifying_key().verify(b"statement", &changed).err(), Some(CryptoError::SignatureInvalid));
    }

    #[test]
    fn a_good_half_of_one_key_with_a_bad_half_of_another_fails_both_ways() {
        // What a break of one algorithm gives an attacker: a valid half for the victim's key, and nothing for the other half.
        let victim = key(4);
        let attacker = key(5);
        let good = victim.sign(b"statement").expect("sign").to_bytes();
        let forged = attacker.sign(b"statement").expect("sign").to_bytes();
        let split = 2 + sign::SIGNATURE_LEN;
        let classical_only = [&good[..split], &forged[split..]].concat();
        let post_quantum_only = [&forged[..split], &good[split..]].concat();
        for mixed in [classical_only, post_quantum_only] {
            let signature = HybridSignature::from_slice(&mixed).expect("right shape");
            assert_eq!(victim.verifying_key().verify(b"statement", &signature).err(), Some(CryptoError::SignatureInvalid));
        }
    }

    #[test]
    fn a_trust_root_with_either_public_half_replaced_refuses() {
        let key = key(6);
        let other = self::key(7);
        let signature = key.sign(b"statement").expect("sign");
        let split = 2 + crate::sign::PUBLIC_KEY_LEN;
        let (ours, theirs) = (key.verifying_key().to_bytes(), other.verifying_key().to_bytes());
        for mixed in [[&ours[..split], &theirs[split..]].concat(), [&theirs[..split], &ours[split..]].concat()] {
            let public = HybridVerifyingKey::from_bytes(&mixed).expect("right shape");
            assert_eq!(public.verify(b"statement", &signature).err(), Some(CryptoError::SignatureInvalid));
        }
    }

    #[test]
    fn a_plain_signature_over_the_bare_message_is_not_a_half() {
        // A plain Ed25519 and a plain ML-DSA signature over the message, by the right keys, in the hybrid wrapper.
        let seed = [8_u8; 32];
        let hybrid = HybridSigningKey::from_seed(&seed).expect("seed");
        let classical = SigningKey::from_seed(&seed).sign(b"statement").to_bytes();
        let post_quantum = super::ml_dsa_key_of_seed(&seed).expect("seed").sign(b"statement").expect("sign");
        let mut encoded = SignatureSuite::Ed25519MlDsa87.id().to_be_bytes().to_vec();
        encoded.extend_from_slice(&classical);
        encoded.extend_from_slice(post_quantum.as_bytes());
        let signature = HybridSignature::from_slice(&encoded).expect("right shape");
        assert_eq!(hybrid.verifying_key().verify(b"statement", &signature).err(), Some(CryptoError::SignatureInvalid));
    }

    #[test]
    fn a_half_does_not_verify_as_a_plain_signature_over_the_message() {
        let seed = [9_u8; 32];
        let hybrid = HybridSigningKey::from_seed(&seed).expect("seed");
        let bytes = hybrid.sign(b"statement").expect("sign").to_bytes();
        let half = crate::sign::Signature::from_slice(&bytes[2..2 + sign::SIGNATURE_LEN]).expect("64 bytes");
        assert!(SigningKey::from_seed(&seed).verifying_key().verify(b"statement", &half).is_err());
        assert!(SigningKey::from_seed(&seed).verifying_key().verify(&signed_bytes(b"statement"), &half).is_ok(), "control");
    }

    #[test]
    fn a_changed_message_a_cut_signature_and_an_unknown_suite_are_refused() {
        let key = key(10);
        let signature = key.sign(b"statement").expect("sign");
        assert_eq!(key.verifying_key().verify(b"another", &signature).err(), Some(CryptoError::SignatureInvalid));
        let bytes = signature.to_bytes();
        assert_eq!(HybridSignature::from_slice(&bytes[..bytes.len() - 1]).err(), Some(CryptoError::InvalidLength));
        let mut unknown = bytes.clone();
        unknown[0] = 0xff;
        assert_eq!(HybridSignature::from_slice(&unknown).err(), Some(CryptoError::InvalidLength));
        let public = key.verifying_key().to_bytes();
        assert_eq!(HybridVerifyingKey::from_bytes(&public[..32]).err(), Some(CryptoError::InvalidKeyLength));
    }

    #[test]
    fn the_halves_wipe_on_drop() {
        // The hand-written `ZeroizeOnDrop` marker above rests on this.
        let key = key(11);
        let (classical, post_quantum): (&SigningKey, &MlDsaSigningKey) = (&key.classical, &key.post_quantum);
        wipes_on_drop(classical);
        wipes_on_drop(post_quantum);
    }
}
