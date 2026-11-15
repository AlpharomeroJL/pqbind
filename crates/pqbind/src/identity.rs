// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Make a hybrid identity from one seed, expose its public key, and compute the SHA-384 pin of that public key.
//!
//! A pin is the SHA-384 of the whole encoded public key (Ed25519 half and ML-DSA-87 half together), 48 bytes, so it fits in a QR code.
//! Pinning the whole key matters: a transport identity that covers only the Ed25519 half would leave the ML-DSA half unbound.

use pqbind_crypto::SecretBytes;
use pqbind_crypto::hash::sha384;
use pqbind_crypto::hybrid::{HybridSigningKey, HybridVerifyingKey, SEED_LEN as KEY_SEED_LEN};

use crate::error::Error;

/// The length of a pin, in bytes.
pub const PIN_LEN: usize = 48;

/// The length of the seed a hybrid identity is made from, in bytes.
pub const SEED_LEN: usize = KEY_SEED_LEN;

/// The longest transport identity a [`PeerId`] holds, in bytes.
pub const MAX_PEER_ID_LEN: usize = 1024;

/// A hybrid Ed25519 and ML-DSA-87 identity: the secret a peer proves with. It prints nothing and cannot be cloned.
pub struct HybridIdentity {
    key: HybridSigningKey,
}

impl HybridIdentity {
    /// A new identity from the operating system random source.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] when the random source fails.
    pub fn generate() -> Result<Self, Error> {
        Ok(Self { key: HybridSigningKey::generate()? })
    }

    /// The identity of a 32-byte seed. The same seed always gives the same identity.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] if the keys cannot be derived.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Result<Self, Error> {
        Ok(Self { key: HybridSigningKey::from_seed(seed)? })
    }

    /// The secret seed, for sealing into a key store. Keep the value short-lived.
    #[must_use]
    pub fn to_seed(&self) -> SecretBytes {
        self.key.to_seed()
    }

    /// The public identity that others enroll or pin.
    #[must_use]
    pub fn public(&self) -> PublicIdentity {
        let key = self.key.verifying_key();
        let encoded = key.to_bytes();
        PublicIdentity { key, encoded }
    }

    /// The pin of this identity's public key.
    #[must_use]
    pub fn pin(&self) -> Pin {
        Pin::of(&self.public())
    }

    pub(crate) const fn signing_key(&self) -> &HybridSigningKey {
        &self.key
    }
}

impl std::fmt::Debug for HybridIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HybridIdentity(..)")
    }
}

/// A hybrid public key: public data, so it may be logged and compared.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    key: HybridVerifyingKey,
    encoded: Vec<u8>,
}

impl PublicIdentity {
    /// Parse an encoded public key. The encoding must be the canonical one: a key that decodes but re-encodes differently is refused,
    /// so the same key always has one pin.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a wrong length, an unknown suite, a bad half or a non-canonical encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let key = HybridVerifyingKey::from_bytes(bytes).map_err(|_| Error::Malformed)?;
        let encoded = key.to_bytes();
        if encoded != bytes {
            return Err(Error::Malformed);
        }
        Ok(Self { key, encoded })
    }

    /// The canonical encoding: the suite identifier, the Ed25519 half and the ML-DSA half.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// The pin of this key.
    #[must_use]
    pub fn pin(&self) -> Pin {
        Pin::of(self)
    }

    pub(crate) const fn verifying_key(&self) -> &HybridVerifyingKey {
        &self.key
    }
}

impl std::fmt::Debug for PublicIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "PublicIdentity(pin {})", &self.pin().to_hex()[..16])
    }
}

/// The SHA-384 of a whole encoded public key. Public data.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pin([u8; PIN_LEN]);

impl Pin {
    /// The pin of `key`.
    #[must_use]
    pub fn of(key: &PublicIdentity) -> Self {
        Self(sha384(key.as_bytes()))
    }

    /// A pin from its 48 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PIN_LEN]) -> Self {
        Self(bytes)
    }

    /// The 48 bytes of the pin.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PIN_LEN] {
        &self.0
    }

    /// The pin as 96 lowercase hex digits.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(PIN_LEN * 2);
        for byte in self.0 {
            out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
        }
        out
    }

    /// Read a pin from 96 hex digits (either case).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for any other length or a character that is not a hex digit.
    pub fn from_hex(text: &str) -> Result<Self, Error> {
        let bytes = text.as_bytes();
        if bytes.len() != PIN_LEN * 2 {
            return Err(Error::Malformed);
        }
        let mut out = [0_u8; PIN_LEN];
        for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
            let high = char::from(pair[0]).to_digit(16).ok_or(Error::Malformed)?;
            let low = char::from(pair[1]).to_digit(16).ok_or(Error::Malformed)?;
            *slot = u8::try_from((high << 4) | low).map_err(|_| Error::Malformed)?;
        }
        Ok(Self(out))
    }
}

impl std::fmt::Debug for Pin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Pin({})", self.to_hex())
    }
}

/// The identity the transport already authenticated for one end of a connection: an iroh node ID, a certificate hash, or any bytes the
/// application chooses. It may be empty (an end the transport does not authenticate). Both peers' identities are signed into every
/// proof, so a proof holds for one pair of peers.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct PeerId(Vec<u8>);

impl PeerId {
    /// A peer identity from bytes.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] when it is longer than [`MAX_PEER_ID_LEN`].
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let bytes = bytes.into();
        if bytes.len() > MAX_PEER_ID_LEN {
            return Err(Error::InvalidInput);
        }
        Ok(Self(bytes))
    }

    /// The empty identity, for an end the transport does not authenticate.
    #[must_use]
    pub const fn anonymous() -> Self {
        Self(Vec::new())
    }

    /// The identity of a TLS certificate: the SHA-384 of its DER encoding (48 bytes). The transport adapters use it for a peer that
    /// presented a certificate.
    #[must_use]
    pub fn of_certificate(der: &[u8]) -> Self {
        Self(sha384(der).to_vec())
    }

    /// The identity bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Whether this is the empty identity.
    #[must_use]
    pub fn is_anonymous(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{HybridIdentity, MAX_PEER_ID_LEN, PeerId, Pin, PublicIdentity};
    use crate::error::Error;

    fn identity(fill: u8) -> HybridIdentity {
        HybridIdentity::from_seed(&[fill; 32]).expect("a seed")
    }

    #[test]
    fn a_seed_always_gives_the_same_identity_and_another_seed_another() {
        assert_eq!(identity(1).public(), identity(1).public());
        assert_ne!(identity(1).public(), identity(2).public());
        assert_eq!(identity(1).pin(), identity(1).public().pin());
    }

    #[test]
    fn a_public_key_round_trips_and_a_changed_or_cut_one_is_refused() {
        let public = identity(3).public();
        assert_eq!(PublicIdentity::from_bytes(public.as_bytes()), Ok(public.clone()));
        assert_eq!(PublicIdentity::from_bytes(&public.as_bytes()[1..]), Err(Error::Malformed), "cut");
        let mut longer = public.as_bytes().to_vec();
        longer.push(0);
        assert_eq!(PublicIdentity::from_bytes(&longer), Err(Error::Malformed), "extended");
        assert_eq!(PublicIdentity::from_bytes(&[]), Err(Error::Malformed), "empty");
    }

    #[test]
    fn a_pin_covers_the_whole_key_so_a_changed_ml_dsa_half_changes_it() {
        let public = identity(4).public();
        let mut other = public.as_bytes().to_vec();
        let last = other.len() - 1;
        other[last] ^= 1;
        // The flipped key may or may not parse; if it parses it must have another pin.
        if let Ok(parsed) = PublicIdentity::from_bytes(&other) {
            assert_ne!(parsed.pin(), public.pin());
        }
        assert_ne!(identity(4).pin(), identity(5).pin());
    }

    #[test]
    fn a_pin_round_trips_through_hex_in_either_case_and_bad_hex_is_refused() {
        let pin = identity(6).pin();
        let hex = pin.to_hex();
        assert_eq!(hex.len(), 96);
        assert_eq!(Pin::from_hex(&hex), Ok(pin));
        assert_eq!(Pin::from_hex(&hex.to_uppercase()), Ok(pin));
        assert_eq!(Pin::from_hex(&hex[..94]), Err(Error::Malformed), "short");
        assert_eq!(Pin::from_hex(&format!("{}zz", &hex[..94])), Err(Error::Malformed), "not hex");
    }

    #[test]
    fn a_peer_id_may_be_empty_but_not_longer_than_the_limit() {
        assert!(PeerId::anonymous().is_anonymous());
        assert!(PeerId::new(vec![7; MAX_PEER_ID_LEN]).is_ok());
        assert_eq!(PeerId::new(vec![7; MAX_PEER_ID_LEN + 1]), Err(Error::InvalidInput));
    }

    #[test]
    fn a_certificate_identity_is_the_sha_384_of_its_der_bytes() {
        let id = PeerId::of_certificate(b"certificate bytes");
        assert_eq!(id.as_bytes().len(), 48);
        assert_eq!(id, PeerId::of_certificate(b"certificate bytes"));
        assert_ne!(id, PeerId::of_certificate(b"other certificate"));
        assert!(!id.is_anonymous());
    }

    #[test]
    fn debug_output_names_no_secret() {
        assert_eq!(format!("{:?}", identity(8)), "HybridIdentity(..)");
    }
}
