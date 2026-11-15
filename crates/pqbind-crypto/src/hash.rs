// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Give the SHA-384 and HMAC-SHA-384 of the `sha2` and `hmac` crates to callers that need a NIST hash.
//!
//! Hashing is SHA-384 and keying is HMAC-SHA-384, the CNSA 2.0 strength.

use hkdf::hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest as _, Sha384};

use crate::CryptoError;

/// The SHA-384 output length, in bytes.
pub const SHA384_LEN: usize = 48;

/// The SHA-384 digest of `data`.
#[must_use]
pub fn sha384(data: &[u8]) -> [u8; SHA384_LEN] {
    Sha384::digest(data).into()
}

/// The HMAC-SHA-384 (RFC 2104) of `data` under `key`.
///
/// # Errors
///
/// [`CryptoError::InvalidKeyLength`] when the primitive refuses the key; HMAC takes a key of any length, so it never does today.
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> Result<[u8; SHA384_LEN], CryptoError> {
    let mut mac = <Hmac<Sha384> as KeyInit>::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    Mac::update(&mut mac, data);
    Ok(Mac::finalize(mac).into_bytes().into())
}

/// Check an HMAC-SHA-384 tag in constant time: `true` only when `expected` is the tag of `data` under `key`.
#[must_use]
pub fn hmac_sha384_verify(key: &[u8], data: &[u8], expected: &[u8]) -> bool {
    let Ok(mut mac) = <Hmac<Sha384> as KeyInit>::new_from_slice(key) else {
        return false;
    };
    Mac::update(&mut mac, data);
    Mac::verify_slice(mac, expected).is_ok()
}

/// The length of a SHA-384 digest in lowercase hex.
pub const SHA384_HEX_LEN: usize = SHA384_LEN * 2;

/// Lowercase hex of the SHA-384 digest of `data`.
#[must_use]
pub fn sha384_hex(data: &[u8]) -> String {
    hex_of(&sha384(data))
}

/// Whether `text` has the shape of a SHA-384 digest: exactly 96 lowercase hex digits.
#[must_use]
pub fn is_sha384_hex(text: &str) -> bool {
    text.len() == SHA384_HEX_LEN && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A SHA-384 computed in parts, for input too large to hold or that arrives in pieces.
#[derive(Clone, Default)]
pub struct Sha384Hasher(Sha384);

impl std::fmt::Debug for Sha384Hasher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Sha384Hasher")
    }
}

impl Sha384Hasher {
    /// A hasher over no input yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `data` to the input.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        sha2::Digest::update(&mut self.0, data.as_ref());
    }

    /// The digest of everything added.
    #[must_use]
    pub fn finalize(self) -> [u8; SHA384_LEN] {
        sha2::Digest::finalize(self.0).into()
    }

    /// Lowercase hex of the digest of everything added.
    #[must_use]
    pub fn finalize_hex(self) -> String {
        hex_of(&self.finalize())
    }
}

/// Lowercase hex of `digest`.
fn hex_of(digest: &[u8; SHA384_LEN]) -> String {
    let mut out = String::with_capacity(SHA384_HEX_LEN);
    for byte in digest {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Sha384Hasher, hmac_sha384, hmac_sha384_verify, is_sha384_hex, sha384, sha384_hex};

    #[test]
    fn sha384_and_its_hmac_match_their_known_answers() {
        let digest = sha384(b"abc");
        assert_eq!(digest[..4], [0xcb, 0x00, 0x75, 0x3f], "FIPS 180-4 example");
        assert_eq!(digest[44..], [0x34, 0xc8, 0x25, 0xa7], "FIPS 180-4 example");
        // RFC 4231 test case 2.
        let tag = hmac_sha384(b"Jefe", b"what do ya want for nothing?").expect("any key");
        assert_eq!(tag[..4], [0xaf, 0x45, 0xd2, 0xe3]);
    }

    #[test]
    fn the_hex_and_streaming_forms_agree_with_the_one_shot_digest() {
        let abc = sha384_hex(b"abc");
        assert_eq!(
            abc, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            "FIPS 180-4 example"
        );
        assert!(is_sha384_hex(&abc));
        assert!(!is_sha384_hex(&abc.to_uppercase()), "uppercase is not the one spelling");
        assert!(!is_sha384_hex(&abc[..64]), "a SHA-256 length is not a SHA-384 digest");
        let mut hasher = Sha384Hasher::new();
        hasher.update(b"a");
        hasher.update(b"bc");
        assert_eq!(hasher.clone().finalize(), sha384(b"abc"));
        assert_eq!(hasher.finalize_hex(), abc);
    }

    #[test]
    fn hmac_verify_accepts_only_the_matching_tag() {
        let tag = hmac_sha384(b"key", b"chunk").expect("any key length");
        assert!(hmac_sha384_verify(b"key", b"chunk", &tag));
        assert!(!hmac_sha384_verify(b"key", b"chunks", &tag), "another message");
        assert!(!hmac_sha384_verify(b"other", b"chunk", &tag), "another key");
        assert!(!hmac_sha384_verify(b"key", b"chunk", &tag[..32]), "a cut tag");
    }
}
