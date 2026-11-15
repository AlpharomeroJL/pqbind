// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Derive keys with HKDF-SHA384 (RFC 5869).
//!
//! Key derivation is at the CNSA 2.0 hash strength, so HKDF-SHA256 is not offered.
//!
//! What is wiped: the HKDF state (an HMAC keyed with the pseudorandom key) wipes its SHA-2 parts on drop, and the pseudorandom
//! key that extract hands back is wiped here.

use hkdf::{Hkdf, HkdfExtract};
use sha2::Sha384;
use zeroize::{Zeroize, Zeroizing};

use crate::{CryptoError, SecretBytes};

/// The longest output HKDF-SHA384 can produce: 255 blocks of 48 bytes.
pub const HKDF_SHA384_MAX_OUTPUT: usize = 255 * 48;

/// HKDF-SHA384 (RFC 5869): extract with `salt` (an empty salt is the RFC's all-zero default), then expand `info` to `len`
/// bytes.
///
/// # Errors
///
/// [`CryptoError::OutputTooLong`] when `len` is over [`HKDF_SHA384_MAX_OUTPUT`].
pub fn hkdf_sha384(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<SecretBytes, CryptoError> {
    if len > HKDF_SHA384_MAX_OUTPUT {
        return Err(CryptoError::OutputTooLong);
    }
    let expander = extract_sha384(salt, ikm);
    let mut output = SecretBytes::zeroed(len);
    expander.expand(info, output.expose_secret_mut()).map_err(|_| CryptoError::OutputTooLong)?;
    Ok(output)
}

/// A 32-byte key derived from `ikm` for the purpose `info`: [`hkdf_sha384`] with the RFC's default salt.
///
/// # Errors
///
/// [`CryptoError::InvalidLength`] only if HKDF gave another length, which it never does.
pub fn hkdf_sha384_key(ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let derived = hkdf_sha384(ikm, &[], info, 32)?;
    <[u8; 32]>::try_from(derived.expose_secret()).map(Zeroizing::new).map_err(|_| CryptoError::InvalidLength)
}

/// HKDF-Extract (RFC 5869 section 2.2): the HMAC-SHA-384 state keyed with the pseudorandom key, ready to expand. It is what
/// `Hkdf::new` computes, except that the pseudorandom key extract returns is wiped instead of dropped.
fn extract_sha384(salt: &[u8], ikm: &[u8]) -> Hkdf<Sha384> {
    let mut extractor = HkdfExtract::<Sha384>::new(Some(salt));
    extractor.input_ikm(ikm);
    let (mut prk, state) = extractor.finalize();
    prk.as_mut_slice().zeroize();
    state
}

#[cfg(test)]
mod tests {
    use super::{HKDF_SHA384_MAX_OUTPUT, hkdf_sha384};
    use crate::CryptoError;

    #[test]
    fn hkdf_refuses_an_output_longer_than_255_blocks() {
        assert!(hkdf_sha384(b"ikm", b"salt", b"info", HKDF_SHA384_MAX_OUTPUT).is_ok());
        assert!(matches!(hkdf_sha384(b"ikm", b"salt", b"info", HKDF_SHA384_MAX_OUTPUT + 1), Err(CryptoError::OutputTooLong)));
    }

    #[test]
    fn hkdf_sha384_gives_the_known_answer() {
        // The inputs of RFC 5869 test case 1 under SHA-384. The RFC has no SHA-384 case, so the answer was computed apart from this
        // crate, from Python's `hmac` and `hashlib`, by the RFC's extract and expand steps.
        const ANSWER: &str = "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5";
        let ikm = [0x0b_u8; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let derived = hkdf_sha384(&ikm, &salt, &info, 42).expect("hkdf");
        #[allow(clippy::format_collect, reason = "test-only: the value is short and read once")]
        let shown: String = derived.expose_secret().iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(shown, ANSWER);
    }
}
