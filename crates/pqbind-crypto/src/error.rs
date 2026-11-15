// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Define the typed error every wrapper returns.
//!
//! The variants say what failed, never which bytes: an error carries no key, nonce, plaintext or ciphertext, so it is safe to
//! log and to show.

/// Why a cryptographic operation failed. The variants carry no input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// A key has the wrong length for its algorithm.
    #[error("the key has the wrong length for this algorithm")]
    InvalidKeyLength,
    /// A nonce has the wrong length for its algorithm.
    #[error("the nonce has the wrong length for this algorithm")]
    InvalidNonceLength,
    /// An input has a length the operation does not accept.
    #[error("the input has a length this operation does not accept")]
    InvalidLength,
    /// A cost or size parameter is outside the range the algorithm accepts.
    #[error("a parameter is outside the range this algorithm accepts")]
    InvalidParameter,
    /// The requested output is longer than the algorithm can produce.
    #[error("the requested output is longer than the algorithm can produce")]
    OutputTooLong,
    /// Authentication failed: the data was changed, moved to another binding or opened with the wrong key.
    #[error("authentication failed: the data was changed, moved to another binding or opened with the wrong key")]
    AuthenticationFailed,
    /// A signature did not verify under the key the caller trusts.
    #[error("the signature did not verify")]
    SignatureInvalid,
    /// An encoded value (a key, an encapsulation or an envelope) is malformed.
    #[error("the encoded value is malformed")]
    Malformed,
    /// The operating system random source failed; nothing falls back to a weaker source.
    #[error("the operating system random source failed")]
    RandomUnavailable,
}

#[cfg(test)]
mod tests {
    use super::CryptoError;

    #[test]
    fn the_message_names_no_bytes() {
        assert_eq!(CryptoError::Malformed.to_string(), "the encoded value is malformed");
    }
}
