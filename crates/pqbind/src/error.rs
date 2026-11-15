// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Define the typed error the pqbind core returns, with variants that carry no key, proof or identity bytes.

use crate::frame::FrameError;

/// Why a pqbind operation failed. No variant carries key material, proof bytes or an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The peer refused this connection. A server sends the same refusal whether the key was unknown, revoked or the proof was bad,
    /// so the answer says nothing about which.
    #[error("the peer refused this connection")]
    Refused,
    /// The server could not prove it holds the key this client pinned.
    #[error("the server could not prove its identity")]
    ServerIdentity,
    /// A proof did not verify.
    #[error("the proof did not verify")]
    ProofInvalid,
    /// A handshake message, key or encoded list is malformed.
    #[error("a handshake message is malformed")]
    Malformed,
    /// The connection failed, closed or timed out.
    #[error("the connection failed or timed out")]
    Io,
    /// A cryptographic operation failed.
    #[error("a cryptographic operation failed")]
    Crypto,
    /// An identifier or label is outside the allowed range.
    #[error("an identifier or label is out of range")]
    InvalidInput,
    /// The connection cannot carry a pqbind binding: it is not TLS 1.3 or QUIC, or it gives no exporter value.
    #[error("the connection does not support exporter binding")]
    Unsupported,
}

impl From<FrameError> for Error {
    fn from(_: FrameError) -> Self {
        Self::Io
    }
}

impl From<pqbind_crypto::CryptoError> for Error {
    fn from(_: pqbind_crypto::CryptoError) -> Self {
        Self::Crypto
    }
}
