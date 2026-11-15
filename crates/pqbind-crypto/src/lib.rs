// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Provide the hybrid Ed25519 and ML-DSA-87 signature, HKDF-SHA384 and SHA-384 that pqbind builds on.
//!
//! This crate is small on purpose, so it can be read and reviewed on its own. Nothing here invents an algorithm: every primitive
//! comes from an established RustCrypto-ecosystem crate (`ed25519-dalek`, `ml-dsa`, `hkdf`, `sha2`), wrapped with zeroization and
//! typed errors that carry no secret bytes. Be aware that the `ml-dsa` crate states it has never been independently audited, and it is
//! a 0.1 release; the ML-DSA half of every signature rests on it.
//!
//! # Modules
//!
//! - [`hybrid`]: Ed25519 and ML-DSA-87 together. A signature verifies only when both halves verify.
//! - [`sign`]: Ed25519 with strict verification.
//! - [`mldsa`]: ML-DSA-87 (FIPS 204).
//! - [`kdf`]: HKDF-SHA384 (RFC 5869).
//! - [`hash`]: SHA-384 and HMAC-SHA-384.
//! - [`suite`]: the named algorithm suites and their two-byte wire identifiers.
//! - [`random`]: bytes from the operating system random source, failing loudly instead of falling back.
//!
//! # Status
//!
//! Pre-release and unpublished. The design has not been independently reviewed.

#![deny(missing_docs)]

pub mod hash;
pub mod hybrid;
pub mod kdf;
pub mod mldsa;
pub mod random;
pub mod sha384;
pub mod sign;
pub mod suite;

mod error;
mod secret;
#[cfg(test)]
mod zeroize_check;

pub use error::CryptoError;
pub use secret::SecretBytes;
