// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Give every caller the one SHA-384 hasher of the `sha2` crate, so a security digest is computed through this crate.
//!
//! A caller that hashes in parts, or wants the digest type itself, uses these names. A caller with the whole input in hand can use
//! [`crate::hash::sha384`].

pub use sha2::{Digest, Sha384};
