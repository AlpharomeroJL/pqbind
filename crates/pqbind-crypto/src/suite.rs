// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Name the signature suite and its two-byte wire identifier.
//!
//! A public key and a signature each open with the 2-byte big-endian identifier of their suite, so a reader never guesses, and a
//! value only opens under a key of the suite it names, which is what stops a downgrade. There is one suite, Ed25519 with ML-DSA-87,
//! so a break of either algorithm alone gains an attacker nothing. No classical-only suite exists on purpose: nothing here can name
//! one, so nothing can select one.

/// The length of a suite identifier on the wire, in bytes.
pub const SUITE_ID_LEN: usize = 2;

/// A hybrid signature suite: a signature verifies only when both of its halves verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureSuite {
    /// Ed25519 (RFC 8032, strict) and ML-DSA-87 (FIPS 204) over one SHA-512 digest.
    Ed25519MlDsa87,
}

impl SignatureSuite {
    /// The identifier written in every public key and signature of this suite.
    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            Self::Ed25519MlDsa87 => 0x0201,
        }
    }

    /// The readable name of this suite.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ed25519MlDsa87 => "ed25519+ml-dsa-87",
        }
    }

    /// The suite with the identifier `id`, or `None` when this build has no such suite.
    #[must_use]
    pub const fn from_id(id: u16) -> Option<Self> {
        match id {
            0x0201 => Some(Self::Ed25519MlDsa87),
            _ => None,
        }
    }
}

/// Read the suite identifier that opens `bytes`, and return it with the bytes after it. `None` for a value too short to hold
/// one.
#[must_use]
pub(crate) fn split_id(bytes: &[u8]) -> Option<(u16, &[u8])> {
    let (id, rest) = bytes.split_first_chunk::<SUITE_ID_LEN>()?;
    Some((u16::from_be_bytes(*id), rest))
}

#[cfg(test)]
mod tests {
    use super::{SignatureSuite, split_id};

    #[test]
    fn the_suite_round_trips_through_its_identifier_and_unknown_identifiers_are_refused() {
        let suite = SignatureSuite::Ed25519MlDsa87;
        assert_eq!(SignatureSuite::from_id(suite.id()), Some(suite));
        assert_eq!(suite.name(), "ed25519+ml-dsa-87");
        assert_eq!(SignatureSuite::from_id(0), None);
        assert_eq!(SignatureSuite::from_id(0x0101), None, "an identifier of a suite this build does not have");
        assert_eq!(SignatureSuite::from_id(0x0200), None);
    }

    #[test]
    fn an_identifier_is_two_big_endian_bytes() {
        assert_eq!(split_id(&[0x01, 0x02, 0xaa]), Some((0x0102, [0xaa].as_slice())));
        assert_eq!(split_id(&[0x01]), None);
    }
}
