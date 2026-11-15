// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Decide whether a client's key is enrolled, through a registry the caller supplies, and keep an enrolled list in a strict encoded form.
//!
//! Trust here comes only from what was enrolled beforehand. A key that arrives in a connection is never trusted because it arrived.
//! A client is a pair: its hybrid key and the transport identity it was enrolled from, so a stolen key used from another endpoint is
//! refused. (An application whose transport authenticates nobody enrolls with [`PeerId::anonymous`].)

use std::sync::{Mutex, PoisonError};

use pqbind_crypto::hybrid::PUBLIC_KEY_LEN;

use crate::error::Error;
use crate::frame::Reader;
use crate::identity::{MAX_PEER_ID_LEN, PeerId, PublicIdentity};

/// The version byte that opens an encoded list.
const FORMAT_VERSION: u8 = 1;

/// The most enrollments a list holds.
pub const MAX_ENROLLMENTS: usize = 65_536;

/// What a server knows about the clients it accepts. Implement it over a database, a sealed file or anything else; refuse a client
/// that was revoked by returning `false`.
pub trait ClientRegistry: Send + Sync {
    /// Whether `key`, used from the transport identity `client_id`, is enrolled and not revoked.
    fn is_enrolled(&self, key: &PublicIdentity, client_id: &PeerId) -> bool;
}

/// One enrolled client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrollment {
    /// The client's hybrid public key.
    pub key: PublicIdentity,
    /// The transport identity the client was enrolled from.
    pub peer_id: PeerId,
    /// When it was enrolled, in milliseconds since the Unix epoch. Informational: it is never checked.
    pub enrolled_at_unix_millis: i64,
}

/// A registry kept in memory, with an encoded form for saving and loading it.
#[derive(Debug, Default)]
pub struct MemoryRegistry {
    entries: Mutex<Vec<Enrollment>>,
}

impl MemoryRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enroll a client. Enrolling the same key from the same identity again replaces the earlier record.
    pub fn enroll(&self, enrollment: Enrollment) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.retain(|entry| !(entry.key == enrollment.key && entry.peer_id == enrollment.peer_id));
        entries.push(enrollment);
    }

    /// Revoke a client. Returns whether it was enrolled.
    pub fn revoke(&self, key: &PublicIdentity, peer_id: &PeerId) -> bool {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let before = entries.len();
        entries.retain(|entry| !(entry.key == *key && entry.peer_id == *peer_id));
        entries.len() != before
    }

    /// How many clients are enrolled.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner).len()
    }

    /// Whether no client is enrolled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The enrolled clients.
    #[must_use]
    pub fn list(&self) -> Vec<Enrollment> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// The encoded list, for saving.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode(&self.list())
    }

    /// A registry from an encoded list.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a list that is cut, has bytes left over, is of another version or is too large. A list that does not
    /// decode is an error, never an empty list: a server that lost its list must not read as "no client was ever revoked".
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self { entries: Mutex::new(decode(bytes)?) })
    }
}

impl ClientRegistry for MemoryRegistry {
    fn is_enrolled(&self, key: &PublicIdentity, client_id: &PeerId) -> bool {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner).iter().any(|entry| entry.key == *key && entry.peer_id == *client_id)
    }
}

/// `version | count u32 | per entry: enrolled_at i64 | id length u16 | id | public key (fixed length)`, all big-endian.
fn encode(entries: &[Enrollment]) -> Vec<u8> {
    let mut out = vec![FORMAT_VERSION];
    out.extend_from_slice(&u32::try_from(entries.len()).unwrap_or(u32::MAX).to_be_bytes());
    for entry in entries {
        out.extend_from_slice(&entry.enrolled_at_unix_millis.to_be_bytes());
        out.extend_from_slice(&u16::try_from(entry.peer_id.as_bytes().len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(entry.peer_id.as_bytes());
        out.extend_from_slice(entry.key.as_bytes());
    }
    out
}

fn decode(bytes: &[u8]) -> Result<Vec<Enrollment>, Error> {
    let mut reader = Reader::new(bytes);
    if reader.byte().ok_or(Error::Malformed)? != FORMAT_VERSION {
        return Err(Error::Malformed);
    }
    let count = usize::try_from(u32::from_be_bytes(reader.array::<4>().ok_or(Error::Malformed)?)).map_err(|_| Error::Malformed)?;
    if count > MAX_ENROLLMENTS {
        return Err(Error::Malformed);
    }
    // Never allocate by a count the bytes cannot back: each entry is at least this long.
    let mut entries = Vec::with_capacity(count.min(bytes.len() / (8 + 2 + PUBLIC_KEY_LEN) + 1));
    for _ in 0..count {
        let enrolled_at_unix_millis = i64::from_be_bytes(reader.array::<8>().ok_or(Error::Malformed)?);
        let id_len = usize::from(u16::from_be_bytes(reader.array::<2>().ok_or(Error::Malformed)?));
        if id_len > MAX_PEER_ID_LEN {
            return Err(Error::Malformed);
        }
        let peer_id = PeerId::new(reader.take(id_len).ok_or(Error::Malformed)?).map_err(|_| Error::Malformed)?;
        let key = PublicIdentity::from_bytes(reader.take(PUBLIC_KEY_LEN).ok_or(Error::Malformed)?)?;
        entries.push(Enrollment { key, peer_id, enrolled_at_unix_millis });
    }
    if reader.remaining().is_empty() { Ok(entries) } else { Err(Error::Malformed) }
}

#[cfg(test)]
mod tests {
    use super::{ClientRegistry, Enrollment, MemoryRegistry};
    use crate::error::Error;
    use crate::identity::{HybridIdentity, PeerId};

    fn enrollment(fill: u8, id: &[u8]) -> Enrollment {
        Enrollment {
            key: HybridIdentity::from_seed(&[fill; 32]).expect("seed").public(),
            peer_id: PeerId::new(id).expect("id"),
            enrolled_at_unix_millis: i64::from(fill) * 1000,
        }
    }

    #[test]
    fn a_client_is_enrolled_for_its_key_and_its_identity_together_and_revocation_takes_it_off() {
        let registry = MemoryRegistry::new();
        let client = enrollment(1, b"node-a");
        registry.enroll(client.clone());
        assert!(registry.is_enrolled(&client.key, &client.peer_id));
        assert!(!registry.is_enrolled(&client.key, &PeerId::new(b"node-b").expect("id")), "the key from another identity");
        assert!(!registry.is_enrolled(&enrollment(2, b"node-a").key, &client.peer_id), "another key from the same identity");
        assert!(registry.revoke(&client.key, &client.peer_id));
        assert!(!registry.is_enrolled(&client.key, &client.peer_id));
        assert!(!registry.revoke(&client.key, &client.peer_id), "a second revoke finds nothing");
        assert!(registry.is_empty());
    }

    #[test]
    fn enrolling_the_same_client_again_replaces_it() {
        let registry = MemoryRegistry::new();
        registry.enroll(enrollment(1, b"x"));
        registry.enroll(Enrollment { enrolled_at_unix_millis: 99, ..enrollment(1, b"x") });
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.list()[0].enrolled_at_unix_millis, 99);
    }

    #[test]
    fn a_list_decodes_to_what_was_encoded() {
        let registry = MemoryRegistry::new();
        registry.enroll(enrollment(1, b"a"));
        registry.enroll(enrollment(2, b""));
        let decoded = MemoryRegistry::decode(&registry.encode()).expect("decode");
        assert_eq!(decoded.list(), registry.list());
        assert!(MemoryRegistry::decode(&MemoryRegistry::new().encode()).expect("empty").is_empty(), "an empty list is a list");
    }

    #[test]
    fn a_list_that_is_cut_extended_or_of_another_version_does_not_decode() {
        let registry = MemoryRegistry::new();
        registry.enroll(enrollment(3, b"a"));
        let bytes = registry.encode();
        assert_eq!(MemoryRegistry::decode(&[]).err(), Some(Error::Malformed));
        assert_eq!(MemoryRegistry::decode(&bytes[..bytes.len() - 1]).err(), Some(Error::Malformed), "cut short");
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(MemoryRegistry::decode(&longer).err(), Some(Error::Malformed), "bytes left over");
        let mut other_version = bytes;
        other_version[0] = 9;
        assert_eq!(MemoryRegistry::decode(&other_version).err(), Some(Error::Malformed), "another version");
    }

    #[test]
    fn a_count_larger_than_the_bytes_hold_does_not_decode_or_allocate_by_it() {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(MemoryRegistry::decode(&bytes).err(), Some(Error::Malformed));
        let mut within_the_cap = vec![1];
        within_the_cap.extend_from_slice(&60_000_u32.to_be_bytes());
        assert_eq!(MemoryRegistry::decode(&within_the_cap).err(), Some(Error::Malformed));
    }
}
