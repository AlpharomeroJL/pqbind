#![no_main]
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Feed arbitrary bytes to `MemoryRegistry::decode`, which must never panic, and whose accepted lists must re-encode to the same bytes.

use libfuzzer_sys::fuzz_target;
use pqbind::{ClientRegistry, MemoryRegistry};
use pqbind_fuzz::key_pool;

/// A well-formed list built from `bytes`, written out by hand from the documented layout: `version 1 | count u32 | per entry:
/// enrolled_at i64 | id length u16 | id | public key`, all big-endian. Each entry is taken from the bytes as eight for the time, one
/// for the identity length (at most 40), the identity, and one that picks one of four real keys. At most 64 entries are taken.
fn well_formed_list(bytes: &[u8]) -> Vec<u8> {
    let mut entries = Vec::new();
    let mut count = 0_u32;
    let mut rest = bytes;
    while count < 64 {
        let Some((time, after_time)) = rest.split_first_chunk::<8>() else { break };
        let Some((len, after_len)) = after_time.split_first() else { break };
        let Some((id, after_id)) = after_len.split_at_checked(usize::from(*len % 41)) else { break };
        let Some((pick, after_pick)) = after_id.split_first() else { break };
        entries.extend_from_slice(time);
        entries.extend_from_slice(&u16::try_from(id.len()).expect("at most 40").to_be_bytes());
        entries.extend_from_slice(id);
        entries.extend_from_slice(key_pool()[usize::from(*pick) % key_pool().len()].as_bytes());
        count += 1;
        rest = after_pick;
    }
    let mut list = vec![1_u8];
    list.extend_from_slice(&count.to_be_bytes());
    list.extend_from_slice(&entries);
    list
}

// The input is a flag and bytes. With the flag clear, the bytes are decoded as they are. With it set, a well-formed list is built from
// them first, which must decode and re-encode to itself. When the bytes are of odd length, one byte of that list, picked by the
// first byte of the input, is then flipped, so the input also covers near-valid lists.
fuzz_target!(|input: (bool, &[u8])| {
    let (structured, bytes) = input;
    let data = if structured {
        let list = well_formed_list(bytes);
        let decoded = MemoryRegistry::decode(&list).expect("a well-formed list must decode");
        assert_eq!(decoded.encode(), list, "a well-formed list must re-encode to the same bytes");
        let mut damaged = list;
        if let (true, Some(first)) = (bytes.len() % 2 == 1, bytes.first()) {
            let at = usize::from(*first) * 131 % damaged.len();
            damaged[at] ^= 0xFF;
        }
        damaged
    } else {
        bytes.to_vec()
    };
    if let Ok(registry) = MemoryRegistry::decode(&data) {
        // The encoding is strict: a list that decoded is exactly what it was read from, with nothing cut, extended or reordered.
        assert_eq!(registry.encode(), data, "a decoded list must re-encode to the same bytes");
        let listed = registry.list();
        assert_eq!(registry.len(), listed.len());
        assert_eq!(registry.is_empty(), listed.is_empty());
        // Every listed client is enrolled for its own key and identity.
        for enrollment in &listed {
            assert!(registry.is_enrolled(&enrollment.key, &enrollment.peer_id));
        }
        let again = MemoryRegistry::decode(&registry.encode()).expect("an encoded list decodes");
        assert_eq!(again.list(), listed);
    }
});
