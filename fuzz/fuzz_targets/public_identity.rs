#![no_main]
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Feed arbitrary bytes to `PublicIdentity::from_bytes`, which must never panic and may only accept the canonical encoding of a key.

use libfuzzer_sys::fuzz_target;
use pqbind::{Pin, PublicIdentity};
use pqbind_fuzz::shaped_key;

// The input is a flag and bytes. With the flag clear, the bytes are parsed as they are. With it set, they are given the suite
// identifier and the length of a real key first, so the input reaches the checks on the two halves instead of stopping at the length.
fuzz_target!(|input: (bool, &[u8])| {
    let (shaped, bytes) = input;
    let data = if shaped { shaped_key(bytes) } else { bytes.to_vec() };
    if let Ok(key) = PublicIdentity::from_bytes(&data) {
        // An accepted key is the canonical encoding: it re-encodes to the very bytes it was read from, so one key has one pin.
        assert_eq!(key.as_bytes(), data.as_slice(), "an accepted key must be in its canonical encoding");
        let pin = key.pin();
        assert_eq!(pin, Pin::of(&key));
        assert_eq!(Pin::from_hex(&pin.to_hex()), Ok(pin), "a pin of an accepted key round-trips through hex");
        assert_eq!(PublicIdentity::from_bytes(key.as_bytes()), Ok(key), "an accepted key parses again to itself");
    }
});
