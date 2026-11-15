#![no_main]
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Feed arbitrary text to `Pin::from_hex`, which must never panic and may only accept exactly 96 hex digits.

use libfuzzer_sys::fuzz_target;
use pqbind::{PIN_LEN, Pin};

fuzz_target!(|data: &[u8]| {
    // Invalid UTF-8 becomes replacement characters, which are not hex digits, so the refusal path is exercised too.
    let text = String::from_utf8_lossy(data);
    match Pin::from_hex(&text) {
        Ok(pin) => {
            assert_eq!(text.len(), PIN_LEN * 2, "only a text of exactly 96 digits is accepted");
            assert!(text.bytes().all(|byte| byte.is_ascii_hexdigit()), "only hex digits are accepted");
            // The pin prints as lowercase hex, whatever case it was read in, and reads back as itself.
            assert_eq!(pin.to_hex(), text.to_ascii_lowercase());
            assert_eq!(Pin::from_hex(&pin.to_hex()), Ok(pin));
        }
        Err(_) => {
            let exactly_hex = text.len() == PIN_LEN * 2 && text.bytes().all(|byte| byte.is_ascii_hexdigit());
            assert!(!exactly_hex, "96 hex digits must be accepted");
        }
    }
});
