#![no_main]
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Run `pqbind::accept` against a scripted peer whose first frame is the fuzz input: it must never return Ok, never panic, and send the peer exactly one REFUSED frame.

use libfuzzer_sys::fuzz_target;
use pqbind::{Error, PeerId, accept};
use pqbind_fuzz::{HELLO, REFUSED, Scripted, block_on, client_identity, enrolled_registry, server_identity, shaped_frame};

// The input is a flag and bytes. With the flag clear, the bytes are the first frame as they are. With it set, the first frame is shaped
// like a HELLO from the enrolled client, with its real public key and the bytes as the proof, so the input reaches the proof check.
fuzz_target!(|input: (bool, &[u8])| {
    let (shaped, bytes) = input;
    let frame = if shaped { shaped_frame(HELLO, &client_identity().public(), bytes) } else { bytes.to_vec() };
    let anonymous = PeerId::anonymous();
    let mut io = Scripted::new(vec![frame]);
    let result = block_on(accept(&mut io, server_identity(), &anonymous, &anonymous, enrolled_registry()));
    assert!(matches!(result, Err(Error::Malformed | Error::Refused)), "a hostile first frame must be refused, got {result:?}");
    // Whatever was wrong with the frame, the peer is told one thing: a single REFUSED frame, and the server proves nothing.
    assert_eq!(io.sent, vec![vec![REFUSED]], "the peer must get exactly one REFUSED frame");
});
