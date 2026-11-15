#![no_main]
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Run `pqbind::connect` against a scripted peer whose reply is the fuzz input: it must never return Ok, never panic, and send exactly one frame, the HELLO.

use libfuzzer_sys::fuzz_target;
use pqbind::{Error, PeerId, connect};
use pqbind_fuzz::{HELLO, SERVER_PROOF, SHAPED_LEN, Scripted, block_on, client_identity, server_identity, server_public, shaped_frame};

// The input is a flag and bytes. With the flag clear, the bytes are the reply as they are. With it set, the reply is shaped like a
// SERVER_PROOF carrying the pinned server's real public key and the bytes as the proof, so the input reaches the proof check.
fuzz_target!(|input: (bool, &[u8])| {
    let (shaped, bytes) = input;
    let reply = if shaped { shaped_frame(SERVER_PROOF, server_public(), bytes) } else { bytes.to_vec() };
    let anonymous = PeerId::anonymous();
    let pin = server_identity().pin();
    let mut io = Scripted::new(vec![reply]);
    let result = block_on(connect(&mut io, client_identity(), &anonymous, &anonymous, &pin));
    assert!(
        matches!(result, Err(Error::Refused | Error::Malformed | Error::ServerIdentity)),
        "a hostile reply must be refused, got {result:?}"
    );
    // The client sent its HELLO before it read the reply, and nothing else: no application data and no second frame.
    assert_eq!(io.sent.len(), 1, "exactly one frame was sent");
    assert_eq!(io.sent[0].len(), SHAPED_LEN);
    assert_eq!(io.sent[0].first(), Some(&HELLO));
});
