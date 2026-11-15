// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Prove the parsers and the handshake never panic and never accept on hostile input: random frames, near-valid frames, random encoded lists.

mod common;

use common::{Scripted, runtime};
use pqbind::{Error, HybridIdentity, MemoryRegistry, PeerId, Pin, PublicIdentity, accept, connect};
use proptest::collection::vec;
use proptest::prelude::*;

/// The length of a well-shaped HELLO or SERVER_PROOF frame: tag, public key, proof.
const SHAPED_LEN: usize = 1 + pqbind_crypto::hybrid::PUBLIC_KEY_LEN + pqbind_crypto::hybrid::SIGNATURE_LEN;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn a_server_never_accepts_and_never_panics_on_a_random_first_frame(frame in vec(any::<u8>(), 0..9000)) {
        let server = HybridIdentity::from_seed(&[2; 32]).expect("seed");
        let id = PeerId::anonymous();
        let mut io = Scripted::new(vec![frame]);
        let result = runtime().block_on(accept(&mut io, &server, &id, &id, &MemoryRegistry::new()));
        prop_assert!(result.is_err());
        // Whatever it was, the peer was told one single refusal frame.
        prop_assert_eq!(io.sent, vec![vec![0x03_u8]]);
    }

    #[test]
    fn a_server_refuses_a_frame_of_exactly_the_right_shape_whose_contents_are_random(
        tag in prop_oneof![Just(0x01_u8), any::<u8>()],
        body in vec(any::<u8>(), SHAPED_LEN - 1),
    ) {
        let server = HybridIdentity::from_seed(&[2; 32]).expect("seed");
        let id = PeerId::anonymous();
        let mut frame = vec![tag];
        frame.extend_from_slice(&body);
        let mut io = Scripted::new(vec![frame]);
        let result = runtime().block_on(accept(&mut io, &server, &id, &id, &MemoryRegistry::new()));
        prop_assert!(matches!(result, Err(Error::Malformed | Error::Refused)));
        prop_assert_eq!(io.sent, vec![vec![0x03_u8]]);
    }

    #[test]
    fn a_client_never_accepts_and_never_panics_on_a_random_reply(reply in vec(any::<u8>(), 0..9000)) {
        let client = HybridIdentity::from_seed(&[1; 32]).expect("seed");
        let pin = HybridIdentity::from_seed(&[2; 32]).expect("seed").pin();
        let id = PeerId::anonymous();
        let mut io = Scripted::new(vec![reply]);
        let result = runtime().block_on(connect(&mut io, &client, &id, &id, &pin));
        prop_assert!(result.is_err());
    }

    #[test]
    fn a_public_key_or_a_registry_list_from_random_bytes_never_panics_and_a_registry_only_decodes_a_real_list(bytes in vec(any::<u8>(), 0..4000)) {
        let _ = PublicIdentity::from_bytes(&bytes);
        let _ = Pin::from_hex(&String::from_utf8_lossy(&bytes));
        if let Ok(registry) = MemoryRegistry::decode(&bytes) {
            // A list that decoded must re-encode to the very bytes it was read from.
            prop_assert_eq!(registry.encode(), bytes);
        }
    }
}
