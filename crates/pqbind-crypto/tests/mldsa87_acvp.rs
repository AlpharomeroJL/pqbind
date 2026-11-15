// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: check ML-DSA-87 key generation, deterministic signing and verifying against NIST's ACVP known answers (FIPS 204).
//!
//! The vectors are in `tests/vectors/mldsa87_acvp.json`, picked from NIST's own files. Key generation runs through this crate's
//! type. The signing cases carry an expanded key and a context, which this crate's type has no use for, so they run on the same
//! `ml-dsa` code this crate's type wraps.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing, deprecated, reason = "test code")]

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, MlDsa87, Signature, VerifyingKey};
use pqbind_crypto::mldsa::{MlDsaSigningKey, MlDsaVerifyingKey};
use serde_json::Value;

fn vectors() -> Value {
    let text = include_str!("vectors/mldsa87_acvp.json");
    serde_json::from_str(text).expect("the vectors are JSON")
}

fn bytes(case: &Value, field: &str) -> Vec<u8> {
    let text = case[field].as_str().expect("a hex field").as_bytes();
    text.chunks(2).map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16).expect("hex")).collect()
}

fn verifying_key(encoded: &[u8]) -> VerifyingKey<MlDsa87> {
    VerifyingKey::decode(&EncodedVerifyingKey::<MlDsa87>::try_from(encoded).expect("a key of the right length"))
}

#[test]
fn nf_sec_01_acvp_key_generation_gives_nist_s_public_key() {
    let vectors = vectors();
    let cases = vectors["keyGen"].as_array().expect("cases");
    assert_eq!(cases.len(), 3);
    for case in cases {
        let seed: [u8; 32] = bytes(case, "seed").try_into().expect("a 32-byte seed");
        assert_eq!(MlDsaSigningKey::from_seed(&seed).verifying_key().to_bytes(), bytes(case, "pk"), "case {}", case["tcId"]);
    }
}

#[test]
fn nf_sec_01_acvp_deterministic_signing_gives_nist_s_signature_and_it_verifies() {
    let vectors = vectors();
    let cases = vectors["sigGen"].as_array().expect("cases");
    assert_eq!(cases.len(), 3);
    for case in cases {
        let id = &case["tcId"];
        let (message, context, expected) = (bytes(case, "message"), bytes(case, "context"), bytes(case, "signature"));
        let expanded = ExpandedSigningKeyBytes::<MlDsa87>::try_from(bytes(case, "sk").as_slice()).expect("a key of the right length");
        let signature = ExpandedSigningKey::<MlDsa87>::from_expanded(&expanded).sign_deterministic(&message, &context).expect("signs");
        assert_eq!(signature.encode().as_slice(), expected.as_slice(), "case {id}");

        let public = bytes(case, "pk");
        MlDsaVerifyingKey::from_bytes(&public).expect("the product type reads NIST's key");
        let key = verifying_key(&public);
        let encoded = EncodedSignature::<MlDsa87>::try_from(expected.as_slice()).expect("a signature of the right length");
        let read = Signature::<MlDsa87>::decode(&encoded).expect("the signature reads");
        assert!(key.verify_with_context(&message, &context, &read), "case {id} verifies");
        let mut changed = message.clone();
        changed[0] ^= 1;
        assert!(!key.verify_with_context(&changed, &context, &read), "case {id} refuses another message");
    }
}
