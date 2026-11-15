// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Pin the hybrid Ed25519 and ML-DSA-87 signature with known answers for a fixed seed and fixed messages, and check them by recomputing.
//!
//! **These vectors were produced by this same code.** Ed25519 and the ML-DSA-87 variant used here are deterministic and the key comes
//! from a seed, so each public key and signature is reproducible. The vectors pin the encoding, the domain label, the SHA-512 step and
//! the seed derivation against accidental change, and let an independent implementation check itself against the bytes this one
//! produces. They are not independent test vectors. The ML-DSA-87 primitive is checked against NIST's own vectors separately, in
//! `mldsa87_acvp.rs`.
//!
//! The vectors are in `tests/vectors/hybrid_v1.json`. To regenerate them after a deliberate format change, run
//! `cargo test -p pqbind-crypto --test known_answers -- --ignored regenerate_vectors --nocapture`: it prints the file, and with the
//! environment variable `PQBIND_WRITE_VECTORS` set to any value it also rewrites it. Review the diff before committing it.

use pqbind_crypto::hash::{sha384, sha384_hex};
use pqbind_crypto::hybrid::{
    HybridSignature, HybridSigningKey, HybridVerifyingKey, PUBLIC_KEY_LEN, SEED_LEN, SIGNATURE_LEN, ml_dsa_key_of_seed, signed_bytes,
};
use pqbind_crypto::kdf::hkdf_sha384;
use pqbind_crypto::sign::SigningKey;
use pqbind_crypto::suite::SignatureSuite;
use serde_json::{Value, json};

const VECTORS: &str = include_str!("vectors/hybrid_v1.json");

/// The label the hybrid signature signs in front of the SHA-512 digest.
const LABEL: &[u8] = b"pqbind/hybrid-signature/ed25519+ml-dsa-87/v1\0";

/// The HKDF `info` of the ML-DSA seed, written out here so a change to it fails this test.
const ML_DSA_SEED_INFO: &[u8] = b"pqbind/hybrid-signature/ml-dsa-87-seed/v1";

/// The 32-byte seed of the vectors: 0x00, 0x01, ... 0x1f.
fn seed() -> [u8; SEED_LEN] {
    std::array::from_fn(|index| u8::try_from(index).expect("below 32"))
}

/// The messages of the vectors: empty, a short text, and 4000 patterned bytes.
fn messages() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("the empty message", Vec::new()),
        ("a short text", b"pqbind-crypto known answer".to_vec()),
        ("4000 patterned bytes", (0..4000_usize).map(|index| u8::try_from((index * 31 + 7) % 251).expect("below 251")).collect()),
    ]
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
        write!(out, "{byte:02x}").expect("writing to a string");
        out
    })
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "hex has an even number of digits");
    text.as_bytes().chunks(2).map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII"), 16).expect("hex")).collect()
}

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("the vectors are JSON")
}

fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field].as_str().unwrap_or_else(|| panic!("a string field {field}"))
}

/// Where the Ed25519 half of an encoded public key or signature starts (after the suite identifier), and where the ML-DSA half starts.
const ED_PUBLIC: std::ops::Range<usize> = 2..34;
const ED_SIGNATURE: std::ops::Range<usize> = 2..66;
const ML_DSA_SIGNATURE_START: usize = 66;
const ML_DSA_PUBLIC_START: usize = 34;

/// Everything the vectors hold, computed from scratch.
fn compute() -> Value {
    let seed = seed();
    let key = HybridSigningKey::from_seed(&seed).expect("a key");
    let public = key.verifying_key().to_bytes();
    let ml_dsa_seed = hkdf_sha384(&seed, &[], ML_DSA_SEED_INFO, 32).expect("the ML-DSA seed");
    let signatures: Vec<Value> = messages()
        .into_iter()
        .map(|(name, message)| {
            let signed = signed_bytes(&message);
            let signature = key.sign(&message).expect("a signature").to_bytes();
            json!({
                "name": name,
                "message_hex": hex(&message),
                "signed_bytes": hex(&signed),
                "ed25519_signature": hex(&signature[ED_SIGNATURE]),
                "ml_dsa_signature_sha384": sha384_hex(&signature[ML_DSA_SIGNATURE_START..]),
                "hybrid_signature_length": signature.len(),
                "hybrid_signature_sha384": sha384_hex(&signature),
            })
        })
        .collect();
    json!({
        "format": "pqbind-crypto-hybrid-vectors-v1",
        "description": "These vectors were produced by the pqbind-crypto code itself: the ignored test regenerate_vectors in \
            crates/pqbind-crypto/tests/known_answers.rs prints this file. They are not independent test vectors. Ed25519 and the \
            ML-DSA-87 variant used here are deterministic and the key comes from a seed, so every value is reproducible. They pin the \
            encoding, the domain label, the SHA-512 step and the seed derivation against accidental change, and an independent \
            implementation can check itself against the exact bytes this one produces. All binary values are lowercase hex.",
        "layout": "public key = suite id 0x0201 | Ed25519 public key (32) | ML-DSA-87 public key (2592). signature = suite id 0x0201 | \
            Ed25519 signature (64) | ML-DSA-87 signature (4627). Both halves sign signed_bytes = label | SHA-512(message), where the \
            label is pqbind/hybrid-signature/ed25519+ml-dsa-87/v1 followed by a zero byte. The Ed25519 seed is the hybrid seed; the \
            ML-DSA-87 seed is HKDF-SHA384(ikm = seed, salt = empty, info = pqbind/hybrid-signature/ml-dsa-87-seed/v1, 32 bytes).",
        "seed": hex(&seed),
        "ed25519_public_key": hex(&public[ED_PUBLIC]),
        "ml_dsa_seed": hex(ml_dsa_seed.expose_secret()),
        "ml_dsa_public_key_sha384": sha384_hex(&public[ML_DSA_PUBLIC_START..]),
        "hybrid_public_key_length": public.len(),
        "hybrid_public_key_sha384": sha384_hex(&public),
        "signatures": signatures,
    })
}

#[test]
fn the_stored_vectors_are_the_ones_this_code_computes() {
    assert_eq!(vectors(), compute(), "regenerate the vectors if the format changed on purpose");
}

#[test]
fn the_key_of_the_fixed_seed_has_the_stored_public_key_and_derives_its_ml_dsa_half_as_stored() {
    let vectors = vectors();
    let seed = unhex(text(&vectors, "seed"));
    assert_eq!(seed, self::seed());
    let key = HybridSigningKey::from_seed(&self::seed()).expect("a key");
    let public = key.verifying_key().to_bytes();
    assert_eq!(public.len(), PUBLIC_KEY_LEN);
    assert_eq!(vectors["hybrid_public_key_length"], PUBLIC_KEY_LEN);
    assert_eq!(public[..2], SignatureSuite::Ed25519MlDsa87.id().to_be_bytes());
    assert_eq!(public[..2], [0x02, 0x01]);
    assert_eq!(hex(&public[ED_PUBLIC]), text(&vectors, "ed25519_public_key"));
    assert_eq!(sha384_hex(&public), text(&vectors, "hybrid_public_key_sha384"));
    assert_eq!(sha384_hex(&public[ML_DSA_PUBLIC_START..]), text(&vectors, "ml_dsa_public_key_sha384"));

    // The Ed25519 half is the plain RFC 8032 key of the seed; the ML-DSA seed is the HKDF output the vectors state.
    assert_eq!(SigningKey::from_seed(&self::seed()).verifying_key().to_bytes().as_slice(), &public[ED_PUBLIC]);
    let derived = hkdf_sha384(&seed, &[], ML_DSA_SEED_INFO, 32).expect("the ML-DSA seed");
    assert_eq!(hex(derived.expose_secret()), text(&vectors, "ml_dsa_seed"));
    let ml_dsa_seed: [u8; 32] = derived.expose_secret().try_into().expect("32 bytes");
    assert_eq!(
        ml_dsa_key_of_seed(&self::seed()).expect("a key").verifying_key().to_bytes(),
        public[ML_DSA_PUBLIC_START..],
        "the key of the derived seed"
    );
    assert_eq!(pqbind_crypto::mldsa::MlDsaSigningKey::from_seed(&ml_dsa_seed).verifying_key().to_bytes(), public[ML_DSA_PUBLIC_START..]);

    // The seed gives the seed back, and the key reads back from its encoding.
    assert_eq!(key.to_seed().expose_secret(), seed.as_slice());
    assert_eq!(HybridVerifyingKey::from_bytes(&public).expect("a public key").to_bytes(), public);
}

#[test]
fn every_stored_signature_is_recomputed_exactly_and_is_made_of_the_stated_parts() {
    let vectors = vectors();
    let key = HybridSigningKey::from_seed(&seed()).expect("a key");
    let cases = vectors["signatures"].as_array().expect("signatures");
    assert_eq!(cases.len(), messages().len());
    for (case, (name, message)) in cases.iter().zip(messages()) {
        assert_eq!(text(case, "name"), name);
        assert_eq!(unhex(text(case, "message_hex")), message, "{name}");
        let signed = signed_bytes(&message);
        assert_eq!(hex(&signed), text(case, "signed_bytes"), "{name}: signed bytes");
        assert_eq!(signed.len(), LABEL.len() + 64, "{name}: label and a SHA-512 digest");
        assert!(signed.starts_with(LABEL), "{name}");

        let signature = key.sign(&message).expect("a signature").to_bytes();
        assert_eq!(signature.len(), SIGNATURE_LEN, "{name}");
        assert_eq!(case["hybrid_signature_length"], SIGNATURE_LEN, "{name}");
        assert_eq!(signature[..2], [0x02, 0x01], "{name}: suite identifier");
        assert_eq!(sha384_hex(&signature), text(case, "hybrid_signature_sha384"), "{name}: signature hash");
        assert_eq!(hex(&signature[ED_SIGNATURE]), text(case, "ed25519_signature"), "{name}: Ed25519 half");
        assert_eq!(sha384_hex(&signature[ML_DSA_SIGNATURE_START..]), text(case, "ml_dsa_signature_sha384"), "{name}: ML-DSA half");
        // The Ed25519 half is a plain Ed25519 signature of the signed bytes.
        assert_eq!(SigningKey::from_seed(&seed()).sign(&signed).to_bytes().as_slice(), &signature[ED_SIGNATURE], "{name}");
        assert_eq!(key.sign(&message).expect("again").to_bytes(), signature, "{name}: signing is deterministic");
    }
}

#[test]
fn every_stored_signature_verifies_and_nothing_else_does() {
    let vectors = vectors();
    let public = HybridSigningKey::from_seed(&seed()).expect("a key").verifying_key();
    let other = HybridSigningKey::from_seed(&[0xA5; SEED_LEN]).expect("another key").verifying_key();
    let cases = vectors["signatures"].as_array().expect("signatures");
    let all: Vec<Vec<u8>> = messages().into_iter().map(|(_, message)| message).collect();
    for (index, (case, message)) in cases.iter().zip(&all).enumerate() {
        let name = text(case, "name");
        let signature = HybridSigningKey::from_seed(&seed()).expect("a key").sign(message).expect("signs");
        assert_eq!(hybrid_sha384(&signature), text(case, "hybrid_signature_sha384"));
        public.verify(message, &signature).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(other.verify(message, &signature).is_err(), "{name}: another key");
        // Another message, including every other message of the vectors, is refused.
        for (other_index, other_message) in all.iter().enumerate().filter(|(other_index, _)| *other_index != index) {
            assert!(public.verify(other_message, &signature).is_err(), "{name}: the message of case {other_index}");
        }
        let mut changed = message.clone();
        changed.push(0);
        assert!(public.verify(&changed, &signature).is_err(), "{name}: the message with a byte appended");
    }
}

fn hybrid_sha384(signature: &HybridSignature) -> String {
    sha384_hex(&signature.to_bytes())
}

/// Whether a signature with one byte of the encoding flipped is refused, at parsing or at verification.
fn flipped_signature_is_refused(public: &HybridVerifyingKey, message: &[u8], signature: &[u8], position: usize) -> bool {
    let mut changed = signature.to_vec();
    changed[position] ^= 0x01;
    HybridSignature::from_slice(&changed).map_or(true, |parsed| public.verify(message, &parsed).is_err())
}

#[test]
fn a_stored_signature_with_one_byte_flipped_is_refused_in_each_part() {
    let key = HybridSigningKey::from_seed(&seed()).expect("a key");
    let public = key.verifying_key();
    let (_, message) = messages().remove(1);
    let signature = key.sign(&message).expect("signs").to_bytes();
    // The suite identifier, both halves at the start, the middle and the end, and the boundary between the halves.
    for position in [0, 1, 2, 33, 65, 66, 67, 66 + 2000, SIGNATURE_LEN - 2, SIGNATURE_LEN - 1] {
        assert!(flipped_signature_is_refused(&public, &message, &signature, position), "byte {position} of the signature");
    }
    // The unflipped signature does verify, so the refusals above are not an artifact of the helper.
    assert!(public.verify(&message, &HybridSignature::from_slice(&signature).expect("parses")).is_ok());
}

#[test]
fn a_stored_public_key_with_one_byte_flipped_does_not_verify_the_stored_signature() {
    let key = HybridSigningKey::from_seed(&seed()).expect("a key");
    let public = key.verifying_key().to_bytes();
    let (_, message) = messages().remove(1);
    let signature = key.sign(&message).expect("signs");
    for position in [0, 1, 2, 17, 33, 34, 35, 34 + 1300, PUBLIC_KEY_LEN - 1] {
        let mut changed = public.clone();
        changed[position] ^= 0x01;
        let refused = HybridVerifyingKey::from_bytes(&changed).map_or(true, |parsed| parsed.verify(&message, &signature).is_err());
        assert!(refused, "byte {position} of the public key");
    }
    assert_eq!(sha384(&public).len(), 48);
}

#[test]
#[ignore = "prints the vectors file; run it on purpose after a deliberate format change"]
fn regenerate_vectors() {
    let text = serde_json::to_string_pretty(&compute()).expect("JSON") + "\n";
    println!("{text}");
    if std::env::var_os("PQBIND_WRITE_VECTORS").is_some() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/hybrid_v1.json");
        std::fs::write(path, &text).expect("write the vectors file");
        println!("wrote {path}");
    }
}
