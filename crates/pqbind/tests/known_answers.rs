// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Pin the pqbind proof layout and the handshake frames with known-answer vectors, and check every stored byte by recomputing it.
//!
//! **These vectors were produced by this same code.** Ed25519 and ML-DSA-87 signing are deterministic, identities come from seeds and
//! the TLS exporter value is fixed with `Binding::new`, so each proof is reproducible. That makes the vectors useful in two ways: they
//! pin the wire format against accidental change, and an independent implementation can check itself against the exact bytes this one
//! produces. They are not independent test vectors, and they say nothing about whether the construction is sound.
//!
//! The vectors are in `tests/vectors/proof_v1.json`. To regenerate them after a deliberate format change, run
//! `cargo test -p pqbind --test known_answers -- --ignored regenerate_vectors --nocapture`: it prints the file, and with the
//! environment variable `PQBIND_WRITE_VECTORS` set to any value it also rewrites it. Review the diff before committing it.
//!
//! This test reads the JSON with a small reader of its own (below), because the crate has no JSON dependency to spare.

mod common;

use common::{hex, memory_pair, registry_for, unhex};
use pqbind::proof::{self, Role, Transcript};
use pqbind::{
    Binding, EXPORTER_LEN, Error, FrameError, FrameIo, HybridIdentity, MemoryRegistry, PIN_LEN, PeerId, Pin, StreamFrames, accept, connect,
};
use pqbind_crypto::hash::{sha384, sha384_hex};
use pqbind_crypto::hybrid::{PUBLIC_KEY_LEN, SIGNATURE_LEN, signed_bytes};
use tokio::io::AsyncReadExt as _;

const VECTORS: &str = include_str!("vectors/proof_v1.json");

const CLIENT_LABEL: &[u8] = b"pqbind/proof/client/v1\0";
const SERVER_LABEL: &[u8] = b"pqbind/proof/server/v1\0";

// ---------------------------------------------------------------------------------------------------------------------------------
// A reader for the JSON subset the vectors file uses: objects, arrays, strings and integers.
// ---------------------------------------------------------------------------------------------------------------------------------

#[derive(Debug)]
enum Json {
    Num(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn field(&self, key: &str) -> &Self {
        match self {
            Self::Obj(fields) => {
                fields.iter().find(|(name, _)| name == key).map(|(_, value)| value).unwrap_or_else(|| panic!("no field {key}"))
            }
            other => panic!("{other:?} is not an object (looking for {key})"),
        }
    }

    fn text(&self) -> &str {
        match self {
            Self::Str(text) => text,
            other => panic!("{other:?} is not a string"),
        }
    }

    fn number(&self) -> i64 {
        match self {
            Self::Num(number) => *number,
            other => panic!("{other:?} is not a number"),
        }
    }

    fn items(&self) -> &[Self] {
        match self {
            Self::Arr(items) => items,
            other => panic!("{other:?} is not an array"),
        }
    }

    fn bytes(&self, key: &str) -> Vec<u8> {
        unhex(self.field(key).text())
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn skip_space(&mut self) {
        while self.bytes.get(self.pos).is_some_and(u8::is_ascii_whitespace) {
            self.pos += 1;
        }
    }

    fn peek(&mut self) -> u8 {
        self.skip_space();
        *self.bytes.get(self.pos).expect("the JSON ends too early")
    }

    fn expect(&mut self, byte: u8) {
        assert_eq!(self.peek(), byte, "at offset {}", self.pos);
        self.pos += 1;
    }

    fn value(&mut self) -> Json {
        match self.peek() {
            b'{' => {
                self.pos += 1;
                let mut fields = Vec::new();
                if self.peek() == b'}' {
                    self.pos += 1;
                    return Json::Obj(fields);
                }
                loop {
                    let name = self.string();
                    self.expect(b':');
                    fields.push((name, self.value()));
                    match self.peek() {
                        b',' => self.pos += 1,
                        b'}' => {
                            self.pos += 1;
                            return Json::Obj(fields);
                        }
                        other => panic!("unexpected {:?} in an object", char::from(other)),
                    }
                }
            }
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                if self.peek() == b']' {
                    self.pos += 1;
                    return Json::Arr(items);
                }
                loop {
                    items.push(self.value());
                    match self.peek() {
                        b',' => self.pos += 1,
                        b']' => {
                            self.pos += 1;
                            return Json::Arr(items);
                        }
                        other => panic!("unexpected {:?} in an array", char::from(other)),
                    }
                }
            }
            b'"' => Json::Str(self.string()),
            b'-' | b'0'..=b'9' => {
                let start = self.pos;
                self.pos += 1;
                while self.bytes.get(self.pos).is_some_and(u8::is_ascii_digit) {
                    self.pos += 1;
                }
                let text = std::str::from_utf8(&self.bytes[start..self.pos]).expect("ASCII digits");
                Json::Num(text.parse().expect("an integer"))
            }
            other => panic!("unexpected {:?} at offset {}", char::from(other), self.pos),
        }
    }

    fn string(&mut self) -> String {
        self.expect(b'"');
        let mut out = Vec::new();
        loop {
            let byte = *self.bytes.get(self.pos).expect("the string ends too early");
            self.pos += 1;
            match byte {
                b'"' => return String::from_utf8(out).expect("UTF-8"),
                b'\\' => {
                    let escaped = *self.bytes.get(self.pos).expect("an escape");
                    self.pos += 1;
                    out.push(match escaped {
                        b'"' | b'\\' | b'/' => escaped,
                        b'n' => b'\n',
                        b't' => b'\t',
                        other => panic!("the vectors file uses no \\{} escape", char::from(other)),
                    });
                }
                other => out.push(other),
            }
        }
    }
}

fn parse(text: &str) -> Json {
    let mut parser = Parser { bytes: text.as_bytes(), pos: 0 };
    let value = parser.value();
    parser.skip_space();
    assert_eq!(parser.pos, parser.bytes.len(), "bytes after the JSON value");
    value
}

// ---------------------------------------------------------------------------------------------------------------------------------
// The cases: what goes in, and what the code must give back.
// ---------------------------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct Inputs {
    name: String,
    client_seed: [u8; 32],
    server_seed: [u8; 32],
    app_label: Vec<u8>,
    client_id: Vec<u8>,
    server_id: Vec<u8>,
    exporter: [u8; EXPORTER_LEN],
}

#[derive(Debug, PartialEq, Eq)]
struct Outputs {
    client_pin: [u8; PIN_LEN],
    server_pin: [u8; PIN_LEN],
    client_transcript: Vec<u8>,
    server_transcript: Vec<u8>,
    client_signed: Vec<u8>,
    server_signed: Vec<u8>,
    client_proof: Vec<u8>,
    server_proof: Vec<u8>,
}

struct Case {
    inputs: Inputs,
    expected: Outputs,
}

fn array<const N: usize>(bytes: Vec<u8>) -> [u8; N] {
    bytes.try_into().unwrap_or_else(|bytes: Vec<u8>| panic!("{} bytes where {N} were expected", bytes.len()))
}

fn read_cases() -> Vec<Case> {
    let root = parse(VECTORS);
    root.field("cases")
        .items()
        .iter()
        .map(|case| Case {
            inputs: Inputs {
                name: case.field("name").text().to_owned(),
                client_seed: array(case.bytes("client_seed")),
                server_seed: array(case.bytes("server_seed")),
                app_label: case.bytes("app_label_hex"),
                client_id: case.bytes("client_id_hex"),
                server_id: case.bytes("server_id_hex"),
                exporter: array(case.bytes("exporter_hex")),
            },
            expected: Outputs {
                client_pin: array(case.bytes("client_pin")),
                server_pin: array(case.bytes("server_pin")),
                client_transcript: case.bytes("client_transcript"),
                server_transcript: case.bytes("server_transcript"),
                client_signed: case.bytes("client_signed_bytes"),
                server_signed: case.bytes("server_signed_bytes"),
                client_proof: case.bytes("client_proof"),
                server_proof: case.bytes("server_proof"),
            },
        })
        .collect()
}

fn seed_of(base: u8) -> [u8; 32] {
    std::array::from_fn(|index| base.wrapping_add(u8::try_from(index).expect("below 32")))
}

fn exporter_of(step: usize) -> [u8; EXPORTER_LEN] {
    std::array::from_fn(|index| u8::try_from((index * step + 1) % 256).expect("below 256"))
}

fn pattern(len: usize, step: usize) -> Vec<u8> {
    (0..len).map(|index| u8::try_from((index * step + 3) % 251).expect("below 251")).collect()
}

/// The inputs of every case. The vectors file must hold exactly these, and `regenerate_vectors` prints them with their outputs.
fn definitions() -> Vec<Inputs> {
    let mut long_label = b"pqbind-vector-label/".to_vec();
    long_label.resize(255, b'x');
    vec![
        Inputs {
            name: "both ends anonymous, one-byte application label".to_owned(),
            client_seed: seed_of(0x00),
            server_seed: seed_of(0x20),
            app_label: b"a".to_vec(),
            client_id: Vec::new(),
            server_id: Vec::new(),
            exporter: exporter_of(1),
        },
        Inputs {
            name: "anonymous client, server identified by a certificate hash".to_owned(),
            client_seed: seed_of(0x40),
            server_seed: seed_of(0x60),
            app_label: b"pqbind-test/v1".to_vec(),
            client_id: Vec::new(),
            server_id: sha384(b"a server certificate").to_vec(),
            exporter: exporter_of(5),
        },
        Inputs {
            name: "short text identities, domain-style application label".to_owned(),
            client_seed: seed_of(0x80),
            server_seed: seed_of(0xA0),
            app_label: b"example.org/chat/v2".to_vec(),
            client_id: b"client-node".to_vec(),
            server_id: b"server-node".to_vec(),
            exporter: exporter_of(11),
        },
        Inputs {
            name: "1024-byte client identity, 32-byte server identity, 255-byte application label".to_owned(),
            client_seed: seed_of(0xC0),
            server_seed: seed_of(0xE0),
            app_label: long_label,
            client_id: pattern(1024, 7),
            server_id: pattern(32, 13),
            exporter: exporter_of(17),
        },
    ]
}

fn peer_ids(inputs: &Inputs) -> (PeerId, PeerId) {
    (PeerId::new(inputs.client_id.clone()).expect("a client identity"), PeerId::new(inputs.server_id.clone()).expect("a server identity"))
}

/// The transcript bytes of `role` for `inputs` and these pins, through the crate's own function.
fn transcript_of(role: Role, inputs: &Inputs, client_pin: &Pin, server_pin: &Pin) -> Vec<u8> {
    let binding = Binding::new(&inputs.app_label, inputs.exporter).expect("a binding");
    let (client_id, server_id) = peer_ids(inputs);
    proof::transcript_bytes(role, &Transcript { binding: &binding, client_id: &client_id, server_id: &server_id, client_pin, server_pin })
}

/// The same bytes written out by hand from the layout in `DESIGN.md`, without calling the crate: the role label, a one-byte length
/// and the application label, a two-byte length and each identity, both pins, the exporter value.
fn layout_by_hand(role: Role, inputs: &Inputs, client_pin: &[u8], server_pin: &[u8]) -> Vec<u8> {
    let mut out = match role {
        Role::Client => CLIENT_LABEL.to_vec(),
        Role::Server => SERVER_LABEL.to_vec(),
    };
    out.push(u8::try_from(inputs.app_label.len()).expect("a label of at most 255 bytes"));
    out.extend_from_slice(&inputs.app_label);
    for id in [&inputs.client_id, &inputs.server_id] {
        out.extend_from_slice(&u16::try_from(id.len()).expect("an identity of at most 1024 bytes").to_be_bytes());
        out.extend_from_slice(id);
    }
    out.extend_from_slice(client_pin);
    out.extend_from_slice(server_pin);
    out.extend_from_slice(&inputs.exporter);
    out
}

fn compute(inputs: &Inputs) -> Outputs {
    let client = HybridIdentity::from_seed(&inputs.client_seed).expect("a client seed");
    let server = HybridIdentity::from_seed(&inputs.server_seed).expect("a server seed");
    let (client_pin, server_pin) = (client.pin(), server.pin());
    let binding = Binding::new(&inputs.app_label, inputs.exporter).expect("a binding");
    let (client_id, server_id) = peer_ids(inputs);
    let transcript =
        Transcript { binding: &binding, client_id: &client_id, server_id: &server_id, client_pin: &client_pin, server_pin: &server_pin };
    let client_transcript = proof::transcript_bytes(Role::Client, &transcript);
    let server_transcript = proof::transcript_bytes(Role::Server, &transcript);
    Outputs {
        client_pin: *client_pin.as_bytes(),
        server_pin: *server_pin.as_bytes(),
        client_signed: signed_bytes(&client_transcript),
        server_signed: signed_bytes(&server_transcript),
        client_proof: proof::prove(Role::Client, &client, &transcript).expect("the client proof"),
        server_proof: proof::prove(Role::Server, &server, &transcript).expect("the server proof"),
        client_transcript,
        server_transcript,
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// The checks.
// ---------------------------------------------------------------------------------------------------------------------------------

#[test]
fn the_file_holds_the_cases_the_generator_defines_and_they_cover_the_shapes_that_matter() {
    let cases = read_cases();
    let from_file: Vec<&Inputs> = cases.iter().map(|case| &case.inputs).collect();
    let defined = definitions();
    assert_eq!(from_file, defined.iter().collect::<Vec<_>>(), "regenerate the vectors if the definitions changed on purpose");
    assert!(cases.len() >= 3);
    assert!(cases.iter().any(|case| case.inputs.client_id.is_empty()), "an empty transport identity");
    assert!(cases.iter().any(|case| !case.inputs.client_id.is_empty() && !case.inputs.server_id.is_empty()), "two identities");
    assert!(cases.iter().any(|case| case.inputs.client_id.len() == 1024 || case.inputs.server_id.len() == 1024), "a 1024-byte identity");
    let mut labels: Vec<&[u8]> = cases.iter().map(|case| case.inputs.app_label.as_slice()).collect();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), cases.len(), "every case has its own application label");
    let mut proofs: Vec<&[u8]> =
        cases.iter().flat_map(|case| [case.expected.client_proof.as_slice(), case.expected.server_proof.as_slice()]).collect();
    proofs.sort_unstable();
    proofs.dedup();
    assert_eq!(proofs.len(), cases.len() * 2, "no two proofs are alike");
}

#[test]
fn every_stored_value_is_recomputed_exactly() {
    for case in read_cases() {
        let name = &case.inputs.name;
        let got = compute(&case.inputs);
        let want = &case.expected;
        assert_eq!(got.client_pin, want.client_pin, "{name}: client pin");
        assert_eq!(got.server_pin, want.server_pin, "{name}: server pin");
        assert_eq!(hex(&got.client_transcript), hex(&want.client_transcript), "{name}: client transcript");
        assert_eq!(hex(&got.server_transcript), hex(&want.server_transcript), "{name}: server transcript");
        assert_eq!(hex(&got.client_signed), hex(&want.client_signed), "{name}: client signed bytes");
        assert_eq!(hex(&got.server_signed), hex(&want.server_signed), "{name}: server signed bytes");
        assert_eq!(got.client_proof.len(), SIGNATURE_LEN, "{name}");
        assert_eq!(hex(&got.client_proof), hex(&want.client_proof), "{name}: client proof");
        assert_eq!(hex(&got.server_proof), hex(&want.server_proof), "{name}: server proof");
        assert_eq!(compute(&case.inputs), got, "{name}: the proofs are deterministic");
    }
}

#[test]
fn the_stored_transcripts_follow_the_layout_in_the_design_document_written_out_by_hand() {
    for case in read_cases() {
        let name = &case.inputs.name;
        let want = &case.expected;
        let (client_pin, server_pin) = (want.client_pin, want.server_pin);
        assert_eq!(layout_by_hand(Role::Client, &case.inputs, &client_pin, &server_pin), want.client_transcript, "{name}: client");
        assert_eq!(layout_by_hand(Role::Server, &case.inputs, &client_pin, &server_pin), want.server_transcript, "{name}: server");
        // The signed bytes are the hybrid label and the SHA-512 of the transcript: 45 bytes of label and 64 of digest.
        assert_eq!(want.client_signed.len(), 45 + 64, "{name}");
        assert!(want.client_signed.starts_with(b"pqbind/hybrid-signature/ed25519+ml-dsa-87/v1\0"), "{name}");
        assert_ne!(want.client_signed, want.server_signed, "{name}: the roles never sign the same bytes");
    }
}

#[test]
fn every_stored_proof_verifies_for_its_own_role_and_for_no_other() {
    for case in read_cases() {
        let name = &case.inputs.name;
        let want = &case.expected;
        let client = HybridIdentity::from_seed(&case.inputs.client_seed).expect("seed").public();
        let server = HybridIdentity::from_seed(&case.inputs.server_seed).expect("seed").public();
        assert_eq!(client.as_bytes().len(), PUBLIC_KEY_LEN);
        assert_eq!(Pin::of(&client).as_bytes(), &want.client_pin, "{name}: the pin is the SHA-384 of the whole public key");
        assert_eq!(sha384(client.as_bytes()), want.client_pin, "{name}");

        let binding = Binding::new(&case.inputs.app_label, case.inputs.exporter).expect("a binding");
        let (client_id, server_id) = peer_ids(&case.inputs);
        let (client_pin, server_pin) = (Pin::from_bytes(want.client_pin), Pin::from_bytes(want.server_pin));
        let transcript = Transcript {
            binding: &binding,
            client_id: &client_id,
            server_id: &server_id,
            client_pin: &client_pin,
            server_pin: &server_pin,
        };
        proof::verify(Role::Client, &client, &want.client_proof, &transcript)
            .unwrap_or_else(|error| panic!("{name}: client proof: {error}"));
        proof::verify(Role::Server, &server, &want.server_proof, &transcript)
            .unwrap_or_else(|error| panic!("{name}: server proof: {error}"));
        // A stored proof is no good under the other role's label, or under the other party's key.
        assert_eq!(proof::verify(Role::Server, &client, &want.client_proof, &transcript), Err(Error::ProofInvalid), "{name}: role");
        assert_eq!(proof::verify(Role::Client, &server, &want.server_proof, &transcript), Err(Error::ProofInvalid), "{name}: role");
        assert_eq!(proof::verify(Role::Client, &server, &want.client_proof, &transcript), Err(Error::ProofInvalid), "{name}: key");
    }
}

/// One flipped byte: the input name, the position within it, the changed inputs, and the client and server pins.
type Flip = (&'static str, usize, Inputs, [u8; PIN_LEN], [u8; PIN_LEN]);

/// One byte of each input, flipped.
fn single_byte_flips(inputs: &Inputs, client_pin: [u8; PIN_LEN], server_pin: [u8; PIN_LEN]) -> Vec<Flip> {
    let mut out = Vec::new();
    for position in 0..inputs.app_label.len() {
        let mut changed = inputs.clone();
        changed.app_label[position] ^= 0x01;
        out.push(("application label", position, changed, client_pin, server_pin));
    }
    for position in 0..inputs.client_id.len() {
        let mut changed = inputs.clone();
        changed.client_id[position] ^= 0x01;
        out.push(("client identity", position, changed, client_pin, server_pin));
    }
    for position in 0..inputs.server_id.len() {
        let mut changed = inputs.clone();
        changed.server_id[position] ^= 0x01;
        out.push(("server identity", position, changed, client_pin, server_pin));
    }
    for position in 0..EXPORTER_LEN {
        let mut changed = inputs.clone();
        changed.exporter[position] ^= 0x01;
        out.push(("exporter value", position, changed, client_pin, server_pin));
    }
    for position in 0..PIN_LEN {
        let mut changed_pin = client_pin;
        changed_pin[position] ^= 0x01;
        out.push(("client pin", position, inputs.clone(), changed_pin, server_pin));
        let mut changed_pin = server_pin;
        changed_pin[position] ^= 0x01;
        out.push(("server pin", position, inputs.clone(), client_pin, changed_pin));
    }
    out
}

#[test]
fn flipping_any_single_byte_of_any_transcript_input_changes_the_transcript_and_the_signed_bytes() {
    for case in read_cases() {
        let name = &case.inputs.name;
        let want = &case.expected;
        let flips = single_byte_flips(&case.inputs, want.client_pin, want.server_pin);
        // Every byte of every input is covered: label, both identities, the exporter value and both pins.
        let expected_count =
            case.inputs.app_label.len() + case.inputs.client_id.len() + case.inputs.server_id.len() + EXPORTER_LEN + 2 * PIN_LEN;
        assert_eq!(flips.len(), expected_count, "{name}");
        for (input, position, changed, client_pin, server_pin) in flips {
            let (client_pin, server_pin) = (Pin::from_bytes(client_pin), Pin::from_bytes(server_pin));
            for (role, original) in [(Role::Client, &want.client_transcript), (Role::Server, &want.server_transcript)] {
                let flipped = transcript_of(role, &changed, &client_pin, &server_pin);
                assert_eq!(flipped.len(), original.len(), "{name}: {input} byte {position} keeps the layout");
                assert_ne!(&flipped, original, "{name}: {role:?} transcript, {input} byte {position}");
                assert_ne!(signed_bytes(&flipped), signed_bytes(original), "{name}: {role:?} signed bytes, {input} byte {position}");
            }
        }
    }
}

#[test]
fn a_stored_proof_does_not_verify_over_a_transcript_with_one_input_byte_changed() {
    // Verifying is the slow step, so this takes the first byte of each input (and the last byte of the exporter value) rather than all.
    for case in read_cases() {
        let name = &case.inputs.name;
        let want = &case.expected;
        let client = HybridIdentity::from_seed(&case.inputs.client_seed).expect("seed").public();
        let server = HybridIdentity::from_seed(&case.inputs.server_seed).expect("seed").public();
        let sampled = single_byte_flips(&case.inputs, want.client_pin, want.server_pin)
            .into_iter()
            .filter(|(input, position, ..)| *position == 0 || (*input == "exporter value" && *position == EXPORTER_LEN - 1));
        for (input, position, changed, client_pin, server_pin) in sampled {
            let binding = Binding::new(&changed.app_label, changed.exporter).expect("a binding");
            let (client_id, server_id) = peer_ids(&changed);
            let (client_pin, server_pin) = (Pin::from_bytes(client_pin), Pin::from_bytes(server_pin));
            let transcript = Transcript {
                binding: &binding,
                client_id: &client_id,
                server_id: &server_id,
                client_pin: &client_pin,
                server_pin: &server_pin,
            };
            assert_eq!(
                proof::verify(Role::Client, &client, &want.client_proof, &transcript),
                Err(Error::ProofInvalid),
                "{name}: client proof, {input} byte {position}"
            );
            assert_eq!(
                proof::verify(Role::Server, &server, &want.server_proof, &transcript),
                Err(Error::ProofInvalid),
                "{name}: server proof, {input} byte {position}"
            );
        }
    }
}

#[test]
fn moving_a_byte_across_the_boundary_between_the_two_identities_changes_the_transcript() {
    for case in read_cases() {
        let name = &case.inputs.name;
        let want = &case.expected;
        let mut moved = case.inputs.clone();
        if let Some(last) = moved.client_id.pop() {
            moved.server_id.insert(0, last);
        } else if !moved.server_id.is_empty() {
            let first = moved.server_id.remove(0);
            moved.client_id.push(first);
        } else {
            continue;
        }
        let both = [&case.inputs.client_id[..], &case.inputs.server_id[..]].concat();
        assert_eq!([&moved.client_id[..], &moved.server_id[..]].concat(), both, "{name}: the same identity bytes, a different split");
        let (client_pin, server_pin) = (Pin::from_bytes(want.client_pin), Pin::from_bytes(want.server_pin));
        assert_ne!(transcript_of(Role::Client, &moved, &client_pin, &server_pin), want.client_transcript, "{name}: client");
        assert_ne!(transcript_of(Role::Server, &moved, &client_pin, &server_pin), want.server_transcript, "{name}: server");
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Frames: the exact bytes the handshake sends.
// ---------------------------------------------------------------------------------------------------------------------------------

/// A frame channel that records every frame sent through it.
struct Tap<F> {
    inner: F,
    sent: Vec<Vec<u8>>,
}

impl<F: FrameIo> FrameIo for Tap<F> {
    fn binding(&self) -> &Binding {
        self.inner.binding()
    }

    async fn send(&mut self, frame: &[u8]) -> Result<(), FrameError> {
        self.sent.push(frame.to_vec());
        self.inner.send(frame).await
    }

    async fn recv(&mut self) -> Result<Vec<u8>, FrameError> {
        self.inner.recv().await
    }
}

/// The case the frame vectors were made from.
fn frames_case(root: &Json) -> Case {
    let wanted = root.field("frames").field("case").text();
    read_cases().into_iter().find(|case| case.inputs.name == wanted).unwrap_or_else(|| panic!("no case named {wanted}"))
}

/// Run the handshake of `case` over an in-memory channel and return what each end sent, and each end's result.
async fn frames_of(case: &Case, registry_holds_the_client: bool) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Result<(), Error>, Result<(), Error>) {
    let inputs = &case.inputs;
    let binding = || Binding::new(&inputs.app_label, inputs.exporter).expect("a binding");
    let (client_end, server_end) = memory_pair(binding(), binding());
    let (mut client_io, mut server_io) = (Tap { inner: client_end, sent: Vec::new() }, Tap { inner: server_end, sent: Vec::new() });
    let client = HybridIdentity::from_seed(&inputs.client_seed).expect("seed");
    let server = HybridIdentity::from_seed(&inputs.server_seed).expect("seed");
    let (client_id, server_id) = peer_ids(inputs);
    let registry = if registry_holds_the_client { registry_for(&client, client_id.clone()) } else { MemoryRegistry::new() };
    let server_pin = server.pin();
    let (client_result, server_result) = tokio::join!(
        connect(&mut client_io, &client, &client_id, &server_id, &server_pin),
        accept(&mut server_io, &server, &server_id, &client_id, &registry),
    );
    (client_io.sent, server_io.sent, client_result.map(|_| ()), server_result.map(|_| ()))
}

/// What a stored frame description says about `frame`.
fn assert_frame_matches(label: &str, description: &Json, frame: &[u8]) {
    assert_eq!(i64::try_from(frame.len()).expect("small"), description.field("length").number(), "{label}: length");
    assert_eq!(i64::from(frame[0]), description.field("first_byte").number(), "{label}: first byte");
    assert_eq!(sha384_hex(frame), description.field("sha384").text(), "{label}: SHA-384 of the whole frame");
}

/// The bytes a frame occupies on a stream: a four-byte big-endian length and the frame.
async fn on_the_wire(frame: &[u8]) -> Vec<u8> {
    let (left, mut right) = tokio::io::duplex(64 * 1024);
    let (reader, writer) = tokio::io::split(left);
    let mut frames = StreamFrames::new(reader, writer, common::binding(1));
    frames.send(frame).await.expect("send");
    let mut bytes = vec![0_u8; 4 + frame.len()];
    right.read_exact(&mut bytes).await.expect("the bytes on the stream");
    bytes
}

#[tokio::test]
async fn the_hello_and_server_proof_frames_are_the_exact_bytes_the_vectors_pin() {
    let root = parse(VECTORS);
    let case = frames_case(&root);
    let (from_client, from_server, client_result, server_result) = frames_of(&case, true).await;
    assert_eq!((client_result, server_result), (Ok(()), Ok(())), "the honest pair authenticates");
    assert_eq!(from_client.len(), 1, "the client sends one frame");
    assert_eq!(from_server.len(), 1, "the server sends one frame");
    let (hello, server_proof) = (&from_client[0], &from_server[0]);

    let frames = root.field("frames");
    assert_frame_matches("HELLO", frames.field("hello"), hello);
    assert_frame_matches("SERVER_PROOF", frames.field("server_proof"), server_proof);
    assert_eq!(hello.len(), 1 + PUBLIC_KEY_LEN + SIGNATURE_LEN);
    assert_eq!(server_proof.len(), 7320);

    // And the frames are exactly the tag, the sender's public key and the stored proof.
    let client = HybridIdentity::from_seed(&case.inputs.client_seed).expect("seed").public();
    let server = HybridIdentity::from_seed(&case.inputs.server_seed).expect("seed").public();
    assert_eq!(hello, &[&[0x01_u8][..], client.as_bytes(), &case.expected.client_proof].concat(), "HELLO is 0x01, key, proof");
    assert_eq!(
        server_proof,
        &[&[0x02_u8][..], server.as_bytes(), &case.expected.server_proof].concat(),
        "SERVER_PROOF is 0x02, key, proof"
    );

    // On a stream each frame is preceded by its length.
    for (label, frame) in [("hello", hello), ("server_proof", server_proof)] {
        let wire = on_the_wire(frame).await;
        assert_eq!(hex(&wire[..4]), frames.field(label).field("length_prefix").text(), "{label}: length prefix");
        assert_eq!(&wire[4..], frame.as_slice(), "{label}: the frame follows its prefix");
    }
}

#[tokio::test]
async fn the_refused_frame_is_the_one_byte_the_vectors_pin_whatever_the_reason() {
    let root = parse(VECTORS);
    let case = frames_case(&root);
    let refused = root.field("frames").field("refused");
    let (from_client, from_server, client_result, server_result) = frames_of(&case, false).await;
    assert_eq!((client_result, server_result), (Err(Error::Refused), Err(Error::Refused)), "an unenrolled client is refused on both ends");
    assert_eq!(from_client.len(), 1, "the client sent its HELLO");
    assert_eq!(from_server, vec![refused.bytes("hex")], "the server answered with the pinned REFUSED frame and nothing else");
    assert_eq!(from_server[0].len() as i64, refused.field("length").number());
    assert_eq!(hex(&on_the_wire(&from_server[0]).await), refused.field("on_the_wire").text());
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Regeneration.
// ---------------------------------------------------------------------------------------------------------------------------------

fn quoted(text: &str) -> String {
    assert!(!text.contains(['"', '\\', '\n']), "the strings in the vectors need no escapes");
    format!("\"{text}\"")
}

fn json_case(inputs: &Inputs, outputs: &Outputs) -> String {
    let fields = [
        ("name", quoted(&inputs.name)),
        ("client_seed", quoted(&hex(&inputs.client_seed))),
        ("server_seed", quoted(&hex(&inputs.server_seed))),
        ("app_label_hex", quoted(&hex(&inputs.app_label))),
        ("client_id_hex", quoted(&hex(&inputs.client_id))),
        ("server_id_hex", quoted(&hex(&inputs.server_id))),
        ("exporter_hex", quoted(&hex(&inputs.exporter))),
        ("client_pin", quoted(&hex(&outputs.client_pin))),
        ("server_pin", quoted(&hex(&outputs.server_pin))),
        ("client_transcript", quoted(&hex(&outputs.client_transcript))),
        ("server_transcript", quoted(&hex(&outputs.server_transcript))),
        ("client_signed_bytes", quoted(&hex(&outputs.client_signed))),
        ("server_signed_bytes", quoted(&hex(&outputs.server_signed))),
        ("client_proof", quoted(&hex(&outputs.client_proof))),
        ("server_proof", quoted(&hex(&outputs.server_proof))),
    ];
    let body: Vec<String> = fields.iter().map(|(name, value)| format!("      \"{name}\": {value}")).collect();
    format!("    {{\n{}\n    }}", body.join(",\n"))
}

fn json_frame(frame: &[u8]) -> String {
    format!(
        "{{ \"length\": {}, \"first_byte\": {}, \"length_prefix\": {}, \"sha384\": {} }}",
        frame.len(),
        frame[0],
        quoted(&hex(&u32::try_from(frame.len()).expect("a frame fits in 32 bits").to_be_bytes())),
        quoted(&sha384_hex(frame)),
    )
}

/// The whole vectors file, produced by the code under test.
fn render_vectors() -> String {
    let defined = definitions();
    let rendered: Vec<String> = defined.iter().map(|inputs| json_case(inputs, &compute(inputs))).collect();

    // The frames come from a real run of the handshake over the third case, whose identities are short text.
    let case = Case { expected: compute(&defined[2]), inputs: defined[2].clone() };
    let runtime = common::runtime();
    let (from_client, from_server, ..) = runtime.block_on(frames_of(&case, true));
    let (_, refusal, ..) = runtime.block_on(frames_of(&case, false));
    let refused = &refusal[0];
    let refused_on_wire = runtime.block_on(on_the_wire(refused));

    let description = "These vectors were produced by the pqbind code itself: the ignored test regenerate_vectors in \
        crates/pqbind/tests/known_answers.rs prints this file. They are not independent test vectors. Ed25519 and ML-DSA-87 signing are \
        deterministic, identities come from the seeds, and the TLS exporter value is fixed, so every value is reproducible. They pin the \
        wire format against accidental change, and an independent implementation can check itself against the exact bytes this one \
        produces. All binary values are lowercase hex.";
    let layout = "transcript = role label (client: pqbind/proof/client/v1 then a zero byte; server: the same with server) | u8 length, \
        application label | u16 length, client id | u16 length, server id | client pin (48) | server pin (48) | exporter (64). \
        signed bytes = hybrid label | SHA-512(transcript). proof = hybrid signature of the transcript. Lengths are big-endian. \
        HELLO = 0x01 | client public key (2626) | client proof (4693). SERVER_PROOF = 0x02 | server public key (2626) | server proof (4693). \
        REFUSED = 0x03. On a stream every frame is preceded by its length as four big-endian bytes.";
    format!(
        "{{\n  \"format\": \"pqbind-proof-vectors-v1\",\n  \"description\": {},\n  \"layout\": {},\n  \"cases\": [\n{}\n  ],\n  \"frames\": {{\n    \
         \"case\": {},\n    \"hello\": {},\n    \"server_proof\": {},\n    \"refused\": {{ \"length\": {}, \"hex\": {}, \"on_the_wire\": {} }}\n  }}\n}}\n",
        quoted(description),
        quoted(layout),
        rendered.join(",\n"),
        quoted(&case.inputs.name),
        json_frame(&from_client[0]),
        json_frame(&from_server[0]),
        refused.len(),
        quoted(&hex(refused)),
        quoted(&hex(&refused_on_wire)),
    )
}

#[test]
#[ignore = "prints the vectors file; run it on purpose after a deliberate format change"]
fn regenerate_vectors() {
    let text = render_vectors();
    println!("{text}");
    if std::env::var_os("PQBIND_WRITE_VECTORS").is_some() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/proof_v1.json");
        std::fs::write(path, &text).expect("write the vectors file");
        println!("wrote {path}");
    }
}
