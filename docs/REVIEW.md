# Reviewer's guide

pqbind has not had an independent review. This page is meant to make one cheap to start. It gives the reading order, how to build
and run everything, what each test claims, and the questions whose answers matter most. It also states what the evidence does not
cover.

Line counts are approximate. Unit tests live in the same files as the code, so the "code" figures exclude the `#[cfg(test)]`
part. The full file map is in [ARCHITECTURE.md](ARCHITECTURE.md). Report findings through [SECURITY.md](../SECURITY.md).

## The claim under review

After a TLS 1.3 or QUIC handshake that already has a post-quantum key exchange, each end can prove that it holds an enrolled (or
pinned) hybrid Ed25519 + ML-DSA-87 key, bound to that one connection, so that forging the classical authentication alone is not
enough.

[THREAT_MODEL.md](../THREAT_MODEL.md) and [DESIGN.md](../DESIGN.md) state the threat model and the protocol. Read both first, about
15 minutes. Both say what is out of scope, for example theft of a whole private key.

## Reading order

| Step | Read | About | Why |
|---|---|---|---|
| 1 | `crates/pqbind-crypto/src/suite.rs`, `hybrid.rs` | 56 + 214 lines of code | The composition: what is signed, how the seed is split, how both halves are required. The most important part of the repository. |
| 2 | `crates/pqbind-crypto/src/mldsa.rs`, `sign.rs` | 155 + 120 lines of code | The two wrappers: ML-DSA-87 (deterministic, empty context, all-zero `t1` refused) and strict Ed25519. |
| 3 | `crates/pqbind-crypto/src/kdf.rs`, `hash.rs`, `random.rs`, `secret.rs`, `sha384.rs`, `error.rs` | about 280 lines | HKDF-SHA384, SHA-384, the random source, zeroizing types. Mostly thin wrappers. |
| 4 | `crates/pqbind/src/proof.rs` | 107 lines | The exact bytes that are signed, per role. |
| 5 | `crates/pqbind/src/handshake.rs` | 179 lines | The state machine: HELLO, SERVER_PROOF, REFUSED, and the order of every check. |
| 6 | `crates/pqbind/src/identity.rs`, `binding.rs`, `trust.rs`, `frame.rs` | about 600 lines of code | Pins and canonical keys, the exporter value, the enrollment registry, the frame reader. |
| 7 | `crates/pqbind/src/adapters/{quinn,rustls,iroh}.rs` | about 220 lines of code | How each transport reads the exporter value and names the remote end. |
| 8 | The tests (below) | about 2,500 lines | What is claimed, and how each claim could fail. |

Steps 1 to 5 decide whether the design is sound. With their unit tests they come to about 1,500 lines. The `pqbind-crypto` crate is
about 1,300 lines of source plus about 440 lines of integration tests, so it can be read in one sitting. Public items are
documented, and `cargo doc` renders the API.

## Build, run and test

Everything works offline once dependencies are fetched. From the repository root:

```text
cargo build --workspace --all-features
cargo test --workspace --all-features             # unit, integration and doc tests; sockets bind on 127.0.0.1 only
cargo run -p pqbind-cli -- demo                   # eight scenarios over real QUIC; exits 0 only if all behave as expected
cargo run -p pqbind-cli -- demo --transport tls   # the same over TLS 1.3 on TCP
cargo run -p pqbind --example quinn_client_server --features quinn   # one honest connection, step by step
cargo doc --workspace --no-deps --all-features --open
```

ML-DSA-87 needs a large stack in an unoptimized build: key expansion alone needs about 960 KiB (480 KiB in a release build),
measured on Windows with `crates/pqbind-cli/examples/stack_probe.rs`. The command line runs on a 2 MiB thread, the example on 4
MiB, and the tests on the default 2 MiB test threads.

## Invariants the tests claim

Each line says what is claimed and where it is tested, so you can try to break the test as well as the code.

**Hybrid signature (`pqbind-crypto`)**

- Both halves are required. Tampering with either half alone fails. A good half of one key with a bad half of another fails both
  ways. Replacing either public half in a trust root refuses. (`hybrid.rs` unit tests.)
- A half is not a plain signature and a plain signature is not a half, because of the label. (`hybrid.rs` unit tests.)
- An unknown suite identifier, a cut signature and a changed message are refused. (`hybrid.rs`, `suite.rs`.)
- A public key whose ML-DSA `t1` is all zero is refused whatever its `rho`. Ed25519 verification is strict: a small-order forgery
  that plain verification accepts is refused. (`mldsa.rs`, `sign.rs`.)
- ML-DSA-87 key generation and deterministic signing match NIST ACVP answers: three key generation and three signing cases, picked
  from NIST's files (`tests/mldsa87_acvp.rs`, vectors in `tests/vectors/`). There are no ACVP verification-failure cases, so the
  rejection paths of `ml-dsa` are tested only by this repository's own negative tests.
- No hand-written primitive: a scan fails if a known primitive constant appears in `src/`, or a dependency outside a short list is
  added. This is a guard, not a proof. (`tests/no_home_grown_primitives.rs`.)
- Secret types wipe themselves on drop, checked at the type level. (`zeroize_check.rs`.)

**Handshake (`pqbind`)**

- An honest pair authenticates over an in-memory channel, over QUIC, over TLS 1.3 and over iroh, and the same streams then carry
  application data. (`handshake_memory.rs`, `quinn_loopback.rs`, `rustls_loopback.rs`, `iroh_adapter.rs`.)
- An attacker holding only the Ed25519 half of a client's or server's key cannot pass as that peer. Each test also runs the forging
  helper with both halves and checks that it reproduces a real proof byte for byte, so a failed forgery is not the result of a
  broken helper. (`attack_stolen_classical_key.rs`.)
- A stolen TLS key without the hybrid key is caught, both by the real pqbind code (the attacker cannot verify the HELLO) and by an
  attacker that skips verification and answers with a proof of its own key (the client's pin check fails). (`quinn_loopback.rs`,
  `rustls_loopback.rs`.)
- A client that was never enrolled, a revoked client, an enrolled key used from another transport identity, a client that pinned a
  different server key, and two ends with different application labels are all refused. (`handshake_memory.rs` and the adapter tests.)
- A proof made on another connection does not verify, and a recorded server proof does not verify on another connection.
  (`handshake_memory.rs`.)
- Every refusal is the same single `REFUSED` frame, including a first frame that is not a HELLO at all. (`handshake_memory.rs`.)
- A TLS 1.2 connection is refused by the rustls adapter. (`rustls_loopback.rs`.)
- Random and near-valid frames, keys and registry lists never panic and are never accepted. The tests use `proptest` with 48 cases
  per property, which is modest. (`hostile_input.rs`.)
- The demo's eight scenarios, including the two that show the limit (whole-key theft), behave as expected over QUIC and TLS.
  (`pqbind demo`, and unit tests in `pqbind-cli`.)
- The `known_answers.rs` tests pin fixed bytes: the hybrid signature in `crates/pqbind-crypto/tests/` (vectors in
  `tests/vectors/hybrid_v1.json`), and the proof layout and handshake frames in `crates/pqbind/tests/` (vectors in
  `tests/vectors/proof_v1.json`). The vectors were produced by this code, so they stop accidental format changes and give a second
  implementation something to compare against. They are not independent evidence that the construction is sound.

## Questions for the reviewer

Roughly in order of importance.

**The composition**

1. Both halves sign `LABEL | SHA-512(message)` (`hybrid.rs`, `signed_bytes`). Is signing one prehash with both algorithms sound?
   A SHA-512 collision would break both halves at once. Is that acceptable, or should each half hash its own way, or should the
   ML-DSA half sign the message itself? Is a single label for both halves right, or should each half have its own?
2. The ML-DSA seed is `HKDF-SHA384(ikm = Ed25519 seed, salt = empty, info = "pqbind/hybrid-signature/ml-dsa-87-seed/v1", 32 bytes)`
   (`hybrid.rs`, `ml_dsa_key_of_seed`). Is deriving one half from the other's seed safe? The design relies on this: a quantum
   attacker who recovers the Ed25519 scalar from the public key does not get the seed, because the scalar is a SHA-512 output. Is
   that argument complete? Is a single stored seed worth the coupling, versus two independent seeds?
3. Is a custom composition acceptable at all, or should this follow an IETF composite-signature scheme? Is there one whose
   parameters (Ed25519 with ML-DSA-87) match closely enough that moving to it is the better answer?
4. Verification evaluates both halves and combines the results, so a failure of one does not skip the other
   (`HybridVerifyingKey::verify`). Is there a failure mode the non-short-circuit evaluation misses?

**The proof and the handshake**

5. The transcript holds the role label, the application label, both transport identities, both key pins and the exporter value
   (`proof.rs`). Are the pins inside the transcript the right choice? They make a proof hold for one pair of keys, so the real server
   never proves itself to a client that pinned something else. The client's pin is computed from the key the client sent in HELLO.
   Is anything missing (for example the suite identifier, or the full public keys instead of hashes of them)? Is anything redundant?
6. Is the encoding unambiguous? One-byte label length, two-byte identity lengths, fixed 48-byte pins and a fixed 64-byte exporter
   value. Check `transcript_bytes` for any way two different transcripts give the same bytes.
7. Every refusal is the same one-byte `REFUSED` frame, and the server runs the proof check and the enrollment check whatever the
   first answered (`handshake.rs`, `check_hello`). Does the uniform refusal leak anything through timing or frame size? Known
   differences: a HELLO of the wrong length or tag, or with a key that does not parse, is refused before either check runs; the
   `MemoryRegistry` lookup is a linear scan that is not constant-time; ML-DSA verification time may depend on the signature.
   Which of these, if any, matters for an attacker who can try many HELLO frames?
8. The server proves itself only after the client's proof and enrollment pass. Is there a reflection, a cross-role or a
   key-confusion attack left over that the role labels and the pins do not stop? Is there an unknown-key-share style attack when
   the client has no transport identity (the anonymous `PeerId`)?
9. A server verifies a well-formed HELLO (7,320 bytes) before it knows the sender is enrolled, which costs an ML-DSA-87 verification
   per unauthenticated connection. Is that an acceptable default, or should enrollment be checked first, accepting the timing
   difference? There is no rate limit or connection cap in pqbind.

**The transport binding**

10. Is the exporter used correctly? The label is `EXPORTER-pqbind-v1`, the context is the application label (1 to 255 bytes) and the
    output is 64 bytes, read through `export_keying_material` for quinn and iroh and through rustls for TLS 1.3 (`binding.rs`,
    `adapters/`). Check the QUIC case in particular: 0-RTT and early data, connection migration, resumption with a pre-shared key,
    and whether two connections can ever share an exporter value.
11. pqbind does not check which key exchange the transport negotiated. The proof is only as strong as the secrecy of the exporter
    value, which assumes the session secret is not recoverable by the attacker, that is, that the key exchange is post-quantum. The
    application must configure that. Is this boundary stated clearly enough, and should the adapters refuse a classical-only
    negotiation?
12. The transport identity of a TLS peer is the SHA-384 of its leaf certificate, and of an iroh peer its 32-byte node ID. A client
    without a certificate is anonymous. What does that cost in enrollment? Every certificate-less client shares the identity
    `anonymous`, so enrollment is by key only.

**Key validation and dependencies**

13. A public key whose ML-DSA `t1` is all zero is refused, because such a key makes the verification equation independent of the
    key (`mldsa.rs`, `MlDsaVerifyingKey::from_bytes`). Is that enough as ML-DSA public key validation? FIPS 204 asks for no more than
    a length check, but are there other weak keys a verifier should refuse? Who can choose a key a victim will trust is part of the
    answer: in pqbind a key is trusted only after enrollment or pinning.
14. Public keys must be canonical (a key that decodes but re-encodes differently is refused, so one key has one pin). Is the check
    in `PublicIdentity::from_bytes` complete?
15. The ML-DSA half rests on the RustCrypto `ml-dsa` crate, version 0.1 (the lockfile has 0.1.1), which states that it has not been
    independently audited. What does that mean for this design? The mitigation today is the ACVP answers above, the negative tests,
    and the fact that the Ed25519 half must also verify. There has been no cross-check against a second ML-DSA implementation, no
    verification-failure vectors, and no side-channel analysis of the crate. Would you accept it in a release, or require a
    different implementation first?
16. Signing is deterministic (no per-signature randomness). Is that acceptable here, given the exposure of the signer to fault
    attacks? Should a hedged variant be used?
17. Is anything in the dependency set (`ed25519-dalek` 3, `hkdf` 0.13, `sha2` 0.11, `rand` 0.10, `zeroize`) used in a way that its
    documentation advises against?

## What the evidence does not cover

- **Outside review.** None of the design or the code has had one.
- **Formal analysis.** There is no proof of the composition and no model-checked protocol (Tamarin, ProVerif or similar).
- **Side channels.** No side-channel testing, no constant-time analysis, and no analysis of memory exposure beyond the zeroizing
  types.
- **Dependencies.** They are not audited, in particular `ml-dsa`. `cargo deny` checks licenses and advisories, not correctness.
- **Platforms.** The full test suite has run on Windows 11 and on Ubuntu under WSL 2. macOS was only compile-checked for both Apple
  targets and has never run the code.
- **Fuzzing.** Each of the five fuzz targets ran for 30 seconds on Windows without a sanitizer and found nothing. That is far less
  than a real fuzzing campaign. `proptest` covers hostile input as well, and is much weaker.
- **Interoperability.** There is one implementation, so the wire format has not been checked against another.
- **iroh.** It was exercised on direct IPv4 loopback only, not through relays or over IPv6.
- **Resource use.** Stack use was measured on Windows only (key expansion 960 KiB debug, 480 KiB release; signing 288 and 144 KiB;
  verifying 144 and 80 KiB) with `crates/pqbind-cli/examples/stack_probe.rs`. There is no heap measurement and no performance
  measurement.
- **Compliance.** pqbind is not FIPS validated and makes no compliance claim.
- **`probe`.** The command is a diagnostic, not a security scanner. It does not validate certificates.
