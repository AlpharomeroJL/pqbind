# Architecture

This page shows how the pieces fit: the crates and layers, what happens on one connection, and where each piece of code lives.
For the reasons behind the choices see [DESIGN.md](../DESIGN.md); for what is and is not defended against see
[THREAT_MODEL.md](../THREAT_MODEL.md).

## Crates and layers

```text
   your application
        |  calls  pqbind::connect  (client)   or   pqbind::accept  (server)
        v
 +--------------------------------------------------------------------------------+
 | pqbind                                                                         |
 |                                                                                |
 |   handshake   HELLO, SERVER_PROOF, REFUSED; the order of every check          |
 |   proof       the exact bytes a proof signs, per role                          |
 |   identity    HybridIdentity, PublicIdentity, Pin (SHA-384), PeerId            |
 |   trust       ClientRegistry, MemoryRegistry (the enrolled keys)               |
 |   binding     the 64-byte TLS exporter value and the application label         |
 |   frame       FrameIo and StreamFrames: length-prefixed frames, time limits    |
 |                                                                                |
 |   adapters    quinn | rustls | iroh   (each behind its own Cargo feature)      |
 +----------------------------------+---------------------------------------------+
        | exporter value, streams,        | signs and verifies, hashes, derives
        | remote transport identity       v
        v                          +-----------------------------------------------+
 transport you already have        | pqbind-crypto                                 |
 (QUIC or TLS 1.3, assumed to      |   hybrid   Ed25519 + ML-DSA-87, both required |
  use a post-quantum key           |   mldsa    ML-DSA-87 (the ml-dsa crate)       |
  exchange; classical              |   sign     Ed25519, strict (ed25519-dalek)    |
  certificates or node ids)        |   kdf      HKDF-SHA384                        |
                                   |   hash     SHA-384, HMAC-SHA-384              |
                                   |   suite, random, secret, error                |
                                   +-----------------------------------------------+

 pqbind-cli (the `pqbind` command: demo, keygen, serve, verify, probe) uses pqbind with the
 quinn and rustls features, and pqbind-crypto directly. Nothing depends on the command line.
```

- **`pqbind-crypto`** is the part to review first. It invents no algorithm: every primitive comes from an established crate, wrapped
  with zeroization and errors that carry no secret bytes. A test fails if a known primitive constant or an unlisted dependency
  appears in it.
- **`pqbind`** is the protocol. The core depends on no transport. It is generic over `FrameIo`, a channel that carries whole
  frames and knows the connection's exporter value.
- **The adapters** connect that to a real transport. Each does two jobs: read the exporter value (always through
  `Binding::derive`, so the label and context cannot be passed wrongly) and carry frames over one stream. Each also names the remote
  end's transport identity.
- **`pqbind-cli`** is a demonstration and diagnostic tool built on the library. It is not needed to use the library.

## The data flow of one connection

```text
   client                                                                      server
     |                                                                           |
 1.  |<=============== transport handshake (QUIC or TLS 1.3) ====================>|
     |      key exchange (post-quantum hybrid, configured by the application)     |
     |      server certificate checked as usual (classical)                       |
     |                                                                           |
 2.  | adapter reads the exporter value: label "EXPORTER-pqbind-v1",              | adapter does the same
     |   context = application label, 64 bytes. Both ends read the same value.    |
     | adapter names the remote end: SHA-384 of the leaf certificate (TLS/QUIC)   |
     |   or the 32-byte node id (iroh); anonymous if there is no certificate      |
     | adapter gives frames over one stream                                       |
     |                                                                           |
 3.  | HELLO  0x01 | client public key (2626) | client proof (4693) -------------->|
     |   proof = hybrid signature over the client transcript                      |
     |                                                                           |
 4.  |                                    server checks the frame shape, parses the key,
     |                                    verifies the proof and checks enrollment;
     |                                    both checks always run                  |
     |                                                                           |
 5a. |<-- SERVER_PROOF  0x02 | server public key (2626) | server proof (4693) ----|   if both passed
 5b. |<-- REFUSED  0x03 ----------------------------------------------------------|   otherwise, always the same frame
     |                                                                           |
 6.  | client checks the key against its pin and verifies the server proof      |
     |   (any failure: Err and no application data is sent)                       |
     |                                                                           |
 7.  |<================== application data on the same streams ===================>|
     |   (only after connect / accept returned Ok on that end)                   |
```

A transcript is, in this order: the role label (`pqbind/proof/client/v1` or `.../server/v1`, each ending in a zero byte), a
one-byte length and the application label, a two-byte length and the client's transport identity, a two-byte length and the
server's transport identity, the client's pin (48 bytes), the server's pin (48 bytes) and the exporter value (64 bytes). The
hybrid key signs `label | SHA-512(transcript)` with both halves. Each frame on the wire is a four-byte big-endian length and the
bytes, at most 16 KiB, with a time limit on every step.

What each step buys you:

- Step 2 makes every proof specific to one connection: another connection reads another exporter value, so a proof does not
  replay or relay.
- Step 4 means a server never reveals which check failed, and never proves itself to a client that has not passed.
- Step 6 means a client never sends application data to a peer that has not proved the pinned key.

## Module map

Line counts are a snapshot taken with `wc -l` when this page was written; they will drift. Every source file starts with a
`//! Responsibility:` line saying what it is for, and that line is the better description if the two disagree.

### `crates/pqbind-crypto/src`

| File | Lines | What it does |
|---|---:|---|
| `lib.rs` | 42 | Crate docs, the module list and `#![deny(missing_docs)]`. |
| `suite.rs` | 76 | The one signature suite and its two-byte wire identifier. |
| `hybrid.rs` | 342 | The hybrid key, public key and signature: both halves sign `label \| SHA-512(message)`, both must verify. |
| `mldsa.rs` | 212 | ML-DSA-87 key, public key and signature, deterministic, empty context; refuses an all-zero `t1`. |
| `sign.rs` | 181 | Ed25519 key, public key and signature, with strict verification. |
| `kdf.rs` | 80 | HKDF-SHA384. |
| `hash.rs` | 142 | SHA-384, HMAC-SHA-384 and a streaming SHA-384 hasher. |
| `sha384.rs` | 9 | Re-exports the one SHA-384 hasher so callers share it. |
| `random.rs` | 45 | Bytes from the operating system, failing loudly rather than falling back. |
| `secret.rs` | 43 | `SecretBytes`: zeroizes on drop, no `Debug`, no `Clone`. |
| `error.rs` | 50 | `CryptoError`, whose variants carry no key or input bytes. |
| `zeroize_check.rs` | 49 | Test-only helper that checks a type wipes itself on drop. |

### `crates/pqbind/src`

| File | Lines | What it does |
|---|---:|---|
| `lib.rs` | 125 | Crate docs with two runnable doctests, and the public re-exports. |
| `handshake.rs` | 179 | `connect` and `accept`: HELLO, SERVER_PROOF, REFUSED and the order of the checks. |
| `proof.rs` | 107 | `Transcript`, `Role`, and the functions that build, sign and verify a proof. |
| `identity.rs` | 302 | `HybridIdentity`, `PublicIdentity` (canonical encoding), `Pin` and `PeerId`. |
| `trust.rs` | 219 | `ClientRegistry`, `MemoryRegistry` and its strict encoded form. |
| `binding.rs` | 113 | `Binding`: the exporter value and application label, read through `Binding::derive`. |
| `frame.rs` | 212 | `FrameIo`, `StreamFrames` (length-prefixed frames with time limits) and a non-panicking byte reader. |
| `error.rs` | 49 | The `Error` type, with variants that carry no key, proof or identity bytes. |
| `adapters/mod.rs` | 21 | The feature-gated adapter modules. |
| `adapters/quinn.rs` | 60 | quinn: `open`, `accept`, `peer_id`. |
| `adapters/rustls.rs` | 63 | rustls over TLS 1.3 only: `frames`, `peer_id`. |
| `adapters/iroh.rs` | 129 | iroh: `open`, `accept`, `peer_id`, `own_id`. |
| `examples/quinn_client_server.rs` | 114 | The runnable teaching example over real QUIC on 127.0.0.1. |

### Tests

| File | Lines | What it does |
|---|---:|---|
| `crates/pqbind-crypto/tests/mldsa87_acvp.rs` | 63 | NIST ACVP known answers for ML-DSA-87 (three key generation and three signing cases). |
| `crates/pqbind-crypto/tests/no_home_grown_primitives.rs` | 118 | Fails on a known primitive constant or an unlisted dependency. |
| `crates/pqbind-crypto/tests/known_answers.rs` | 254 | Fixed-byte vectors for the hybrid signature, made by this same code (they pin the format; they are not independent). |
| `crates/pqbind/tests/handshake_memory.rs` | 165 | The handshake over an in-memory channel: every refusal, replay, relay and malformed frames. |
| `crates/pqbind/tests/attack_stolen_classical_key.rs` | 143 | An attacker with one half of a key, each with a positive control. |
| `crates/pqbind/tests/hostile_input.rs` | 64 | Random and near-valid input never panics and is never accepted. |
| `crates/pqbind/tests/quinn_loopback.rs` | 187 | The quinn adapter over real QUIC on 127.0.0.1. |
| `crates/pqbind/tests/rustls_loopback.rs` | 221 | The rustls adapter over real TLS 1.3, and the refusal of TLS 1.2. |
| `crates/pqbind/tests/iroh_adapter.rs` | 170 | The whole handshake over real iroh connections on loopback. |
| `crates/pqbind/tests/known_answers.rs` | 776 | Fixed-byte vectors for the proof layout and the handshake frames, made by this same code. |
| `crates/pqbind/tests/common/mod.rs` | 384 | Shared helpers for the integration tests. |

### `crates/pqbind-cli`

The command line was being reorganized while this page was written, so it is described by directory, not by file. Each file has a
`//! Responsibility:` line.

| Path | What it does |
|---|---|
| `src/main.rs`, `src/runtime.rs` | Parse the arguments, start a 2 MiB thread (the measured minimum is about 1 MiB in a debug build) and an async runtime, and hand the chosen command to it. |
| `src/commands/` | One module per command: `demo` (the eight scenarios), `keygen`, `serve`, `verify` and `probe` (the key exchange probe, including its own `SecP384r1MLKEM1024` group). |
| `src/transport/` | The QUIC and TLS 1.3 endpoints, certificates and framing the commands share. |
| `src/common.rs`, `src/keyfiles.rs` | Shared errors and text helpers, and the seed and public key files. |
| `examples/stack_probe.rs` | Measures how much stack one hybrid signature operation needs. |
