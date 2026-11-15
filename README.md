# pqbind

**Post-quantum authentication for connections that already have post-quantum key exchange.**

Break the classical key and you still can't get in.

> **Status: pre-release (0.0.0), not published.** The hybrid signature crate, the core handshake, the quinn, rustls and iroh
> adapters and the command line are implemented and tested. The design has **not** been independently reviewed. See
> [Security status](#security-status) before you rely on it.

## The problem

Post-quantum key exchange is arriving in TLS and QUIC, and it protects recorded traffic from being decrypted later. The
authentication is a different matter. Certificates and node identities are still classical, and post-quantum certificates are not
deployed. So a connection can have a post-quantum key exchange and still be impersonated by someone who can forge a classical
signature.

## The idea

After the normal handshake, each peer signs the connection's own TLS exporter value, together with both transport identities and
both key pins, using a hybrid Ed25519 and ML-DSA-87 key. A signature verifies only when both halves verify.

- An attacker who forges the classical identity cannot produce the ML-DSA half.
- A man in the middle runs two separate sessions, so each side's exporter value differs, and a proof relayed from one leg fails on
  the other.
- No post-quantum certificates are needed.

## Documentation

| | |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | The crates and layers, the data flow of one connection, and a map of every source file |
| [docs/REVIEW.md](docs/REVIEW.md) | A guide for an independent reviewer: what to read first, how to run everything, and the questions that most need an answer |
| [docs/WRITEUP.md](docs/WRITEUP.md) | An unpublished draft article on why this exists |
| [DESIGN.md](DESIGN.md) | What the code does, and which choices are unreviewed |
| [THREAT_MODEL.md](THREAT_MODEL.md) | What pqbind is meant to stop, and what it is not |
| [SECURITY.md](SECURITY.md) | What has been checked, and how to report a problem |

API documentation is in the rustdoc of the two library crates (`cargo doc --workspace --no-deps --all-features --open`).

## Try it

```text
cargo run -p pqbind-cli -- demo                      # eight attack scenarios over real QUIC on 127.0.0.1
cargo run -p pqbind-cli -- demo --transport tls      # the same over TLS on TCP
```

`demo` exits 0 only if every scenario behaves as expected, so it doubles as a self test. It runs, for real:

| | Scenario | Expected |
|---|---|---|
| a | Honest pair | both authenticate |
| b1 | Attacker holds the server's TLS key and Ed25519 key, forges the proof | client refuses (`ServerIdentity`) |
| b2 | Same attacker runs the real pqbind code with its own key | client refused |
| c | Attacker holds an enrolled client's Ed25519 key | server refuses |
| d | Relay between two connections | server refuses the relayed proof |
| e | A client that was never enrolled | refused |
| f1, f2 | **Limit:** the whole private key is stolen | attacker is accepted; pqbind cannot help |

A small server and client, to see it work between two terminals on one machine:

```text
pqbind keygen --out client.seed --public-out client.pub
pqbind serve --listen 127.0.0.1:4433 --identity server.seed --enroll client.pub --cert-out server.pem
pqbind verify 127.0.0.1:4433 --pin <the server pin serve printed> --identity client.seed --ca server.pem
```

`serve` listens on loopback only unless you pass `--allow-non-loopback`. `verify` exits 0 when the server proved the pinned key,
1 when it refused or could not prove it, and 2 for any other failure.

### A runnable example for developers

One file, heavily commented, shows the whole flow in a single process: two identities, enrollment and pinning, a real QUIC
connection on 127.0.0.1, the proof exchange, then one line of application data each way on the same streams.

```text
cargo run -p pqbind --example quinn_client_server --features quinn
```

The source is [`crates/pqbind/examples/quinn_client_server.rs`](crates/pqbind/examples/quinn_client_server.rs).

### `probe`: which post-quantum key exchange does a host accept?

```text
pqbind probe cloudflare.com google.com
```

For each host it tries one key exchange group at a time (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, pure MLKEM1024
and two classical baselines) and reports the verdict: PQ capable, no post-quantum, PQ intolerant (a heuristic), unreachable or
inconclusive. **It does not validate certificates**; it only tests the key exchange. The exit code is 0 when every host is PQ
capable, 1 when a host has no post-quantum key exchange or is suspected PQ intolerant, and 2 when a host is unreachable or the
result is inconclusive (2 wins over 1). The verdict lines below are from the author's machine on 2026-11-15; results depend on the
host and your network:

```text
cloudflare.com
  verdict: PQ capable (X25519MLKEM768)
google.com
  verdict: PQ capable (X25519MLKEM768, MLKEM1024)
```

## Use it as a library

The handshake is generic over a frame channel, so it needs no transport at all to try. This snippet is compiled and run as a
doctest in the `pqbind` crate docs (`crates/pqbind/src/lib.rs`), over an in-memory pipe. A real transport adapter reads the exporter
value from the live connection; the example above does that over QUIC. The snippet uses `?`, so run it inside an async function that
returns `Result<_, pqbind::Error>` (the doctest wraps it that way).

```rust
use pqbind::{Binding, Enrollment, HybridIdentity, MemoryRegistry, PeerId, StreamFrames, accept, connect};

// Each end makes a hybrid identity.
let client = HybridIdentity::generate()?;
let server = HybridIdentity::generate()?;

// Enrollment happens before any connection, outside pqbind. The server enrolls the client's public key, and the client keeps the
// pin (the SHA-384 of the whole public key) of the server. This client presents no transport identity, so it is anonymous.
let registry = MemoryRegistry::new();
registry.enroll(Enrollment { key: client.public(), peer_id: PeerId::anonymous(), enrolled_at_unix_millis: 0 });
let server_pin = server.pin();

// The transport. An adapter would hand each end a `StreamFrames` over the connection's stream, with the exporter value it read.
let (client_pipe, server_pipe) = tokio::io::duplex(64 * 1024);
let exporter = [7_u8; 64];
let (client_read, client_write) = tokio::io::split(client_pipe);
let (server_read, server_write) = tokio::io::split(server_pipe);
let mut client_io = StreamFrames::new(client_read, client_write, Binding::new(b"my-app/v1", exporter)?);
let mut server_io = StreamFrames::new(server_read, server_write, Binding::new(b"my-app/v1", exporter)?);

// The transport identity of the server, as the transport authenticated it (for TLS, the hash of its certificate).
let server_id = PeerId::new(b"the server's transport identity".to_vec())?;

// Both ends run their half. Neither may send application data until its call returns `Ok`.
let anonymous = PeerId::anonymous();
let (from_client, from_server) = tokio::join!(
    connect(&mut client_io, &client, &anonymous, &server_id, &server_pin),
    accept(&mut server_io, &server, &server_id, &anonymous, &registry),
);
assert_eq!(from_client?.peer_key(), &server.public()); // the client now knows it talks to the pinned server
assert_eq!(from_server?.peer_key(), &client.public()); // the server now knows it talks to an enrolled client
```

Three things to know:

- Neither end may send application data until its call returns `Ok`, and an application must refuse a connection that does not
  complete the handshake. pqbind cannot enforce that for you.
- The frame timeouts use `tokio::time`, so the tokio runtime must have its time driver enabled.
- The lattice signature code keeps large buffers on the stack: ML-DSA-87 key expansion alone needs about 1 MiB in a debug build and
  about 0.5 MiB in a release build (measured on Windows; see [Known limitations](#known-limitations)). Do not call it on a thread
  with a smaller stack. An ordinary Windows main thread has 1 MiB.

The transport adapters are behind Cargo features: `quinn`, `rustls` (TLS 1.3 over TCP) and `iroh`. Each gives you the frames over one
stream and the transport identity of the remote end.

## Trust model

pqbind authenticates keys that were **enrolled or pinned beforehand**. Keys travel inside the connection, but a key is never
trusted because it was sent. There is no trust on first use. How a key gets enrolled (a QR code, an admin, a ticket) is outside the
guarantee; see [THREAT_MODEL.md](THREAT_MODEL.md) and [DESIGN.md](DESIGN.md).

## Layout

| Path | What it is |
|---|---|
| `crates/pqbind-crypto` | Hybrid Ed25519 + ML-DSA-87 signature, HKDF-SHA384, SHA-384 and HMAC-SHA-384. Small on purpose, so it can be reviewed alone. |
| `crates/pqbind` | Identity and pin, exporter binding, proof, trust registry, frames and the handshake |
| `crates/pqbind/src/adapters` | quinn, rustls (TLS 1.3 over TCP) and iroh adapters, each behind its own Cargo feature |
| `crates/pqbind/examples` | `quinn_client_server`, the runnable teaching example |
| `crates/pqbind-cli` | The `pqbind` command: `demo`, `keygen`, `serve`, `verify`, `probe` |
| `docs/` | Architecture, the reviewer's guide and the draft article |

## Tests

```text
cargo test --workspace --all-features
```

Over 200 tests (the exact count changes; a few ignored regeneration helpers are not counted), including: unit tests; NIST ACVP known answers for ML-DSA-87; attack tests that give the attacker one half of a
key, each with a positive control that proves the forging helper is itself correct; replay, relay and malformed-frame cases; random
and near-valid hostile input; real QUIC, TLS and iroh connections on 127.0.0.1; known-answer vectors that pin the wire format (made
by this same code, so they are not independent evidence); two doctests; and a guard that fails if a primitive
constant or an unlisted dependency appears in `pqbind-crypto`. The tests bind sockets on loopback only. The reviewer's guide,
[docs/REVIEW.md](docs/REVIEW.md), says what each group of tests claims.

## Security status

Extensively tested. The design, including the composition of Ed25519 and ML-DSA-87, has **not been independently reviewed**.
The ML-DSA half rests on the RustCrypto `ml-dsa` crate (0.1), which states that it has never been independently audited. This is not
FIPS validated. See [SECURITY.md](SECURITY.md).

## Known limitations

- Only Windows has been tested. The Unix file-permission branch of `keygen` has never been run.
- The iroh adapter was exercised on direct IPv4 loopback only, not through relays or IPv6.
- **Stack use of ML-DSA-87** (measured on Windows 11 with Rust 1.94.1, one operation alone on a fresh thread; the smallest stack that
  worked, found with `crates/pqbind-cli/examples/stack_probe.rs`): key expansion 960 KiB debug and 480 KiB release; signing 288 KiB
  debug and 144 KiB release; verifying 144 KiB debug and 80 KiB release. The cause is the `ml-dsa` crate's own buffers. The command
  line runs its commands on a 2 MiB thread and its async workers on 1.25 MiB. Other platforms were not measured.
- The minimum supported Rust version is not proven. `Cargo.toml` declares 1.94, the lowest version checked, on the only two stable
  toolchains the author had (1.94.1 and 1.99.0).
- `keygen` cannot restrict file permissions on Windows with the standard library alone; it says so, and you should restrict the seed
  file yourself.

## License

pqbind is available under the **GNU Affero General Public License, version 3** (`AGPL-3.0-only`), or under a **commercial
license** from VaultScribe Limited Liability Company. See [LICENSING.md](LICENSING.md).

## Trademark

VaultScribe™ is a trademark of VaultScribe Limited Liability Company. The license does not grant rights to use the VaultScribe name
or logo. See [TRADEMARKS.md](TRADEMARKS.md).
