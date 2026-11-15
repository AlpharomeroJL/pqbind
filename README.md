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

### `probe`: which post-quantum key exchange does a host accept?

```text
pqbind probe cloudflare.com google.com
```

For each host it tries one key exchange group at a time (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, pure MLKEM1024
and two classical baselines) and reports the verdict: PQ capable, no post-quantum, PQ intolerant (a heuristic), unreachable or
inconclusive. **It does not validate certificates**; it only tests the key exchange. Exit code 0 means every host is PQ capable.
An example from the author's machine on 2026-11-15 (results depend on the host and your network):

```text
cloudflare.com   verdict: PQ capable (X25519MLKEM768)
google.com       verdict: PQ capable (X25519MLKEM768, MLKEM1024)
```

## Use it as a library

A sketch, not compiled documentation (see `crates/pqbind/tests/quinn_loopback.rs` for working code):

```rust
// Both ends: a hybrid identity, and the transport identity the transport already authenticated.
let me = pqbind::HybridIdentity::generate()?;

// Client: after the QUIC handshake, open a stream, then prove and check.
let mut io = pqbind::adapters::quinn::open(&connection, b"my-app/v1").await?;
let server_id = pqbind::adapters::quinn::peer_id(&connection);
let established = pqbind::connect(&mut io, &me, &pqbind::PeerId::anonymous(), &server_id, &server_pin).await?;
let (reader, writer) = io.into_parts(); // application data from here on

// Server: accept, with the registry of enrolled clients.
let mut io = pqbind::adapters::quinn::accept(&connection, b"my-app/v1").await?;
let client_id = pqbind::adapters::quinn::peer_id(&connection);
let established = pqbind::accept(&mut io, &me, &own_id, &client_id, &registry).await?;
```

Neither end may send application data until its call returns `Ok`.

## Trust model

pqbind authenticates keys that were **enrolled or pinned beforehand**. Keys travel inside the connection, but a key is never
trusted because it was sent. There is no trust on first use. How a key gets enrolled (a QR code, an admin, a ticket) is outside the
guarantee; see [THREAT_MODEL.md](THREAT_MODEL.md) and [DESIGN.md](DESIGN.md).

## Layout

| Path | What it is |
|---|---|
| `crates/pqbind-crypto` | Hybrid Ed25519 + ML-DSA-87 signature, HKDF-SHA384, SHA-384. Small on purpose, so it can be reviewed alone. |
| `crates/pqbind` | Identity and pin, exporter binding, proof, trust registry, frames and the handshake |
| `crates/pqbind/src/adapters` | quinn, rustls (TLS 1.3 over TCP) and iroh adapters, each behind its own Cargo feature |
| `crates/pqbind-cli` | The `pqbind` command: `demo`, `keygen`, `serve`, `verify`, `probe` |

## Tests

```text
cargo test --workspace --all-features
```

About 160 tests, including: unit tests; NIST ACVP known answers for ML-DSA-87; attack tests that give the attacker one half of a
key, each with a positive control that proves the forging helper is itself correct; replay, relay and malformed-frame cases; random
and near-valid hostile input; real QUIC, TLS and iroh connections on 127.0.0.1; and a guard that fails if a primitive constant
or an unlisted dependency appears in `pqbind-crypto`. The tests bind sockets on loopback only.

## Security status

Extensively tested. The design, including the composition of Ed25519 and ML-DSA-87, has **not been independently reviewed**.
The ML-DSA half rests on the RustCrypto `ml-dsa` crate (0.1), which states that it has never been independently audited. This is not
FIPS validated. See [SECURITY.md](SECURITY.md).

## Known limitations

- Only Windows has been tested. The Unix file-permission branch of `keygen` has never been run.
- The iroh adapter was exercised on direct IPv4 loopback only, not through relays or IPv6.
- The command line runs on large stacks because the demo overflowed the default Windows main-thread stack in a debug build.
  Stack use of ML-DSA-87 in other builds has not been measured.
- The minimum supported Rust version is not determined; the code has been tested on Rust 1.99.
- `keygen` cannot restrict file permissions on Windows with the standard library alone; it says so, and you should restrict the seed
  file yourself.

## License

pqbind is available under the **GNU Affero General Public License, version 3** (`AGPL-3.0-only`), or under a **commercial
license** from VaultScribe Limited Liability Company. See [LICENSING.md](LICENSING.md).

## Trademark

VaultScribe™ is a trademark of VaultScribe Limited Liability Company. The license does not grant rights to use the VaultScribe name
or logo. See [TRADEMARKS.md](TRADEMARKS.md).
