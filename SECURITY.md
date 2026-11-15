# Security

## Reporting a vulnerability

Report security problems privately, not in a public issue. Contact: josefdean@protonmail.com.

Include what you found, how to reproduce it and the impact you expect. There is no bounty.

## Supported versions

pqbind is pre-1.0 and has no releases. Only the latest commit is supported.

## Security model and limitations

pqbind authenticates the two ends of an existing TLS 1.3 or QUIC connection with a hybrid Ed25519 + ML-DSA-87 proof bound to the
connection's TLS exporter value. [THREAT_MODEL.md](THREAT_MODEL.md) lists what it stops; [DESIGN.md](DESIGN.md) specifies the
protocol. Do not use it to protect anything you cannot afford to lose.

**Review status**

- The design has not had an independent review. [docs/REVIEW.md](docs/REVIEW.md) lists the questions a reviewer should answer.
- The ML-DSA half depends on the RustCrypto `ml-dsa` 0.1 crate, which states that it has not been independently audited.
- The hybrid composition is pqbind's own. It is not an IETF composite-signature scheme.
- pqbind is not FIPS validated and makes no compliance claim, including for CNSA 2.0.

**Protocol limits**

- pqbind does not check that the transport negotiated a post-quantum key exchange. The proof is only as strong as the secrecy of
  the exporter value, so the application must configure a post-quantum key exchange in the transport.
- A server verifies a well-formed HELLO before it knows the sender is enrolled, and pqbind has no rate limit or connection cap. An
  unauthenticated peer can make the server spend one ML-DSA-87 verification per connection. The application must add its own limits.
- Data sent before `connect` or `accept` returns `Ok`, including QUIC 0-RTT data, is not authenticated.
- Theft of a whole private key (both halves) is outside the model: whoever holds it is that peer.
- Enrollment is outside the guarantee. A pin or enrolled key delivered over a channel an attacker controls defeats it.
- Side channels, and the memory exposure of anything not covered by the zeroizing types, have not been analyzed.

**Testing and platforms**

| Platform | Status |
|---|---|
| Windows | Full test suite run |
| Linux (Ubuntu under WSL 2) | Full test suite run |
| macOS | Compiles for both Apple targets; the code has not been run there |

- iroh was exercised on direct IPv4 loopback only, not through relays or over IPv6.
- Five fuzz targets each ran for 30 seconds without a sanitizer and found nothing. That is a smoke run, not a fuzzing campaign.
  See [fuzz/README.md](fuzz/README.md).
- There is one implementation, so the wire format has not been checked against another.
- ML-DSA-87 needs a large stack in an unoptimized build. Measured on Windows with `crates/pqbind-cli/examples/stack_probe.rs`, key
  expansion needs about 960 KiB in a debug build and 480 KiB in a release build; signing needs 288 and 144 KiB, and verifying 144
  and 80 KiB. Heap use and performance have not been measured.

**What the tests cover**

Unit tests for the hybrid signature, NIST ACVP known answers for ML-DSA-87 key generation and deterministic signing, attack tests
with one half of a key, replay, relay, wrong-identity and malformed-frame cases, property tests on hostile input, and real
connections over QUIC, TLS 1.3 and iroh on 127.0.0.1. A guard test fails if a known primitive constant or an unlisted dependency
appears in `pqbind-crypto`. Secret-bearing types wipe themselves on drop, checked at the type level. The tests do not replace
review: they show the code does what is intended, not that the intent is sound.
