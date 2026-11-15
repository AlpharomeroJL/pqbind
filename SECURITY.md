# Security

## Status

pqbind is pre-release and **has not been independently reviewed**. The hybrid composition of Ed25519 and ML-DSA-87 is a custom
construction, not one defined by an IETF composite-signature specification. The ML-DSA half rests on the RustCrypto `ml-dsa` crate
(0.1), which says it has never been independently audited. pqbind is not FIPS validated. Do not use it to protect anything you
cannot afford to lose.

## What has been checked

- Unit tests for the hybrid signature and the primitives around it, and NIST ACVP known answers for ML-DSA-87 key generation and
  deterministic signing. Key generation runs through this crate's own type; the signing vectors carry an expanded key and a context,
  so they run on the `ml-dsa` code directly.
- Attack tests that give an attacker one half of a key (the Ed25519 half), with a positive control showing the forging helper
  reproduces a real proof byte for byte when it has both halves.
- Replay, relay, wrong-identity, wrong-key, wrong-label and malformed-frame cases; random and near-valid input never panics and is
  never accepted.
- Real connections over QUIC, TLS 1.3 and iroh on 127.0.0.1, including a stolen TLS key and a TLS 1.2 connection that must be refused.
- A guard test that fails if a known primitive constant or an unlisted dependency appears in `pqbind-crypto`.
- `cargo clippy` over the whole workspace with all features: no errors, a few minor warnings in the command line crate.
- Secret-bearing types wipe themselves on drop, and the tests check this at the type level for the parts that hold key material.

What this does not cover: side channels, memory exposure outside what is wiped, platforms other than Windows, resistance to
denial of service (a server verifies a well-formed HELLO before it knows the sender is enrolled, and pqbind has no rate limit), and
the correctness of the design itself. [docs/REVIEW.md](docs/REVIEW.md) lists the questions an independent reviewer should answer. An earlier internal audit process existed, but its reports are not available, so none of its findings are claimed
here.

## Reporting a vulnerability

Please report security problems privately, not in a public issue. Contact:
josefdean@protonmail.com. Once the repository is public, GitHub's private vulnerability reporting is the better channel; switch to it then.

Please include what you found, how to reproduce it and what you expect the impact to be. There is no bounty.
