# Changelog

All notable changes to this project are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project intends to follow [Semantic Versioning](https://semver.org/) once it has a release.

## [Unreleased]

Nothing is released or published yet. The crates are marked `publish = false`, and the version is `0.0.0`.

### Added

- `pqbind-crypto`: hybrid Ed25519 and ML-DSA-87 signatures, HKDF-SHA384, SHA-384, and secret types that wipe themselves on drop.
  Checked against the NIST ACVP known answers for ML-DSA-87 key generation and deterministic signing.
- `pqbind`: the core handshake that signs a connection's TLS exporter value with the hybrid key, with adapters for quinn, rustls
  and iroh, each behind its own feature.
- `pqbind-cli`: the `pqbind` command line, with an attack demo, a verifier and a post-quantum probe.
- Attack, replay, relay, malformed-input and loopback transport tests.
- Dual license: AGPL-3.0-only or a commercial license (see `LICENSING.md`).
- Release tooling: a CI workflow for Windows, Linux and macOS, `cargo-deny` and REUSE checks, and local gate scripts in `scripts/`.

### Known limits

- The design has not been independently reviewed, and the `ml-dsa` crate it relies on has not been audited. See `SECURITY.md`.
- Only Windows has been exercised so far. Linux and macOS are first run by the CI workflow.
- The minimum supported Rust version is not determined.
