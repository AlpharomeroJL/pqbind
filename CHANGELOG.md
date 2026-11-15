# Changelog

All notable changes to this project are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project intends to follow [Semantic Versioning](https://semver.org/) once it has a release.

## [Unreleased]

pqbind has no release yet. The crates are marked `publish = false` and the version is `0.0.0`. Limitations are listed in
[SECURITY.md](SECURITY.md).

### Added

- `pqbind-crypto`: hybrid Ed25519 and ML-DSA-87 signatures from one 32-byte seed, HKDF-SHA384, SHA-384, and secret types that wipe
  themselves on drop. ML-DSA-87 key generation and deterministic signing are checked against NIST ACVP known answers.
- `pqbind`: the handshake that signs a connection's TLS exporter value with the hybrid key, with adapters for quinn, rustls (TLS 1.3
  only) and iroh, each behind its own Cargo feature.
- `pqbind-cli`: the `pqbind` command line with `demo` (eight attack scenarios over real connections), `keygen`, `serve`, `verify` and
  `probe` (which key exchange groups a host accepts).
- Tests for attacks, replay, relay, malformed input and loopback transports, and five cargo-fuzz targets.
- A dual license: AGPL-3.0-only or a commercial license (see [LICENSING.md](LICENSING.md)).
- CI for Windows, Linux and macOS, `cargo-deny` and REUSE checks, and the local check scripts in `scripts/`.
