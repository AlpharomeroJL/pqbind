# Threat model

This document describes what pqbind is meant to stop, and what it is not. The demo (`pqbind demo`) runs each scenario below for
real, except where it says otherwise.

## What pqbind adds

The transport (TLS 1.3 or QUIC) is assumed to already use a post-quantum hybrid key exchange. pqbind adds an authentication step
that does not rely on classical signatures alone.

## Attackers pqbind is meant to stop

- **An active attacker who can forge the classical authentication** of a peer, for example one with a large quantum computer who
  can derive a classical private key from a public key. They can complete the classical handshake (the demo gives the attacker the
  TLS certificate key and the Ed25519 half of the hybrid key) but cannot sign with the ML-DSA half, so the proof fails. Demo
  scenarios b1, b2 and c.
- **A relay or man in the middle.** Each leg of a relayed connection has a different TLS exporter value, so a proof made on one leg
  does not verify on the other. Demo scenario d.
- **Replay of an old proof.** A proof signs the exporter value of one connection, so it does not verify on another.
- **Reflection.** The two roles sign under different labels and the signed bytes include both peers' identities and both pins, so a
  server's proof cannot be reused as a client's.
- **A client that pinned the wrong key,** and **a client that was never enrolled.** Both are refused. Demo scenario e runs the
  second. The first is covered by the tests (`handshake_memory.rs` and `iroh_adapter.rs`), not by the demo.

## What pqbind does not cover

- **Compromise of a whole private key.** An attacker who holds both halves of a hybrid private key is that peer. The demo shows this
  (scenarios f1 and f2) on purpose: the attacker is accepted.
- **Enrollment and first contact.** The guarantee starts from keys that were enrolled or pinned beforehand. If the pin was delivered
  over a channel an attacker controlled, nothing here helps.
- **Confidentiality.** That is the job of the transport's key exchange.
- **Browsers and ordinary TLS clients.** pqbind needs both ends to run it.
- **Applications that do not require it.** A peer that skips the pqbind step is unauthenticated by pqbind. The application must
  refuse connections that do not complete the handshake, and must not send application data before it returns `Ok`.
- **Data sent before the handshake returns.** Anything an application sends before `connect` or `accept` returns `Ok`, including
  QUIC 0-RTT data if the application turns it on, is not authenticated by pqbind.
- **Denial of service.** A server verifies a well-formed HELLO before it knows the sender is enrolled, so an unauthenticated peer can
  make it spend an ML-DSA-87 verification per connection. pqbind has no rate limit or connection cap.
- **Revocation timing.** A revoked key is refused at the next check the server makes, which depends on the registry the application
  supplies.
- **Side channels** and implementation faults in the underlying libraries. The proofs are deterministic, and the registry lookup is
  not constant-time (the data it compares is public).
- **The hybrid construction itself.** It is a custom composition that has not been independently reviewed, and the ML-DSA half rests
  on a crate that states it has never been independently audited.
- **Transports other than TLS 1.3 and QUIC.** TLS 1.2 is refused, because its exporter is not bound to the whole handshake.

## About `probe`

`pqbind probe` is a diagnostic, not a security scanner. It does not validate certificates, it tests one handshake per group, and its
"PQ intolerant" verdict is a heuristic based on timeouts and resets. A host's answer can differ by network path.
