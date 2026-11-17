# Threat model

This page states what pqbind stops and what it does not. `pqbind demo` runs each scenario named below against real connections,
except where noted. Scenario letters refer to the demo's output.

## What pqbind adds

The transport (TLS 1.3 or QUIC) is assumed to use a post-quantum hybrid key exchange already. pqbind adds an authentication step
that does not rely on classical signatures alone: each end proves it holds a hybrid Ed25519 + ML-DSA-87 key, bound to the
connection. See [DESIGN.md](DESIGN.md) for the exact proof.

## What pqbind stops

| Attacker | Why it fails | Demo |
|---|---|---|
| **An active attacker who can forge classical authentication**, for example one with a large quantum computer who derives a classical private key from a public key. | The attacker completes the classical handshake (the demo gives it the TLS certificate key and the Ed25519 half of the hybrid key) but cannot sign with the ML-DSA half, so the proof fails. | b1, b2, c |
| **A relay or man in the middle.** | Each leg of a relayed connection has a different TLS exporter value, so a proof made on one leg does not verify on the other. | d |
| **Replay of an old proof.** | A proof signs the exporter value of one connection, so it does not verify on another. | tests |
| **Reflection.** | The two roles sign under different labels, and the signed bytes include both identities and both pins, so a server's proof cannot be reused as a client's. | tests |
| **A client that was never enrolled.** | The server refuses it with the same single-byte answer as every other refusal. | e |
| **A client that pinned the wrong server key.** | The client's proof covers the pin it holds, so the real server refuses it. A different server key fails the client's own pin check. | tests |

"Tests" means the case is covered by the test suite (`handshake_memory.rs`, `iroh_adapter.rs` and the attack tests) and not by the
demo.

## What pqbind does not cover

- **Compromise of a whole private key.** An attacker who holds both halves of a hybrid private key is that peer. Demo scenarios f1
  and f2 show this on purpose: the attacker is accepted.
- **Enrollment and first contact.** The guarantee starts from keys that were enrolled or pinned beforehand. If the pin was delivered
  over a channel an attacker controlled, nothing here helps. `pqbind enroll add` makes the check hard to skip, because it enrolls a
  key only when the pin was confirmed, but it cannot tell whether the pin you confirmed against came from the right person.
- **Confidentiality.** That is the job of the transport's key exchange. pqbind does not check that the transport negotiated a
  post-quantum key exchange; the application must configure one.
- **Browsers and ordinary TLS clients.** Both ends must run pqbind.
- **Applications that do not require it.** A peer that skips the pqbind step is unauthenticated by pqbind. The application must
  refuse connections that do not complete the handshake, and must not send application data before it returns `Ok`.
- **Data sent before the handshake returns.** Anything an application sends before `connect` or `accept` returns `Ok`, including
  QUIC 0-RTT data if the application turns it on, is not authenticated by pqbind.
- **Denial of service.** A server verifies a well-formed HELLO before it knows the sender is enrolled, so an unauthenticated peer can
  make it spend one ML-DSA-87 verification per connection. pqbind has no rate limit or connection cap.
- **Revocation timing.** A revoked key is refused at the next check the server makes, which depends on the registry the application
  supplies.
- **Side channels** and implementation faults in the underlying libraries. Proofs are deterministic, and the registry lookup is
  not constant-time (the data it compares is public).
- **The hybrid construction itself.** It is pqbind's own composition, not an IETF composite scheme, and it has not had an
  independent review. The ML-DSA half rests on a crate that states it has not been independently audited.
- **Transports other than TLS 1.3 and QUIC.** TLS 1.2 is refused, because its exporter is not bound to the whole handshake.

## About `probe`

`pqbind probe` is a diagnostic, not a security scanner. It does not validate certificates, it tests one handshake per group, and its
"PQ intolerant" verdict is a heuristic based on timeouts and resets. A host's answer can differ by network path.
