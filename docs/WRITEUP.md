> **UNPUBLISHED DRAFT.** This article has not been published or reviewed by anyone else. Facts in it are meant to be checkable
> against this repository; where one is not, the text says so. Do not publish it before the design has had an independent review
> (see [REVIEW.md](REVIEW.md)).

# Your TLS is post-quantum. Your authentication isn't.

Most of the effort to prepare the internet for quantum computers has gone into key exchange, and for a good reason. Someone can
record encrypted traffic today and decrypt it later, once a large enough quantum computer exists. The fix is to mix a
post-quantum key exchange into the handshake, and that is happening: the hybrid group X25519MLKEM768 combines classical X25519
with ML-KEM-768 (FIPS 203).

A quick check shows it is live. I ran `pqbind probe` against two large hosts on 2026-11-15, from my own network. It offers one key
exchange group per handshake and records the answer. This is a point-in-time observation, and other networks or other days may
differ:

- cloudflare.com accepted X25519MLKEM768 and rejected SecP256r1MLKEM768, SecP384r1MLKEM1024 and pure MLKEM1024.
- google.com accepted X25519MLKEM768 and pure MLKEM1024, and rejected the other two post-quantum groups.

(The probe tests the key exchange only. It does not validate certificates.)

## The gap

Key exchange protects secrecy against a future attacker. Authentication is a different problem, because it is checked now, by
the party you are talking to. If a classical signature can be forged in the future, then a connection with a perfectly good
post-quantum key exchange can still be impersonated, by someone who forges the certificate signature or the node key. To my
knowledge, post-quantum certificates are not deployed on the public web, and the identities that peer-to-peer systems use are
classical keys too. I have not measured that here, so check it before you rely on it.

For a closed system, the gap can be closed without waiting for the web to change. If you control both ends of a connection, you
can add your own authentication step on top of the transport you already have.

## What pqbind does

pqbind (pre-release, version 0.0.0, not published) adds that step. After the normal TLS 1.3 or QUIC handshake, each peer signs a
transcript with a hybrid key made of Ed25519 and ML-DSA-87 (FIPS 204). The transcript contains:

- the connection's TLS exporter value, 64 bytes that both ends derive from the session and that no other session shares;
- both transport identities (for TLS, the hash of the certificate; for iroh, the node id);
- the SHA-384 pins of both hybrid public keys;
- the application's label, and a label for the role, so a server's proof cannot be replayed as a client's.

A signature counts only if both halves verify. So an attacker who can forge the classical half still cannot produce the
ML-DSA half. A relayed proof fails because the second connection has a different exporter value. Keys are enrolled or pinned
beforehand; a key that merely arrives in a message is never trusted.

I am not claiming the pieces are new. Binding an authentication step to the TLS exporter is an established technique (RFC 5705
and RFC 8446 section 7.5 define exporters, and RFC 9266 defines a channel binding from one). Hybrid and composite signatures are
under discussion in the IETF. The hybrid construction here is my own composition, not one of those specifications, which is
exactly why it needs review.

The cost is size and one extra round trip. A hybrid public key is 2,626 bytes and a proof is 4,693, so each side's frame is 7,320
bytes. A refusal is a single byte.

## The demo

`pqbind demo` runs eight scenarios over real QUIC connections on 127.0.0.1 (and over TLS with `--transport tls`). It exits 0 only
if every scenario behaves as expected. On my machine the summary ended with "All 8 scenarios behaved as expected."

| Scenario | What happens |
|---|---|
| a | An honest pair authenticates. |
| b1 | An attacker holds the server's TLS key and Ed25519 key and forges a proof. The client refuses it. |
| b2 | The same attacker runs the real pqbind code with its own key. The client is refused. |
| c | An attacker holds an enrolled client's Ed25519 key. The server refuses it. |
| d | A man in the middle copies frames between two connections. Both ends are refused. |
| e | A valid key that was never enrolled is refused, with the same one-byte answer as every other refusal. |
| f1, f2 | The whole private key is stolen, on the client side or the server side. The attacker is accepted. |

The last two are the honest limit. If someone holds both halves of a key, they are that peer, and no signature scheme changes
that. The demo includes them on purpose, and it counts them as passing only because the attacker is accepted.

## What it does not do

- It does not enroll anyone. How a key becomes enrolled or pinned (a QR code, an admin, a ticket) is outside the guarantee. If the
  pin reached you over a channel an attacker controlled, nothing here helps.
- It does not provide confidentiality. That is the transport's key exchange, which is assumed to be post-quantum.
- It needs pqbind at both ends, so it does not work for browsers or ordinary TLS clients, and it refuses TLS 1.2.
- It does not protect data sent before the handshake returns, and it has no rate limiting: a server verifies a well-formed first
  message before it knows the sender is enrolled.
- It is not FIPS validated and makes no compliance claim.

## What is still unreviewed

Everything above is tested but not reviewed. The tests include NIST ACVP known answers for ML-DSA-87, attack tests with a
positive control for each forging helper, hostile-input tests and real connections on loopback. That shows the code does what I
meant. It does not show that what I meant is sound.

The open questions are specific. Is signing one label-and-hash message with both halves a safe composition? Is it safe to derive
the ML-DSA seed from the Ed25519 seed with HKDF? Are the pins in the transcript the right choice? Does the uniform refusal leak
anything through timing or size? Is the exporter used correctly for QUIC? The ML-DSA half rests on the RustCrypto `ml-dsa` crate at
version 0.1, which says it has never been independently audited. [REVIEW.md](REVIEW.md) lists these questions with the code to read.

Until someone outside the project has answered them, treat pqbind as a research prototype, not as protection for anything you
cannot afford to lose. Reports go through [SECURITY.md](../SECURITY.md).
