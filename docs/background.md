# Your TLS is post-quantum. Your authentication isn't.

Most of the work on preparing the internet for quantum computers has gone into key exchange, for a good reason. An attacker can
record encrypted traffic today and decrypt it later, once a large enough quantum computer exists. The fix is to mix a
post-quantum key exchange into the handshake, and that is happening. The hybrid group X25519MLKEM768 combines classical X25519
with ML-KEM-768 (FIPS 203) and is one of the groups specified in RFC 10024.

You can see it is live. `pqbind probe` offers one key exchange group per handshake and records the answer. On 2026-11-15, from one
network, it reported:

- cloudflare.com accepted X25519MLKEM768 and rejected SecP256r1MLKEM768, SecP384r1MLKEM1024 and pure MLKEM1024.
- google.com accepted X25519MLKEM768 and pure MLKEM1024, and rejected the other two post-quantum groups.

This is a dated observation, and other networks or other days may differ. The probe tests the key exchange only. It does not
validate certificates.

## The gap

Key exchange protects secrecy against a future attacker. Authentication is a different problem, because the party you are talking
to is checked now. If the signatures that authenticate a connection are classical, a connection with a perfectly good
post-quantum key exchange can still be impersonated by someone who can forge them: the certificate signature in TLS, or the node
key in a peer-to-peer system such as iroh. The attacker does not need to break the key exchange. They only need to be the other
end.

For a closed system, the gap can be closed without waiting for the wider ecosystem to change. If you control both ends of a
connection, you can add your own authentication step on top of the transport you already have.

## What pqbind does

pqbind adds that step. After the normal TLS 1.3 or QUIC handshake, each peer signs a transcript with a hybrid key made of Ed25519
and ML-DSA-87 (FIPS 204). The transcript contains:

- the connection's TLS exporter value: 64 bytes that both ends derive from the session and that no other session shares;
- both transport identities (for TLS, the hash of the certificate; for iroh, the node ID);
- the SHA-384 pins of both hybrid public keys;
- the application's label, and a label for the role, so a server's proof cannot be replayed as a client's.

A signature counts only if both halves verify, so an attacker who can forge the classical half still cannot produce the ML-DSA
half. A relayed proof fails because the second connection has a different exporter value. Keys are enrolled or pinned
beforehand, and a key that merely arrives in a message is never trusted.

The pieces are standard. A TLS exporter derives keying material from a live session. RFC 5705 defined it for earlier versions of
TLS, and RFC 8446 section 7.5 redefines it for TLS 1.3 on top of HKDF, keeping the same interface. RFC 9266 builds a channel
binding from one, called `tls-exporter`, using the label `EXPORTER-Channel-Binding` and a 32-byte output. pqbind uses its own
label, `EXPORTER-pqbind-v1`, with the application label as the exporter context, and reads 64 bytes. The hybrid construction is
pqbind's own composition, not an IETF composite-signature scheme, which is why it needs review.

The cost is size and one extra round trip. A hybrid public key is 2,626 bytes and a proof is 4,693 bytes, so each side's frame is
7,320 bytes. A refusal is a single byte.

## The demo

`pqbind demo` runs eight scenarios over real QUIC connections on 127.0.0.1, and over TLS 1.3 with `--transport tls`. It exits 0
only if every scenario behaves as expected.

| Scenario | What happens |
|---|---|
| a | An honest pair authenticates. |
| b1 | An attacker holds the server's TLS key and Ed25519 key and forges a proof. The client refuses it. |
| b2 | The same attacker runs the real pqbind code with its own key. The client is refused. |
| c | An attacker holds an enrolled client's Ed25519 key. The server refuses it. |
| d | A man in the middle copies frames between two connections. Both ends are refused. |
| e | A valid key that was never enrolled is refused, with the same one-byte answer as every other refusal. |
| f1, f2 | The whole private key is stolen, on the client side or the server side. The attacker is accepted. |

The last two mark the limit. If someone holds both halves of a key, they are that peer, and no signature scheme changes that. The
demo includes them on purpose and counts them as passing only because the attacker is accepted.

## What it does not do

- It does not decide who to trust. The library enrolls no one, and `pqbind enroll` only records keys whose pin you confirmed. How a
  key reaches you (a QR code, an administrator, a ticket) is outside the guarantee. If the pin reached you over a channel an attacker
  controlled, nothing here helps.
- It does not provide confidentiality. That is the transport's key exchange, and pqbind does not check that the transport
  negotiated a post-quantum one.
- It needs pqbind at both ends, so it does not work for browsers or ordinary TLS clients, and it refuses TLS 1.2.
- It does not protect data sent before the handshake returns, and it has no rate limiting: a server verifies a well-formed first
  message before it knows the sender is enrolled.
- It is not FIPS validated and makes no compliance claim.

## What is still unreviewed

The design has not had an independent review. The tests include NIST ACVP known answers for ML-DSA-87, attack tests, hostile-input
tests and real connections on loopback. They show the code does what is intended. They do not show that the intent is sound.

The open questions are specific. Is signing one label-and-hash message with both halves a safe composition? Is it safe to derive
the ML-DSA seed from the Ed25519 seed with HKDF? Are the pins in the transcript the right choice? Does the uniform refusal leak
anything through timing or size? Is the exporter used correctly for QUIC? The ML-DSA half rests on the RustCrypto `ml-dsa` crate at
version 0.1, which states that it has not been independently audited. [REVIEW.md](REVIEW.md) lists these questions with the code
to read.

Until someone outside the project has answered them, treat pqbind as a research prototype, not as protection for anything you
cannot afford to lose. Reports go through [SECURITY.md](../SECURITY.md).

## References

- RFC 5705, Keying Material Exporters for Transport Layer Security (TLS), March 2010.
- RFC 8446, The Transport Layer Security (TLS) Protocol Version 1.3, section 7.5 (Exporters).
- RFC 9266, Channel Bindings for TLS 1.3, July 2022.
- RFC 10024, Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3.
- FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM), NIST, August 2024.
- FIPS 204, Module-Lattice-Based Digital Signature Standard (ML-DSA), NIST, August 2024.
