# Design

This describes what the code does. Where something is a design choice that has not been reviewed, it says so.

## The hybrid signature (`pqbind-crypto`)

- A hybrid key is made from **one 32-byte seed**. The seed is the Ed25519 seed, and the ML-DSA-87 seed is HKDF-SHA384 of it (an
  empty salt, the `info` string `pqbind/hybrid-signature/ml-dsa-87-seed/v1`, 32 bytes out). Recovering the Ed25519 scalar from its
  public key does not give the seed, so breaking Ed25519 reveals nothing about the ML-DSA half.
- Both halves sign the same bytes: the domain label `pqbind/hybrid-signature/ed25519+ml-dsa-87/v1` and a zero byte, followed by the
  SHA-512 digest of the message. The label stops a half being lifted out and passed off as a plain Ed25519 or ML-DSA signature, and a
  plain signature being passed off as a half.
- **Both halves must verify.** Verification evaluates both halves whatever the first one answered.
- Public keys and signatures start with a two-byte suite identifier, so a value only opens under the suite it names, which stops a
  downgrade. There is one suite, and no classical-only suite exists.
- ML-DSA-87 is the RustCrypto `ml-dsa` 0.1 crate (never independently audited), signing in its deterministic variant with an empty
  context string (pure ML-DSA over the label and digest above, not HashML-DSA). A public key
  whose `t1` is all zero is refused, because such a key is forgeable whatever its `rho`.
- This composition is a custom construction, not an IETF composite-signature pairing. Independent review is the open item.

## The proof

After the transport handshake, each peer reads a 64-byte exporter value from the connection (label `EXPORTER-pqbind-v1`, with the
application label as the context) and signs:

```text
role label | u8 length, application label | u16 length, client id | u16 length, server id
           | client pin (48) | server pin (48) | exporter value (64)
```

The role labels are `pqbind/proof/client/v1` and `pqbind/proof/server/v1` (each ending in a zero byte).

- The two roles use different labels, so a server's proof is never a client's proof.
- Both transport identities are inside, always in client-then-server order and length-prefixed, so a proof holds for one pair of
  peers and the boundary between two identities cannot be moved.
- **Both keys' pins are inside.** A client that holds the wrong pin therefore produces a proof the real server refuses, so the real
  server never proves itself to a client that pinned something else. An attacker who presents its own key instead is caught by the
  client's own pin check.
- The exporter value is unique to one session, so a proof made on another connection does not verify.
- A transport that is not TLS 1.3 or QUIC is refused: a TLS 1.2 exporter is not bound to the whole handshake.

## The handshake

```text
client -> server   HELLO         0x01 | client public key (2626) | client proof (4693)      = 7320 bytes
server -> client   SERVER_PROOF  0x02 | server public key (2626) | server proof (4693)     = 7320 bytes   (or)
server -> client   REFUSED       0x03
```

- The server accepts a client only if the proof verifies **and** the key is enrolled for that transport identity. Once the HELLO has
  the right length and tag and carries a key that parses, it runs both checks whatever the first one answered, so timing does not
  tell an unknown key from a bad proof. A HELLO of the wrong length or tag, or with a key that does not parse, is refused earlier,
  before either check runs. Every refusal is the same single `REFUSED` frame. A server learns locally whether a frame was malformed or refused,
  and the peer does not.
- The server proves itself only after the client passed.
- The client accepts a server only if the key it sends has the pin the client holds **and** the proof verifies. It stops before
  sending any application data otherwise.
- Keys in these frames are never trusted because they were sent. Trust comes from the enrolled registry and the pin.
- Frames are a four-byte length and the bytes, at most 16 KiB, with a time limit on every step (30 seconds by default).
- A server verifies the ML-DSA-87 half of a well-formed HELLO before it knows the sender is enrolled, so an unauthenticated peer can
  make it do that work. pqbind has no rate limit or connection cap; the application must supply one.

## Trust

- A server keeps the full enrolled public keys of its clients, each with the transport identity it was enrolled from, in a
  `ClientRegistry` the application supplies (a `MemoryRegistry` is included, with a strict encoded form that refuses a list that is
  cut, extended, of another version or too large; a list that does not decode is an error, never an empty list).
- A client keeps a SHA-384 **pin** of the server's whole hybrid public key, small enough for a QR code. The server sends its full key in
  the connection, and the client checks it against the pin.
- The pin covers the entire key, including the ML-DSA half. A transport identity that only authenticates the Ed25519 half would
  leave the ML-DSA half unbound.
- Public keys must be in their canonical encoding, so one key always has one pin.

## Transports

Each adapter does two things: read the exporter value (through `Binding::derive`, which passes the label and context so an adapter
cannot get them wrong) and carry frames over a stream. quinn and iroh open or accept one bidirectional stream; the rustls adapter splits
a finished TLS 1.3 stream. The transport identity of a TLS peer is the SHA-384 of its leaf certificate; of an iroh peer, its node ID.

## Open questions

- Whether to move to an IETF composite-signature pairing if a suitable one exists for Ed25519 with ML-DSA-87.
- How key rotation should work: a new key signed by the old hybrid key would keep the chain post-quantum.
- Independent review of the construction and of the `ml-dsa` crate it rests on.
