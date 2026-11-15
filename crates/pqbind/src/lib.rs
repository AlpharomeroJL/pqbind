// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Authenticate the two ends of an existing TLS 1.3 or QUIC connection with hybrid post-quantum signatures bound to that connection.
//!
//! After the normal handshake, both peers read the connection's TLS exporter value and sign it, with both transport identities and both
//! key pins, using an Ed25519 and ML-DSA-87 hybrid key. A peer whose classical authentication was forged still cannot produce the proof.
//!
//! # Use
//!
//! 1. Each end makes a [`HybridIdentity`]. Enrollment happens outside pqbind: the server stores the client's public key in a
//!    [`ClientRegistry`], and the client keeps the [`Pin`] of the server's key.
//! 2. After the transport handshake, an adapter reads a [`Binding`] and gives a [`FrameIo`] over a stream.
//! 3. The client calls [`connect`] and the server calls [`accept`]. Neither sends application data before its call returns `Ok`.
//!
//! # Example
//!
//! The handshake is generic over [`FrameIo`], so this example runs it over an in-memory pipe and needs no transport feature. A real
//! adapter (`adapters::quinn`, `adapters::rustls` or `adapters::iroh`, each behind its own Cargo feature) reads the exporter value from
//! the live connection; here both ends are simply given the same 64 bytes. The runnable example `quinn_client_server` in this crate
//! does the same over a real QUIC connection on 127.0.0.1.
//!
//! ```
//! # fn main() {
//! #     // The lattice signature code keeps large buffers on the stack, so run on a thread with a bigger one.
//! #     std::thread::Builder::new().stack_size(64 * 1024 * 1024).spawn(run).unwrap().join().unwrap();
//! # }
//! # fn run() {
//! #     tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap().block_on(handshake()).unwrap();
//! # }
//! # async fn handshake() -> Result<(), pqbind::Error> {
//! use pqbind::{Binding, Enrollment, HybridIdentity, MemoryRegistry, PeerId, StreamFrames, accept, connect};
//!
//! // Each end makes a hybrid identity.
//! let client = HybridIdentity::generate()?;
//! let server = HybridIdentity::generate()?;
//!
//! // Enrollment happens before any connection, outside pqbind. The server enrolls the client's public key, and the client keeps the
//! // pin (the SHA-384 of the whole public key) of the server. This client presents no transport identity, so it is anonymous.
//! let registry = MemoryRegistry::new();
//! registry.enroll(Enrollment { key: client.public(), peer_id: PeerId::anonymous(), enrolled_at_unix_millis: 0 });
//! let server_pin = server.pin();
//!
//! // The transport. An adapter would hand each end a `StreamFrames` over the connection's stream, with the exporter value it read.
//! let (client_pipe, server_pipe) = tokio::io::duplex(64 * 1024);
//! let exporter = [7_u8; 64];
//! let (client_read, client_write) = tokio::io::split(client_pipe);
//! let (server_read, server_write) = tokio::io::split(server_pipe);
//! let mut client_io = StreamFrames::new(client_read, client_write, Binding::new(b"my-app/v1", exporter)?);
//! let mut server_io = StreamFrames::new(server_read, server_write, Binding::new(b"my-app/v1", exporter)?);
//!
//! // The transport identity of the server, as the transport authenticated it (for TLS, the hash of its certificate).
//! let server_id = PeerId::new(b"the server's transport identity".to_vec())?;
//!
//! // Both ends run their half. Neither may send application data until its call returns `Ok`.
//! let anonymous = PeerId::anonymous();
//! let (from_client, from_server) = tokio::join!(
//!     connect(&mut client_io, &client, &anonymous, &server_id, &server_pin),
//!     accept(&mut server_io, &server, &server_id, &anonymous, &registry),
//! );
//! assert_eq!(from_client?.peer_key(), &server.public()); // the client now knows it talks to the pinned server
//! assert_eq!(from_server?.peer_key(), &client.public()); // the server now knows it talks to an enrolled client
//!
//! // `client_io.into_parts()` and `server_io.into_parts()` give the streams back for application data.
//! # Ok(())
//! # }
//! ```
//!
//! A proof is bound to one connection. If the two ends read different exporter values, which is what a relay between two connections
//! causes, the proof does not verify and both ends are refused:
//!
//! ```
//! # fn main() {
//! #     std::thread::Builder::new().stack_size(64 * 1024 * 1024).spawn(run).unwrap().join().unwrap();
//! # }
//! # fn run() {
//! #     tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap().block_on(relay()).unwrap();
//! # }
//! # async fn relay() -> Result<(), pqbind::Error> {
//! use pqbind::{Binding, Enrollment, Error, HybridIdentity, MemoryRegistry, PeerId, StreamFrames, accept, connect};
//!
//! let (client, server) = (HybridIdentity::generate()?, HybridIdentity::generate()?);
//! let registry = MemoryRegistry::new();
//! registry.enroll(Enrollment { key: client.public(), peer_id: PeerId::anonymous(), enrolled_at_unix_millis: 0 });
//!
//! let (client_pipe, server_pipe) = tokio::io::duplex(64 * 1024);
//! let (client_read, client_write) = tokio::io::split(client_pipe);
//! let (server_read, server_write) = tokio::io::split(server_pipe);
//! // The two ends sit on two different connections, so they read different exporter values.
//! let mut client_io = StreamFrames::new(client_read, client_write, Binding::new(b"my-app/v1", [1_u8; 64])?);
//! let mut server_io = StreamFrames::new(server_read, server_write, Binding::new(b"my-app/v1", [2_u8; 64])?);
//!
//! let (anonymous, server_pin) = (PeerId::anonymous(), server.pin());
//! let (from_client, from_server) = tokio::join!(
//!     connect(&mut client_io, &client, &anonymous, &anonymous, &server_pin),
//!     accept(&mut server_io, &server, &anonymous, &anonymous, &registry),
//! );
//! assert_eq!(from_client.err(), Some(Error::Refused));
//! assert_eq!(from_server.err(), Some(Error::Refused));
//! # Ok(())
//! # }
//! ```
//!
//! # Status
//!
//! Pre-release, and the design has not been independently reviewed. See `THREAT_MODEL.md` and `DESIGN.md` in the repository.

#![deny(missing_docs)]

pub mod adapters;
pub mod binding;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod identity;
pub mod proof;
pub mod trust;

pub use binding::{Binding, EXPORTER_LABEL, EXPORTER_LEN};
pub use error::Error;
pub use frame::{FrameError, FrameIo, MAX_FRAME_LEN, StreamFrames};
pub use handshake::{Established, accept, connect};
pub use identity::{HybridIdentity, PIN_LEN, PeerId, Pin, PublicIdentity};
pub use proof::{Role, Transcript};
pub use trust::{ClientRegistry, Enrollment, MemoryRegistry};
