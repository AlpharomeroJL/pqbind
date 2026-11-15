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
//! # Status
//!
//! Pre-release, and the design has not been independently reviewed. See `THREAT_MODEL.md` and `DESIGN.md` in the repository.

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
