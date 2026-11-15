// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Connect pqbind to a transport: read the exporter value and carry frames over its streams.
//!
//! Each adapter sits behind its own Cargo feature, so the core depends on no transport:
//!
//! - `quinn` (feature `quinn`): a QUIC connection from the `quinn` crate.
//! - `rustls` (feature `rustls`): a finished TLS 1.3 stream from `tokio-rustls`. TLS 1.2 is refused.
//! - `iroh` (feature `iroh`): a QUIC connection from the `iroh` crate, identified by its node id.
//!
//! An adapter does two jobs. It reads the connection's exporter value through [`crate::Binding::derive`], and it carries pqbind's
//! frames over one stream as a [`crate::StreamFrames`]. It also names the remote end's transport identity (`peer_id`). The runnable
//! example `quinn_client_server` in this crate shows the quinn adapter end to end.

#[cfg(feature = "iroh")]
pub mod iroh;
#[cfg(feature = "quinn")]
pub mod quinn;
#[cfg(feature = "rustls")]
pub mod rustls;
