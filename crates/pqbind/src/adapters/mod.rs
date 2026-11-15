// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Connect pqbind to a transport: read the exporter value and carry frames over its streams.
//!
//! Status: not implemented yet. Each adapter will sit behind its own Cargo feature, so the core never depends on a transport.

#[cfg(feature = "iroh")]
pub mod iroh;
#[cfg(feature = "quinn")]
pub mod quinn;
#[cfg(feature = "rustls")]
pub mod rustls;
