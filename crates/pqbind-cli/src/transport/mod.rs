// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Gather the QUIC and TLS 1.3 transport pieces the commands share behind one small surface.
//!
//! A [`Raw`] is a finished transport connection. `client_frames` or `server_frames` turn it into a [`Link`]: the pqbind frames, the
//! transport identity of the other end and a hold that keeps the connection open until the caller is done with it. The parts:
//!
//! - `cert`: the self-signed certificate and the trust store loader.
//! - `config`: the rustls and quinn configurations and the endpoints built from them.
//! - `frames`: the frames of either transport as one type, and the application data after the handshake.
//! - `raw`: a finished connection, its hold and its link.
//! - `connect`: connecting a client (to a server or to a loopback peer).
//! - `listen`: the server side, a listener and the connections that arrive.

mod cert;
mod config;
mod connect;
mod frames;
mod listen;
mod raw;

pub use cert::{Tls, load_roots};
pub use connect::{dial, loopback_pair};
pub use listen::{Listener, Pending};
pub use raw::{Link, Raw};

use std::time::Duration;

/// How long one step of connecting may take.
const STEP: Duration = Duration::from_secs(15);
