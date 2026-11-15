// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Hold a finished transport connection and turn it into pqbind frames, a [`Link`], that keep the connection open until dropped or closed.

use std::time::Duration;

use pqbind::adapters::quinn as pq_quinn;
use pqbind::adapters::rustls as pq_rustls;
use pqbind::{Error, PeerId};
use quinn::{Connection, Endpoint};

use super::frames::{AnyFrames, TlsIo};

/// What keeps a connection open while the caller uses its streams.
pub enum Hold {
    /// A QUIC connection and the client endpoints that belong to it.
    Quic {
        /// The connection.
        conn: Connection,
        /// Endpoints that must outlive the connection.
        endpoints: Vec<Endpoint>,
    },
    /// A TLS stream needs nothing besides itself.
    Tls,
}

impl Hold {
    /// Wait up to `wait` for the peer to close (it does once it has what it needs), then close.
    pub async fn linger(self, wait: Duration) {
        if let Self::Quic { conn, .. } = &self {
            let _ = tokio::time::timeout(wait, conn.closed()).await;
            conn.close(0_u32.into(), b"done");
        }
    }

    /// Close now and give the close a moment to leave.
    pub async fn close(self) {
        if let Self::Quic { conn, endpoints } = &self {
            conn.close(0_u32.into(), b"done");
            for endpoint in endpoints {
                let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
            }
        }
    }
}

/// The pqbind frames over one connection, the transport identity of the other end, and what keeps the connection open.
pub struct Link {
    /// The frames, with the connection's exporter value.
    pub frames: AnyFrames,
    /// The transport identity of the other end, as the adapter computes it.
    pub peer: PeerId,
    /// Keeps the connection open.
    pub hold: Hold,
}

/// A finished transport connection that has not carried a pqbind frame yet.
pub enum Raw {
    /// A QUIC connection.
    Quic {
        /// The connection.
        conn: Connection,
        /// Endpoints that must outlive the connection.
        endpoints: Vec<Endpoint>,
    },
    /// A TLS 1.3 connection. Boxed: the stream is far larger than the other variant, and a `Raw` is passed by value through async code.
    Tls(Box<TlsIo>),
}

impl Raw {
    /// The transport identity of the other end.
    pub fn peer(&self) -> PeerId {
        match self {
            Self::Quic { conn, .. } => pq_quinn::peer_id(conn),
            Self::Tls(stream) => pq_rustls::peer_id(stream),
        }
    }

    /// The address of the other end, as text.
    pub fn remote_text(&self) -> String {
        match self {
            Self::Quic { conn, .. } => conn.remote_address().to_string(),
            Self::Tls(stream) => stream.get_ref().0.peer_addr().map_or_else(|_| "an unknown address".to_owned(), |addr| addr.to_string()),
        }
    }

    /// Client side: read the exporter value under `label` and open the stream.
    pub async fn client_frames(self, label: &[u8]) -> Result<Link, Error> {
        let peer = self.peer();
        match self {
            Self::Quic { conn, endpoints } => {
                let frames = pq_quinn::open(&conn, label).await?;
                Ok(Link { frames: AnyFrames::Quic(frames), peer, hold: Hold::Quic { conn, endpoints } })
            }
            Self::Tls(stream) => tls_link(*stream, label, peer),
        }
    }

    /// Server side: read the exporter value under `label` and accept the stream (a QUIC stream appears once the client writes on it).
    pub async fn server_frames(self, label: &[u8]) -> Result<Link, Error> {
        let peer = self.peer();
        match self {
            Self::Quic { conn, endpoints } => {
                let frames = pq_quinn::accept(&conn, label).await?;
                Ok(Link { frames: AnyFrames::Quic(frames), peer, hold: Hold::Quic { conn, endpoints } })
            }
            Self::Tls(stream) => tls_link(*stream, label, peer),
        }
    }
}

/// The link over a TLS stream, which needs no accept step because TLS has one stream per connection.
fn tls_link(stream: TlsIo, label: &[u8], peer: PeerId) -> Result<Link, Error> {
    let frames = pq_rustls::frames(stream, label)?;
    Ok(Link { frames: AnyFrames::Tls(frames), peer, hold: Hold::Tls })
}
