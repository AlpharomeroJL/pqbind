// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Listen for client connections over QUIC or TLS and finish their transport handshakes.

use std::net::SocketAddr;
use std::time::Duration;

use quinn::{Endpoint, Incoming};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use super::STEP;
use super::cert::Tls;
use super::config::{quic_server_endpoint, tls_acceptor};
use super::raw::Raw;
use crate::common::{CliError, CliResult, Transport, fail};

/// A server socket that hands out transport connections.
pub enum Listener {
    /// A QUIC endpoint.
    Quic(Endpoint),
    /// A TCP listener with the TLS acceptor to run on what it accepts.
    Tcp {
        /// The TCP listener.
        listener: TcpListener,
        /// The TLS acceptor.
        acceptor: TlsAcceptor,
    },
}

/// A connection that has arrived and whose transport handshake is not finished.
pub enum Pending {
    /// A QUIC connection attempt, boxed because it is far larger than the TCP variant.
    Quic(Box<Incoming>),
    /// A TCP connection and the TLS acceptor to run on it.
    Tcp(TcpStream, TlsAcceptor),
}

impl Listener {
    /// Listen on `addr` with `tls`.
    pub async fn bind(transport: Transport, tls: &Tls, addr: SocketAddr) -> CliResult<Self> {
        match transport {
            Transport::Quic => Ok(Self::Quic(quic_server_endpoint(tls, addr)?)),
            Transport::Tls => {
                let listener = TcpListener::bind(addr).await.map_err(fail("cannot listen"))?;
                Ok(Self::Tcp { listener, acceptor: tls_acceptor(tls)? })
            }
        }
    }

    /// The address actually bound (useful after binding port 0).
    pub fn local_addr(&self) -> CliResult<SocketAddr> {
        match self {
            Self::Quic(endpoint) => endpoint.local_addr().map_err(fail("local address")),
            Self::Tcp { listener, .. } => listener.local_addr().map_err(fail("local address")),
        }
    }

    /// The next connection, or `None` once the listener is closed.
    pub async fn next(&self) -> Option<Pending> {
        match self {
            Self::Quic(endpoint) => endpoint.accept().await.map(|incoming| Pending::Quic(Box::new(incoming))),
            Self::Tcp { listener, acceptor } => loop {
                match listener.accept().await {
                    Ok((tcp, _)) => return Some(Pending::Tcp(tcp, acceptor.clone())),
                    Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            },
        }
    }
}

impl Pending {
    /// Finish the transport handshake.
    pub async fn complete(self) -> CliResult<Raw> {
        let work = async {
            match self {
                Self::Quic(incoming) => {
                    let conn = (*incoming).await.map_err(fail("QUIC handshake"))?;
                    Ok(Raw::Quic { conn, endpoints: Vec::new() })
                }
                Self::Tcp(tcp, acceptor) => {
                    let stream = acceptor.accept(tcp).await.map_err(fail("TLS handshake"))?;
                    Ok(Raw::Tls(Box::new(stream.into())))
                }
            }
        };
        tokio::time::timeout(STEP, work).await.map_err(|_| CliError::new("the transport handshake timed out"))?
    }
}
