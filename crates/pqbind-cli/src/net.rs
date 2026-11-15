// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Build the QUIC and TLS 1.3 endpoints the commands use, and give the pqbind frames of either transport one type.
//!
//! A [`Raw`] is a finished transport connection. `client_frames` or `server_frames` turn it into a [`Link`]: the pqbind frames, the
//! transport identity of the other end and a [`Hold`] that keeps the connection open until the caller is done with it.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use pqbind::adapters::quinn as pq_quinn;
use pqbind::adapters::rustls as pq_rustls;
use pqbind::{Binding, Error, FrameError, FrameIo, PeerId, StreamFrames};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Connection, Endpoint, Incoming, RecvStream, SendStream, ServerConfig};
use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

use crate::cert::Tls;
use crate::common::{CliError, CliResult, Transport, fail};

/// How long one step of connecting may take.
const STEP: Duration = Duration::from_secs(15);

type TlsIo = TlsStream<TcpStream>;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn server_tls_config(tls: &Tls) -> CliResult<rustls::ServerConfig> {
    rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(fail("TLS 1.3 setup"))?
        .with_no_client_auth()
        .with_single_cert(vec![tls.certificate()], tls.private_key())
        .map_err(fail("the server certificate"))
}

fn client_tls_config(roots: RootCertStore) -> CliResult<rustls::ClientConfig> {
    Ok(rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(fail("TLS 1.3 setup"))?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// A QUIC server endpoint listening on `listen`.
pub fn quic_server_endpoint(tls: &Tls, listen: SocketAddr) -> CliResult<Endpoint> {
    let crypto = QuicServerConfig::try_from(server_tls_config(tls)?).map_err(fail("QUIC server setup"))?;
    Endpoint::server(ServerConfig::with_crypto(Arc::new(crypto)), listen).map_err(fail("cannot listen"))
}

/// A QUIC client endpoint bound to `bind` that trusts `roots`.
pub fn quic_client_endpoint(roots: RootCertStore, bind: SocketAddr) -> CliResult<Endpoint> {
    let crypto = QuicClientConfig::try_from(client_tls_config(roots)?).map_err(fail("QUIC client setup"))?;
    let mut endpoint = Endpoint::client(bind).map_err(fail("cannot open a client socket"))?;
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(crypto)));
    Ok(endpoint)
}

fn tls_acceptor(tls: &Tls) -> CliResult<TlsAcceptor> {
    Ok(TlsAcceptor::from(Arc::new(server_tls_config(tls)?)))
}

fn tls_connector(roots: RootCertStore) -> CliResult<TlsConnector> {
    Ok(TlsConnector::from(Arc::new(client_tls_config(roots)?)))
}

/// The local address a client socket binds to for a connection to `remote`: loopback for a loopback target (so no firewall prompt is
/// triggered), the unspecified address of the same family otherwise.
pub fn client_bind_for(remote: SocketAddr) -> SocketAddr {
    let ip = match (remote.ip().to_canonical(), remote.ip().to_canonical().is_loopback()) {
        (IpAddr::V4(_), true) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        (IpAddr::V4(_), false) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        (IpAddr::V6(_), true) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        (IpAddr::V6(_), false) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    SocketAddr::new(ip, 0)
}

/// The pqbind frames of either transport, as one type.
pub enum AnyFrames {
    /// Frames over a QUIC bidirectional stream.
    Quic(StreamFrames<RecvStream, SendStream>),
    /// Frames over a TLS 1.3 stream.
    Tls(StreamFrames<ReadHalf<TlsIo>, WriteHalf<TlsIo>>),
}

impl FrameIo for AnyFrames {
    fn binding(&self) -> &Binding {
        match self {
            Self::Quic(frames) => frames.binding(),
            Self::Tls(frames) => frames.binding(),
        }
    }

    async fn send(&mut self, frame: &[u8]) -> Result<(), FrameError> {
        match self {
            Self::Quic(frames) => frames.send(frame).await,
            Self::Tls(frames) => frames.send(frame).await,
        }
    }

    async fn recv(&mut self) -> Result<Vec<u8>, FrameError> {
        match self {
            Self::Quic(frames) => frames.recv().await,
            Self::Tls(frames) => frames.recv().await,
        }
    }
}

impl AnyFrames {
    /// Give the streams back, for application data after the handshake.
    pub fn into_streams(self) -> Streams {
        match self {
            Self::Quic(frames) => {
                let (recv, send) = frames.into_parts();
                Streams::Quic(recv, send)
            }
            Self::Tls(frames) => {
                let (read, write) = frames.into_parts();
                Streams::Tls(read, write)
            }
        }
    }
}

/// The two halves of a stream after the handshake, for one short line of application data each way.
pub enum Streams {
    /// A QUIC stream.
    Quic(RecvStream, SendStream),
    /// A TLS stream.
    Tls(ReadHalf<TlsIo>, WriteHalf<TlsIo>),
}

impl Streams {
    /// Send `text` and a newline.
    pub async fn send_line(&mut self, text: &str) -> io::Result<()> {
        let mut line = text.to_owned();
        line.push('\n');
        match self {
            Self::Quic(_, send) => send.write_all(line.as_bytes()).await.map_err(io::Error::other),
            Self::Tls(_, write) => {
                write.write_all(line.as_bytes()).await?;
                write.flush().await
            }
        }
    }

    /// Say nothing more: finish a QUIC stream, or shut down the write side of a TLS stream (which sends close_notify).
    pub async fn finish(&mut self) {
        match self {
            Self::Quic(_, send) => {
                let _ = send.finish();
            }
            Self::Tls(_, write) => {
                let _ = write.shutdown().await;
            }
        }
    }

    /// Read one line of at most `limit` bytes, waiting at most `wait`.
    pub async fn read_line(&mut self, limit: usize, wait: Duration) -> io::Result<String> {
        match self {
            Self::Quic(recv, _) => read_line_from(recv, limit, wait).await,
            Self::Tls(read, _) => read_line_from(read, limit, wait).await,
        }
    }
}

async fn read_line_from<R: AsyncRead + Unpin>(reader: &mut R, limit: usize, wait: Duration) -> io::Result<String> {
    let mut bytes = Vec::new();
    let read = async {
        loop {
            match reader.read_u8().await {
                Ok(b'\n') => return Ok(()),
                Ok(byte) => {
                    if bytes.len() >= limit {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "the line is too long"));
                    }
                    bytes.push(byte);
                }
                // A peer that ends the stream without a newline has still said what it said.
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof && !bytes.is_empty() => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    };
    tokio::time::timeout(wait, read).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "timed out waiting for the line"))??;
    String::from_utf8(bytes).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the line is not text"))
}

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
    /// A TLS 1.3 connection.
    Tls(TlsIo),
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
            Self::Tls(stream) => {
                let frames = pq_rustls::frames(stream, label)?;
                Ok(Link { frames: AnyFrames::Tls(frames), peer, hold: Hold::Tls })
            }
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
            Self::Tls(stream) => {
                let frames = pq_rustls::frames(stream, label)?;
                Ok(Link { frames: AnyFrames::Tls(frames), peer, hold: Hold::Tls })
            }
        }
    }
}

/// One real connection on 127.0.0.1 between a client that trusts `tls` and a server that holds it: `(client end, server end)`.
pub async fn loopback_pair(transport: Transport, tls: &Tls) -> CliResult<(Raw, Raw)> {
    let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let timed_out = || CliError::new("timed out opening a loopback connection");
    match transport {
        Transport::Quic => {
            let server = quic_server_endpoint(tls, loopback)?;
            let addr = server.local_addr().map_err(fail("local address"))?;
            let client = quic_client_endpoint(tls.roots()?, loopback)?;
            let connecting = client.connect(addr, "localhost").map_err(fail("QUIC connect"))?;
            let dial = async { connecting.await.map_err(fail("QUIC connect")) };
            let accept = async {
                match server.accept().await {
                    Some(incoming) => incoming.await.map_err(fail("QUIC accept")),
                    None => Err(CliError::new("the QUIC server endpoint closed")),
                }
            };
            let (client_conn, server_conn) =
                tokio::time::timeout(STEP, async { tokio::join!(dial, accept) }).await.map_err(|_| timed_out())?;
            Ok((Raw::Quic { conn: client_conn?, endpoints: vec![client] }, Raw::Quic { conn: server_conn?, endpoints: vec![server] }))
        }
        Transport::Tls => {
            let listener = TcpListener::bind(loopback).await.map_err(fail("cannot listen"))?;
            let addr = listener.local_addr().map_err(fail("local address"))?;
            let acceptor = tls_acceptor(tls)?;
            let connector = tls_connector(tls.roots()?)?;
            let name = ServerName::try_from("localhost").map_err(fail("server name"))?;
            let dial = async {
                let tcp = TcpStream::connect(addr).await.map_err(fail("TCP connect"))?;
                connector.connect(name, tcp).await.map_err(fail("TLS connect"))
            };
            let accept = async {
                let (tcp, _) = listener.accept().await.map_err(fail("TCP accept"))?;
                acceptor.accept(tcp).await.map_err(fail("TLS accept"))
            };
            let (client_stream, server_stream) =
                tokio::time::timeout(STEP, async { tokio::join!(dial, accept) }).await.map_err(|_| timed_out())?;
            Ok((Raw::Tls(client_stream?.into()), Raw::Tls(server_stream?.into())))
        }
    }
}

/// Connect to a server at `remote` and finish the transport handshake, trusting `roots` and checking the certificate against `server_name`.
pub async fn dial(transport: Transport, remote: SocketAddr, server_name: &str, roots: RootCertStore) -> CliResult<Raw> {
    let attempt = async {
        match transport {
            Transport::Quic => {
                let endpoint = quic_client_endpoint(roots, client_bind_for(remote))?;
                let conn = endpoint.connect(remote, server_name).map_err(fail("QUIC connect"))?.await.map_err(fail("QUIC connect"))?;
                Ok(Raw::Quic { conn, endpoints: vec![endpoint] })
            }
            Transport::Tls => {
                let tcp = TcpStream::connect(remote).await.map_err(fail("TCP connect"))?;
                let name = ServerName::try_from(server_name.to_owned()).map_err(fail("server name"))?;
                let stream = tls_connector(roots)?.connect(name, tcp).await.map_err(fail("TLS connect"))?;
                Ok(Raw::Tls(stream.into()))
            }
        }
    };
    tokio::time::timeout(STEP, attempt).await.map_err(|_| CliError::new(format!("timed out connecting to {remote}")))?
}

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
    /// A QUIC connection attempt.
    Quic(Incoming),
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
            Self::Quic(endpoint) => endpoint.accept().await.map(Pending::Quic),
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
                    let conn = incoming.await.map_err(fail("QUIC handshake"))?;
                    Ok(Raw::Quic { conn, endpoints: Vec::new() })
                }
                Self::Tcp(tcp, acceptor) => {
                    let stream = acceptor.accept(tcp).await.map_err(fail("TLS handshake"))?;
                    Ok(Raw::Tls(stream.into()))
                }
            }
        };
        tokio::time::timeout(STEP, work).await.map_err(|_| CliError::new("the transport handshake timed out"))?
    }
}
