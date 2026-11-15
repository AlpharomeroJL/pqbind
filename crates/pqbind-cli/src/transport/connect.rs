// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Open client connections: to a server at an address, and between two ends on 127.0.0.1 for the demo.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use tokio::net::{TcpListener, TcpStream};

use super::STEP;
use super::cert::Tls;
use super::config::{client_bind_for, quic_client_endpoint, quic_server_endpoint, tls_acceptor, tls_connector};
use super::raw::Raw;
use crate::common::{CliError, CliResult, Transport, fail};

/// One real connection on 127.0.0.1 between a client that trusts `tls` and a server that holds it: `(client end, server end)`.
pub async fn loopback_pair(transport: Transport, tls: &Tls) -> CliResult<(Raw, Raw)> {
    match transport {
        Transport::Quic => quic_loopback_pair(tls).await,
        Transport::Tls => tls_loopback_pair(tls).await,
    }
}

fn loopback() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn timed_out() -> CliError {
    CliError::new("timed out opening a loopback connection")
}

async fn quic_loopback_pair(tls: &Tls) -> CliResult<(Raw, Raw)> {
    let server = quic_server_endpoint(tls, loopback())?;
    let addr = server.local_addr().map_err(fail("local address"))?;
    let client = quic_client_endpoint(tls.roots()?, loopback())?;
    let connecting = client.connect(addr, "localhost").map_err(fail("QUIC connect"))?;
    let dial = async { connecting.await.map_err(fail("QUIC connect")) };
    let accept = async {
        match server.accept().await {
            Some(incoming) => incoming.await.map_err(fail("QUIC accept")),
            None => Err(CliError::new("the QUIC server endpoint closed")),
        }
    };
    let (client_conn, server_conn) = tokio::time::timeout(STEP, async { tokio::join!(dial, accept) }).await.map_err(|_| timed_out())?;
    Ok((Raw::Quic { conn: client_conn?, endpoints: vec![client] }, Raw::Quic { conn: server_conn?, endpoints: vec![server] }))
}

async fn tls_loopback_pair(tls: &Tls) -> CliResult<(Raw, Raw)> {
    let listener = TcpListener::bind(loopback()).await.map_err(fail("cannot listen"))?;
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
    let (client_stream, server_stream) = tokio::time::timeout(STEP, async { tokio::join!(dial, accept) }).await.map_err(|_| timed_out())?;
    Ok((Raw::Tls(Box::new(client_stream?.into())), Raw::Tls(Box::new(server_stream?.into()))))
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
                Ok(Raw::Tls(Box::new(stream.into())))
            }
        }
    };
    tokio::time::timeout(STEP, attempt).await.map_err(|_| CliError::new(format!("timed out connecting to {remote}")))?
}
