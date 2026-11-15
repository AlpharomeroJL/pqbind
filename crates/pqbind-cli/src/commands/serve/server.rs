// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Run the pqbind server in the background: accept connections, authenticate enrolled clients, greet them with one line and close.
//!
//! A client that is refused just gets closed. Each connection has a time limit from arrival to close.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pqbind::{Enrollment, Error, HybridIdentity, MemoryRegistry, PeerId, Pin, PublicIdentity};

use crate::common::{CliResult, Transport, now_millis, short_pin};
use crate::transport::{Link, Listener, Pending, Tls};

/// The longest one connection may take from arrival to close.
const CONNECTION_LIMIT: Duration = Duration::from_secs(60);

/// How long the server waits for the client to close after it was greeted.
const LINGER: Duration = Duration::from_secs(5);

/// Everything a server needs to start.
pub struct Config {
    /// The transport to serve.
    pub transport: Transport,
    /// The address to listen on (already checked).
    pub listen: SocketAddr,
    /// The server's hybrid identity.
    pub identity: HybridIdentity,
    /// The clients to enroll, all for the anonymous transport identity.
    pub enrolled: Vec<PublicIdentity>,
    /// The server's TLS certificate and key.
    pub tls: Tls,
    /// The application label.
    pub app_label: Vec<u8>,
}

/// Where a running server writes what happens.
pub type Log = Arc<dyn Fn(String) + Send + Sync>;

struct Shared {
    identity: HybridIdentity,
    own_id: PeerId,
    registry: MemoryRegistry,
    label: Vec<u8>,
    log: Log,
}

/// A running server.
pub struct Server {
    addr: SocketAddr,
    pin: Pin,
    /// The accept loop. The command runs until the process ends, so only the tests stop it.
    #[cfg(test)]
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    /// The address it listens on.
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The pin of its hybrid key.
    pub const fn pin(&self) -> &Pin {
        &self.pin
    }

    /// Stop accepting connections.
    #[cfg(test)]
    pub fn shutdown(self) {
        self.task.abort();
    }
}

/// Start serving in the background.
pub async fn start(config: Config, log: Log) -> CliResult<Server> {
    let listener = Listener::bind(config.transport, &config.tls, config.listen).await?;
    let addr = listener.local_addr()?;
    let pin = config.identity.pin();
    let registry = MemoryRegistry::new();
    for key in config.enrolled {
        registry.enroll(Enrollment { key, peer_id: PeerId::anonymous(), enrolled_at_unix_millis: now_millis() });
    }
    let shared = Arc::new(Shared { identity: config.identity, own_id: config.tls.id(), registry, label: config.app_label, log });
    let task = tokio::spawn(accept_loop(listener, shared));
    #[cfg(not(test))]
    drop(task);
    Ok(Server {
        addr,
        pin,
        #[cfg(test)]
        task,
    })
}

async fn accept_loop(listener: Listener, shared: Arc<Shared>) {
    while let Some(pending) = listener.next().await {
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let _ = tokio::time::timeout(CONNECTION_LIMIT, handle(pending, &shared)).await;
        });
    }
}

async fn handle(pending: Pending, shared: &Shared) {
    let log = |line: String| (shared.log)(line);
    let raw = match pending.complete().await {
        Ok(raw) => raw,
        Err(error) => return log(format!("a connection failed before pqbind started: {error}")),
    };
    let remote = raw.remote_text();
    let link = match raw.server_frames(&shared.label).await {
        Ok(link) => link,
        Err(error) => return log(format!("{remote}: no pqbind handshake started ({error})")),
    };
    let Link { mut frames, peer, hold } = link;
    let result = pqbind::accept(&mut frames, &shared.identity, &shared.own_id, &peer, &shared.registry).await;
    let greeting = match &result {
        Ok(established) => {
            let who = short_pin(&established.peer_key().pin());
            log(format!("{remote}: authenticated client {who}"));
            Some(format!("pqbind: authenticated {who}"))
        }
        Err(Error::Refused) => {
            log(format!("{remote}: refused (the client is not enrolled, or its proof did not verify)"));
            None
        }
        Err(error) => {
            log(format!("{remote}: handshake failed ({error})"));
            None
        }
    };
    let mut streams = frames.into_streams();
    if let Some(line) = greeting {
        let _ = streams.send_line(&line).await;
    }
    streams.finish().await;
    hold.linger(LINGER).await;
}
