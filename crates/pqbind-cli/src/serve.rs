// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Run `pqbind serve`: a small pqbind server that authenticates enrolled clients, greets them with one line and closes.
//!
//! The server listens on a loopback address unless the user passes `--allow-non-loopback`, so it never opens a port to the network (and
//! never triggers an operating system firewall prompt) by accident. A client that is refused just gets closed.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use pqbind::{Enrollment, Error, HybridIdentity, MemoryRegistry, PeerId, Pin, PublicIdentity};

use crate::cert::Tls;
use crate::common::{CliError, CliResult, DEFAULT_APP_LABEL, Transport, label_bytes, now_millis, short_pin};
use crate::keygen::{Permissions, load_or_create_identity, load_public};
use crate::net::{Link, Listener, Pending};

/// The longest one connection may take from arrival to close.
const CONNECTION_LIMIT: Duration = Duration::from_secs(60);

/// How long the server waits for the client to close after it was greeted.
const LINGER: Duration = Duration::from_secs(5);

/// The arguments of `pqbind serve`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// The address to listen on, for example 127.0.0.1:4433. It must be a loopback address unless `--allow-non-loopback` is given.
    #[arg(long)]
    pub listen: String,
    /// The server's seed file. It is created, like `keygen` does, when it does not exist.
    #[arg(long)]
    pub identity: PathBuf,
    /// A client public key file to enroll (from `keygen --public-out`). Repeat the option for more clients.
    #[arg(long, required = true)]
    pub enroll: Vec<PathBuf>,
    /// The transport to serve.
    #[arg(long, value_enum, default_value_t = Transport::Quic)]
    pub transport: Transport,
    /// Write the server's self-signed TLS certificate (PEM) here, for clients to pass as `--ca`.
    #[arg(long)]
    pub cert_out: Option<PathBuf>,
    /// The application label both ends must use.
    #[arg(long, default_value = DEFAULT_APP_LABEL)]
    pub app_label: String,
    /// Allow listening on an address that is not loopback (the network can then reach the server).
    #[arg(long)]
    pub allow_non_loopback: bool,
}

/// Read `--listen` and refuse an address that is not loopback unless `allow_non_loopback` is set.
pub fn parse_listen(text: &str, allow_non_loopback: bool) -> CliResult<SocketAddr> {
    let addr: SocketAddr = text
        .parse()
        .map_err(|_| CliError::new(format!("--listen must be an address and port such as 127.0.0.1:4433 (or [::1]:4433), not {text:?}")))?;
    check_loopback(addr, allow_non_loopback)?;
    Ok(addr)
}

/// Refuse a listen address that is not loopback unless `allow_non_loopback` is set.
pub fn check_loopback(addr: SocketAddr, allow_non_loopback: bool) -> CliResult<()> {
    if allow_non_loopback || addr.ip().to_canonical().is_loopback() {
        return Ok(());
    }
    Err(CliError::new(format!(
        "refusing to listen on {addr}: it is not a loopback address (127.0.0.0/8 or ::1), so the network could reach this server. \
         Use a loopback address, or pass --allow-non-loopback if you really mean it."
    )))
}

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
    #[cfg_attr(not(test), allow(dead_code))]
    cert_pem: String,
    #[cfg_attr(not(test), allow(dead_code))]
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

    /// Its TLS certificate as PEM, for a client's `--ca`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Stop accepting connections.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn shutdown(self) {
        self.task.abort();
    }
}

/// Start serving in the background.
pub async fn start(config: Config, log: Log) -> CliResult<Server> {
    let listener = Listener::bind(config.transport, &config.tls, config.listen).await?;
    let addr = listener.local_addr()?;
    let pin = config.identity.pin();
    let cert_pem = config.tls.pem().to_owned();
    let registry = MemoryRegistry::new();
    for key in config.enrolled {
        registry.enroll(Enrollment { key, peer_id: PeerId::anonymous(), enrolled_at_unix_millis: now_millis() });
    }
    let shared = Arc::new(Shared { identity: config.identity, own_id: config.tls.id(), registry, label: config.app_label, log });
    let task = tokio::spawn(async move {
        while let Some(pending) = listener.next().await {
            let shared = Arc::clone(&shared);
            tokio::spawn(async move {
                let _ = tokio::time::timeout(CONNECTION_LIMIT, handle(pending, &shared)).await;
            });
        }
    });
    Ok(Server { addr, pin, cert_pem, task })
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

/// Run `pqbind serve` until the process is stopped.
pub async fn run(args: Args) -> ExitCode {
    match serve(args).await {
        Ok(never) => match never {},
        Err(error) => {
            eprintln!("pqbind serve: {error}");
            ExitCode::from(2)
        }
    }
}

async fn serve(args: Args) -> CliResult<std::convert::Infallible> {
    let listen = parse_listen(&args.listen, args.allow_non_loopback)?;
    let app_label = label_bytes(&args.app_label)?;
    let (identity, created) = load_or_create_identity(&args.identity)?;
    let mut enrolled = Vec::with_capacity(args.enroll.len());
    for path in &args.enroll {
        enrolled.push(load_public(path)?);
    }
    let tls = Tls::generate()?;
    if let Some(path) = &args.cert_out {
        std::fs::write(path, tls.pem())
            .map_err(|error| CliError::new(format!("cannot write the certificate to {}: {error}", path.display())))?;
    }
    let enrolled_count = enrolled.len();
    let config = Config { transport: args.transport, listen, identity, enrolled, tls, app_label };
    let log: Log = Arc::new(|line| println!("  {line}"));
    let server = start(config, log).await?;

    println!("pqbind serve");
    println!("  transport:   {}", args.transport.name());
    println!("  listening:   {}", server.addr());
    println!("  server pin:  {}", server.pin().to_hex());
    match created {
        Some(permissions) => {
            println!("  identity:    created {} (permissions: {})", args.identity.display(), permissions_word(permissions));
        }
        None => println!("  identity:    loaded {}", args.identity.display()),
    }
    println!("  enrolled:    {enrolled_count} client key(s)");
    match &args.cert_out {
        Some(path) => println!("  certificate: written to {} (new on every start)", path.display()),
        None => println!("  certificate: not written; pass --cert-out so a client has a certificate to trust"),
    }
    let ca = args.cert_out.as_ref().map_or_else(|| "<server certificate pem>".to_owned(), |path| path.display().to_string());
    let label = if args.app_label == DEFAULT_APP_LABEL { String::new() } else { format!(" --app-label {}", args.app_label) };
    println!();
    println!("Verify it from another terminal on this machine with:");
    println!(
        "  pqbind verify {} --pin {} --identity <client seed file> --ca {ca} --transport {}{label}",
        server.addr(),
        server.pin().to_hex(),
        args.transport.name()
    );
    println!();
    println!("Waiting for connections. Stop with Ctrl+C.");
    std::future::pending().await
}

const fn permissions_word(permissions: Permissions) -> &'static str {
    match permissions {
        Permissions::OwnerOnly => "owner-only",
        Permissions::NotSet => "not restricted on this platform",
    }
}

#[cfg(test)]
mod tests {
    use super::{check_loopback, parse_listen};

    #[test]
    fn loopback_addresses_are_accepted_without_the_flag() {
        for text in ["127.0.0.1:4433", "127.0.0.1:0", "127.5.6.7:1", "[::1]:4433", "[::ffff:127.0.0.1]:9"] {
            assert!(parse_listen(text, false).is_ok(), "{text}");
        }
    }

    #[test]
    fn a_non_loopback_address_is_refused_without_the_flag_and_accepted_with_it() {
        for text in ["0.0.0.0:4433", "192.168.1.5:4433", "10.0.0.1:1", "[::]:4433", "8.8.8.8:53"] {
            let error = parse_listen(text, false).expect_err(text);
            assert!(error.to_string().contains("--allow-non-loopback"), "{text}: {error}");
            assert!(parse_listen(text, true).is_ok(), "{text} with the flag");
        }
        let addr = "0.0.0.0:1".parse().expect("address");
        assert!(check_loopback(addr, false).is_err());
    }

    #[test]
    fn text_that_is_not_an_address_is_refused() {
        for text in ["localhost:4433", "4433", "127.0.0.1", ""] {
            assert!(parse_listen(text, true).is_err(), "{text:?}");
        }
    }
}
