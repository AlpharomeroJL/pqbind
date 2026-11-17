// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Run `pqbind serve`: read the arguments, start the server, print how to reach it and wait until the process is stopped.
//!
//! The server listens on a loopback address unless the user passes `--allow-non-loopback`, so it never opens a port to the network (and
//! never triggers an operating system firewall prompt) by accident.

mod server;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use pqbind::{PeerId, PublicIdentity};

use crate::common::{CliError, CliResult, DEFAULT_APP_LABEL, Transport, label_bytes};
use crate::keyfiles::{Permissions, load_or_create_identity, load_public};
use crate::registry_file::load as load_registry;
use crate::transport::Tls;

pub use self::server::{Config, Log, Server, start};

/// The arguments of `pqbind serve`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// The address to listen on, for example 127.0.0.1:4433. It must be a loopback address unless `--allow-non-loopback` is given.
    #[arg(long)]
    pub listen: String,
    /// The server's seed file. It is created, like `keygen` does, when it does not exist.
    #[arg(long)]
    pub identity: PathBuf,
    /// A client public key file to enroll (from `keygen --public-out`). Repeat the option for more clients. Give this, `--registry`, or both.
    #[arg(long, required_unless_present = "registry")]
    pub enroll: Vec<PathBuf>,
    /// A file of enrolled clients, made and kept with `pqbind enroll`. It is read once, when the server starts.
    #[arg(long)]
    pub registry: Option<PathBuf>,
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
    if let Some(path) = &args.registry {
        enrolled.extend(registry_keys(path)?);
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
    print_banner(&args, &server, created, enrolled_count);
    std::future::pending().await
}

/// The keys in an enrolled-clients file. This server's clients present no transport identity, so a client enrolled from one is refused
/// here with a message, not silently dropped.
fn registry_keys(path: &Path) -> CliResult<Vec<PublicIdentity>> {
    let mut keys = Vec::new();
    for entry in load_registry(path)?.list() {
        if entry.peer_id != PeerId::anonymous() {
            return Err(CliError::new(format!(
                "the registry file {} enrolls a client for a transport identity, which `pqbind serve` does not use; \
                 enroll it with `pqbind enroll add`, which uses the anonymous identity",
                path.display()
            )));
        }
        keys.push(entry.key);
    }
    Ok(keys)
}

/// Say where the server listens, what it holds and how to verify it from another terminal.
fn print_banner(args: &Args, server: &Server, created: Option<Permissions>, enrolled_count: usize) {
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
}

const fn permissions_word(permissions: Permissions) -> &'static str {
    match permissions {
        Permissions::OwnerOnly => "owner-only",
        Permissions::NotSet => "not restricted on this platform",
    }
}

#[cfg(test)]
mod tests {
    use super::{check_loopback, parse_listen, permissions_word};
    use crate::keyfiles::Permissions;

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

    #[test]
    fn the_permissions_words_are_the_ones_the_banner_prints() {
        assert_eq!(permissions_word(Permissions::OwnerOnly), "owner-only");
        assert_eq!(permissions_word(Permissions::NotSet), "not restricted on this platform");
    }
}
