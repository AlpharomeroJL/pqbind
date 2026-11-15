// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Run `pqbind verify`: connect to a pqbind server as a client, check its proof against a pinned key and report the result.
//!
//! Exit codes: 0 when the server proved the pinned key and accepted this client, 1 when the server refused this client or could not
//! prove the pinned key, 2 for anything else (bad arguments, no connection, a TLS failure, a malformed reply).

mod report;
mod target;

#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use pqbind::{Error, PeerId, Pin};

use self::report::{Failure, Report};
use self::target::{dial_any, resolve, split_target};
use crate::common::{DEFAULT_APP_LABEL, Transport, label_bytes};
use crate::keyfiles::load_identity;
use crate::transport::{Link, load_roots};

/// How long to wait for the server's greeting line.
const GREETING_WAIT: Duration = Duration::from_secs(10);

/// The longest greeting line read, in bytes.
const GREETING_LIMIT: usize = 512;

/// The longest the whole verification may take.
const VERIFY_LIMIT: Duration = Duration::from_secs(60);

/// The arguments of `pqbind verify`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// The server to connect to, as host:port.
    pub target: String,
    /// The pin of the server's hybrid public key: 96 hex digits, as `serve` and `keygen` print it.
    #[arg(long)]
    pub pin: String,
    /// This client's seed file (from `keygen`). Its public key must be enrolled on the server.
    #[arg(long)]
    pub identity: PathBuf,
    /// A PEM file with the certificate (or CA) the server's TLS certificate must chain to. Required: this build has no built-in web trust roots.
    #[arg(long)]
    pub ca: Option<PathBuf>,
    /// The name to check the TLS certificate against. The default is the host part of the target.
    #[arg(long)]
    pub server_name: Option<String>,
    /// The transport to use.
    #[arg(long, value_enum, default_value_t = Transport::Quic)]
    pub transport: Transport,
    /// The application label both ends must use.
    #[arg(long, default_value = DEFAULT_APP_LABEL)]
    pub app_label: String,
    /// Print one JSON object instead of text.
    #[arg(long)]
    pub json: bool,
}

async fn attempt(args: &Args, report: &mut Report) -> Result<Option<String>, Failure> {
    let pin = Pin::from_hex(args.pin.trim()).map_err(|_| Failure::Other("--pin must be exactly 96 hex digits".to_owned()))?;
    report.expected_server_pin = Some(pin.to_hex());
    let label = label_bytes(&args.app_label)?;
    let Some(ca) = &args.ca else {
        return Err(Failure::Other(
            "--ca is required: this build has no built-in web trust roots, so pass the server's certificate (or its CA) as a PEM file, \
             for example the file `pqbind serve --cert-out` wrote"
                .to_owned(),
        ));
    };
    let identity = load_identity(&args.identity)?;
    report.client_pin = Some(identity.pin().to_hex());
    let roots = load_roots(ca)?;
    let (host, port) = split_target(&args.target)?;
    let server_name = args.server_name.clone().unwrap_or_else(|| host.clone());
    let addrs = resolve(&host, port).await?;

    let raw = dial_any(args.transport, &addrs, &server_name, &roots).await?;
    let link = raw.client_frames(&label).await.map_err(|error| Failure::Other(format!("cannot start the pqbind handshake: {error}")))?;
    let Link { mut frames, peer, hold } = link;
    let result = pqbind::connect(&mut frames, &identity, &PeerId::anonymous(), &peer, &pin).await;
    match result {
        Ok(_) => {
            let mut streams = frames.into_streams();
            let greeting = streams.read_line(GREETING_LIMIT, GREETING_WAIT).await.ok();
            hold.close().await;
            Ok(greeting)
        }
        Err(error) => {
            hold.close().await;
            Err(match error {
                Error::Refused => Failure::Refused,
                Error::ServerIdentity => Failure::ServerIdentity,
                other => Failure::Other(format!("the pqbind handshake failed: {other}")),
            })
        }
    }
}

/// Connect, verify and describe the result. Never prints.
pub async fn execute(args: &Args) -> Report {
    let mut report = Report::begin(&args.target, args.transport);
    match attempt(args, &mut report).await {
        Ok(greeting) => report.succeed(greeting),
        Err(failure) => report.fail(failure),
    }
    report
}

/// Run `pqbind verify`.
pub async fn run(args: Args) -> ExitCode {
    let report = match tokio::time::timeout(VERIFY_LIMIT, execute(&args)).await {
        Ok(report) => report,
        Err(_) => Report::timed_out(&args.target, args.transport),
    };
    if args.json {
        report.print_json();
    } else {
        report.print_text();
    }
    ExitCode::from(report.exit_code)
}
