// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Run `pqbind verify`: connect to a pqbind server as a client, check its proof against a pinned key and report the result.
//!
//! Exit codes: 0 when the server proved the pinned key and accepted this client, 1 when the server refused this client or could not
//! prove the pinned key, 2 for anything else (bad arguments, no connection, a TLS failure, a malformed reply).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use pqbind::{Error, PeerId, Pin};
use rustls::RootCertStore;
use serde::Serialize;

use crate::cert::load_roots;
use crate::common::{CliError, CliResult, DEFAULT_APP_LABEL, Transport, label_bytes};
use crate::keygen::load_identity;
use crate::net::{Link, Raw, dial};

/// How long to wait for the server's greeting line.
const GREETING_WAIT: Duration = Duration::from_secs(10);

/// The longest greeting line read, in bytes.
const GREETING_LIMIT: usize = 512;

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

/// The result of one verification, as `--json` prints it.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// `verified`, `refused`, `server_identity` or `error`.
    pub result: &'static str,
    /// Whether the server proved the pinned key and accepted this client.
    pub verified: bool,
    /// The process exit code.
    pub exit_code: u8,
    /// The target as given.
    pub target: String,
    /// `quic` or `tls`.
    pub transport: &'static str,
    /// The pin the server had to prove (96 hex digits), when it could be read.
    pub expected_server_pin: Option<String>,
    /// The pin of this client's key (96 hex digits), when the identity could be read.
    pub client_pin: Option<String>,
    /// The line the server sent after it authenticated this client.
    pub greeting: Option<String>,
    /// One sentence that says what happened.
    pub detail: String,
}

/// Why a verification did not succeed.
enum Failure {
    Refused,
    ServerIdentity,
    Other(String),
}

impl From<CliError> for Failure {
    fn from(error: CliError) -> Self {
        Self::Other(error.to_string())
    }
}

/// Split `host:port` (also `[::1]:4433` and `1.2.3.4:5`) into the host and the port.
pub fn split_target(text: &str) -> CliResult<(String, u16)> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    let bad = || CliError::new(format!("the target must be host:port, for example 127.0.0.1:4433, not {text:?}"));
    let (host, port) = text.rsplit_once(':').ok_or_else(bad)?;
    let host = host.trim_matches(['[', ']']);
    if host.is_empty() {
        return Err(bad());
    }
    Ok((host.to_owned(), port.parse::<u16>().map_err(|_| bad())?))
}

/// Every address `host` resolves to, in the order the resolver gave them.
async fn resolve(host: &str, port: u16) -> CliResult<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| CliError::new(format!("cannot resolve {host}: {error}")))?
        .map(|addr| SocketAddr::new(addr.ip().to_canonical(), addr.port()))
        .collect();
    if addrs.is_empty() {
        return Err(CliError::new(format!("{host} has no address")));
    }
    Ok(addrs)
}

/// Connect to the first address that answers (a name such as `localhost` may resolve to an IPv6 address nothing listens on).
async fn dial_any(transport: Transport, addrs: &[SocketAddr], server_name: &str, roots: &RootCertStore) -> CliResult<Raw> {
    let mut last = CliError::new("no address to connect to");
    for remote in addrs {
        match dial(transport, *remote, server_name, roots.clone()).await {
            Ok(raw) => return Ok(raw),
            Err(error) => last = error,
        }
    }
    Err(last)
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
        Err(Error::Refused) => {
            hold.close().await;
            Err(Failure::Refused)
        }
        Err(Error::ServerIdentity) => {
            hold.close().await;
            Err(Failure::ServerIdentity)
        }
        Err(error) => {
            hold.close().await;
            Err(Failure::Other(format!("the pqbind handshake failed: {error}")))
        }
    }
}

/// Connect, verify and describe the result. Never prints.
pub async fn execute(args: &Args) -> Report {
    let mut report = Report {
        result: "error",
        verified: false,
        exit_code: 2,
        target: args.target.clone(),
        transport: args.transport.name(),
        expected_server_pin: None,
        client_pin: None,
        greeting: None,
        detail: String::new(),
    };
    match attempt(args, &mut report).await {
        Ok(greeting) => {
            report.result = "verified";
            report.verified = true;
            report.exit_code = 0;
            report.detail = "the server proved the pinned key and accepted this client".to_owned();
            report.greeting = greeting;
        }
        Err(Failure::Refused) => {
            report.result = "refused";
            report.exit_code = 1;
            report.detail = "the server refused this connection: this client is not enrolled there, or the pin is not that server's pin, or the proof did not verify".to_owned();
        }
        Err(Failure::ServerIdentity) => {
            report.result = "server_identity";
            report.exit_code = 1;
            report.detail = "the server could not prove it holds the pinned key".to_owned();
        }
        Err(Failure::Other(message)) => {
            report.detail = message;
        }
    }
    report
}

fn print_text(report: &Report) {
    println!("pqbind verify {} ({})", report.target, report.transport);
    if let Some(pin) = &report.expected_server_pin {
        println!("  pinned server key: {}...", short_hex(pin));
    }
    if let Some(pin) = &report.client_pin {
        println!("  this client:       {}...", short_hex(pin));
    }
    match report.result {
        "verified" => {
            println!("  result:            VERIFIED, {}", report.detail);
            match &report.greeting {
                Some(greeting) => println!("  server says:       {greeting}"),
                None => println!("  server says:       (no greeting line arrived)"),
            }
        }
        "refused" => println!("  result:            REFUSED, {}", report.detail),
        "server_identity" => println!("  result:            SERVER IDENTITY FAILED, {}", report.detail),
        _ => eprintln!("pqbind verify: {}", report.detail),
    }
}

fn short_hex(hex: &str) -> String {
    hex.chars().take(16).collect()
}

/// Run `pqbind verify`.
pub async fn run(args: Args) -> ExitCode {
    let report = match tokio::time::timeout(Duration::from_secs(60), execute(&args)).await {
        Ok(report) => report,
        Err(_) => timed_out_report(&args),
    };
    if args.json {
        match serde_json::to_string(&report) {
            Ok(text) => println!("{text}"),
            Err(error) => eprintln!("pqbind verify: cannot write the JSON report: {error}"),
        }
    } else {
        print_text(&report);
    }
    ExitCode::from(report.exit_code)
}

fn timed_out_report(args: &Args) -> Report {
    Report {
        result: "error",
        verified: false,
        exit_code: 2,
        target: args.target.clone(),
        transport: args.transport.name(),
        expected_server_pin: None,
        client_pin: None,
        greeting: None,
        detail: "timed out after 60 seconds".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use super::{Args, execute, split_target};
    use crate::cert::Tls;
    use crate::common::{DEFAULT_APP_LABEL, Transport, label_bytes};
    use crate::keygen::{Args as KeygenArgs, generate, load_public};
    use crate::serve::{Config, Log, Server, start};
    use crate::testutil::TempDir;

    /// A client identity on disk.
    struct Client {
        seed: PathBuf,
        public: PathBuf,
    }

    fn client(dir: &Path, name: &str) -> Client {
        let seed = dir.join(format!("{name}.seed"));
        let public = dir.join(format!("{name}.pub"));
        generate(&KeygenArgs { out: seed.clone(), public_out: Some(public.clone()) }).expect("keygen");
        Client { seed, public }
    }

    /// A running server on loopback port 0 that enrolls these clients, with its certificate written to `dir/ca.pem`.
    async fn server(transport: Transport, dir: &Path, enrolled: &[&Client]) -> (Server, PathBuf, Arc<Mutex<Vec<String>>>) {
        let identity = crate::keygen::create_identity(&dir.join(format!("server-{}.seed", transport.name()))).expect("identity").0;
        let tls = Tls::generate().expect("certificate");
        let ca = dir.join(format!("ca-{}.pem", transport.name()));
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&lines);
        let log: Log = Arc::new(move |line| sink.lock().expect("log lock").push(line));
        let config = Config {
            transport,
            listen: "127.0.0.1:0".parse().expect("address"),
            identity,
            enrolled: enrolled.iter().map(|c| load_public(&c.public).expect("public key")).collect(),
            tls,
            app_label: label_bytes(DEFAULT_APP_LABEL).expect("label"),
        };
        let server = start(config, log).await.expect("server");
        std::fs::write(&ca, server.cert_pem()).expect("write the certificate");
        assert!(server.addr().ip().is_loopback(), "the test server is bound to loopback only");
        (server, ca, lines)
    }

    fn args(server: &Server, client: &Client, ca: Option<&Path>, transport: Transport, pin: Option<String>) -> Args {
        Args {
            target: server.addr().to_string(),
            pin: pin.unwrap_or_else(|| server.pin().to_hex()),
            identity: client.seed.clone(),
            ca: ca.map(Path::to_path_buf),
            server_name: None,
            transport,
            app_label: DEFAULT_APP_LABEL.to_owned(),
            json: true,
        }
    }

    async fn right_pin_verifies_and_failures_exit_as_specified(transport: Transport) {
        let dir = TempDir::new(&format!("verify-{}", transport.name()));
        let enrolled = client(dir.path(), "enrolled");
        let stranger = client(dir.path(), "stranger");
        let (server, ca, lines) = server(transport, dir.path(), &[&enrolled]).await;

        // The right pin and an enrolled client: verified, with the greeting.
        let report = execute(&args(&server, &enrolled, Some(&ca), transport, None)).await;
        assert_eq!((report.result, report.exit_code, report.verified), ("verified", 0, true), "{report:?}");
        let greeting = report.greeting.clone().expect("a greeting");
        assert!(greeting.starts_with("pqbind: authenticated "), "{greeting}");
        assert_eq!(greeting.len(), "pqbind: authenticated ".len() + 16, "the short client pin");
        assert_eq!(report.expected_server_pin.as_deref(), Some(server.pin().to_hex().as_str()));
        assert_eq!(report.client_pin.as_deref().map(|pin| &pin[..16]), Some(&greeting["pqbind: authenticated ".len()..]));

        // A name that resolves to ::1 before 127.0.0.1 still reaches the IPv4 loopback server (the first address that answers wins).
        let mut by_name = args(&server, &enrolled, Some(&ca), transport, None);
        by_name.target = format!("localhost:{}", server.addr().port());
        let report = execute(&by_name).await;
        assert_eq!((report.result, report.exit_code), ("verified", 0), "{report:?}");

        // The JSON form is one object that names the result.
        let json = serde_json::to_string(&report).expect("json");
        assert!(json.starts_with('{') && json.ends_with('}') && !json.contains('\n'), "{json}");
        assert!(json.contains("\"result\":\"verified\"") && json.contains("\"exit_code\":0"), "{json}");

        // A wrong pin: the client signs the wrong server key, so the real server refuses it. Exit 1.
        let wrong = "ab".repeat(48);
        let report = execute(&args(&server, &enrolled, Some(&ca), transport, Some(wrong))).await;
        assert_eq!((report.result, report.exit_code, report.verified), ("refused", 1, false), "{report:?}");

        // A client that is not enrolled: refused. Exit 1.
        let report = execute(&args(&server, &stranger, Some(&ca), transport, None)).await;
        assert_eq!((report.result, report.exit_code, report.verified), ("refused", 1, false), "{report:?}");

        // No CA: exit 2, and the message names the option.
        let report = execute(&args(&server, &enrolled, None, transport, None)).await;
        assert_eq!((report.result, report.exit_code), ("error", 2), "{report:?}");
        assert!(report.detail.contains("--ca"), "{}", report.detail);

        // A CA file that does not exist, a bad pin and a bad target are also exit 2.
        let report = execute(&args(&server, &enrolled, Some(&dir.path().join("missing.pem")), transport, None)).await;
        assert_eq!(report.exit_code, 2, "{report:?}");
        let report = execute(&args(&server, &enrolled, Some(&ca), transport, Some("not a pin".to_owned()))).await;
        assert_eq!(report.exit_code, 2, "{report:?}");
        let mut bad_target = args(&server, &enrolled, Some(&ca), transport, None);
        bad_target.target = "no-port".to_owned();
        assert_eq!(execute(&bad_target).await.exit_code, 2);

        // A certificate the client does not trust: the transport handshake fails, exit 2, before pqbind starts.
        let other_ca = dir.path().join("other-ca.pem");
        std::fs::write(&other_ca, Tls::generate().expect("certificate").pem()).expect("write");
        let report = execute(&args(&server, &enrolled, Some(&other_ca), transport, None)).await;
        assert_eq!((report.result, report.exit_code), ("error", 2), "{report:?}");

        // The server's log names the authenticated clients and the refusals, and nothing secret.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let lines = lines.lock().expect("log lock").clone();
        assert_eq!(lines.iter().filter(|line| line.contains("authenticated client")).count(), 2, "the two successful verifies: {lines:?}");
        assert!(lines.iter().filter(|line| line.contains("refused")).count() >= 2, "{lines:?}");
        server.shutdown();
    }

    #[tokio::test]
    async fn over_quic_the_right_pin_verifies_and_failures_exit_as_specified() {
        right_pin_verifies_and_failures_exit_as_specified(Transport::Quic).await;
    }

    #[tokio::test]
    async fn over_tls_the_right_pin_verifies_and_failures_exit_as_specified() {
        right_pin_verifies_and_failures_exit_as_specified(Transport::Tls).await;
    }

    #[test]
    fn a_target_splits_into_host_and_port() {
        assert_eq!(split_target("127.0.0.1:4433").expect("ok"), ("127.0.0.1".to_owned(), 4433));
        assert_eq!(split_target("[::1]:9").expect("ok"), ("::1".to_owned(), 9));
        assert_eq!(split_target("example.test:443").expect("ok"), ("example.test".to_owned(), 443));
        for bad in ["", "example.test", ":80", "host:notaport", "host:99999"] {
            assert!(split_target(bad).is_err(), "{bad:?}");
        }
    }
}
