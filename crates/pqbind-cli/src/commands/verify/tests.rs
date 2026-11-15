// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Test `verify` end to end against an in-process server on 127.0.0.1: the verdicts, the exit codes and the JSON form.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::{Args, execute};
use crate::commands::keygen::{Args as KeygenArgs, generate};
use crate::commands::serve::{Config, Log, Server, start};
use crate::common::{DEFAULT_APP_LABEL, Transport, label_bytes};
use crate::keyfiles::{create_identity, load_public};
use crate::testutil::TempDir;
use crate::transport::Tls;

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
    let identity = create_identity(&dir.join(format!("server-{}.seed", transport.name()))).expect("identity").0;
    let tls = Tls::generate().expect("certificate");
    let ca = dir.join(format!("ca-{}.pem", transport.name()));
    std::fs::write(&ca, tls.pem()).expect("write the certificate");
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
