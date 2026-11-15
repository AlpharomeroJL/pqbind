// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Test the probe end to end against in-process servers on 127.0.0.1 (never a real host), and its arguments and exit codes.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use rustls::ServerConfig;
use rustls::crypto::SupportedKxGroup;
use rustls::crypto::aws_lc_rs::kx_group;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::classify::{GroupResult, Outcome, ProbeGroup, Verdict};
use super::kx::SECP384R1_MLKEM1024;
use super::report::HostReport;
use super::target::parse_target;
use super::{Args, probe_target, run};

type Groups = Vec<&'static dyn SupportedKxGroup>;

/// A TLS 1.3 server configuration with a throwaway self-signed certificate that offers exactly `groups`.
fn server_config(groups: Groups) -> Arc<ServerConfig> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("a self-signed certificate");
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()));
    let config = ServerConfig::builder_with_provider(super::kx::provider_with_groups(groups))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("a server certificate");
    Arc::new(config)
}

async fn bind_loopback() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind 127.0.0.1:0");
    let port = listener.local_addr().expect("a local address").port();
    (listener, port)
}

/// A TLS server on 127.0.0.1 that offers `groups`, and the port it listens on.
async fn spawn_tls_server(groups: Groups) -> u16 {
    let acceptor = TlsAcceptor::from(server_config(groups));
    let (listener, port) = bind_loopback().await;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = acceptor.accept(stream).await;
            });
        }
    });
    port
}

/// A server that peeks at the first TLS record header and, when the ClientHello record is longer than 1000 bytes, closes the
/// connection without an alert; otherwise it completes a classical (X25519) handshake.
async fn spawn_large_hello_intolerant_server() -> u16 {
    let acceptor = TlsAcceptor::from(server_config(vec![kx_group::X25519]));
    let (listener, port) = bind_loopback().await;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut header = [0u8; 5];
                loop {
                    match stream.peek(&mut header).await {
                        Ok(read) if read >= header.len() => break,
                        Ok(0) | Err(_) => return,
                        Ok(_) => tokio::time::sleep(Duration::from_millis(5)).await,
                    }
                }
                let record_length = usize::from(u16::from_be_bytes([header[3], header[4]]));
                if record_length > 1000 {
                    return; // dropped: closed with no alert
                }
                let _ = acceptor.accept(stream).await;
            });
        }
    });
    port
}

/// A server that accepts TCP connections and never says anything.
async fn spawn_silent_server() -> u16 {
    let (listener, port) = bind_loopback().await;
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    port
}

async fn probe_port(port: u16, limit: Duration) -> HostReport {
    let target = parse_target(&format!("127.0.0.1:{port}")).expect("a valid target");
    probe_target(&target, None, limit).await
}

fn result_for(report: &HostReport, group: ProbeGroup) -> &GroupResult {
    report.groups.iter().find(|result| result.group == group).expect("every group has a result")
}

fn is_alert(outcome: &Outcome, name: &str) -> bool {
    matches!(outcome, Outcome::Rejected { alert } if alert == name)
}

fn exit_is(code: ExitCode, expected: u8) -> bool {
    format!("{code:?}") == format!("{:?}", ExitCode::from(expected))
}

fn args(hosts: &[String], timeout_ms: u64) -> Args {
    Args { hosts: hosts.to_vec(), timeout_ms, json: true, sni: None }
}

#[tokio::test]
async fn a_server_with_x25519mlkem768_and_x25519_is_pq_capable() {
    let port = spawn_tls_server(vec![kx_group::X25519MLKEM768, kx_group::X25519]).await;
    let report = probe_port(port, Duration::from_secs(10)).await;
    assert_eq!(report.verdict, Verdict::PqCapable { groups: vec![ProbeGroup::X25519MlKem768] });
    assert_eq!(report.groups.iter().map(|result| result.group).collect::<Vec<_>>(), ProbeGroup::ALL.to_vec());
    let hybrid = result_for(&report, ProbeGroup::X25519MlKem768);
    assert_eq!(hybrid.outcome, Outcome::Accepted { negotiated: Some("X25519MLKEM768".to_owned()) });
    assert!(hybrid.connected);
    assert!(result_for(&report, ProbeGroup::X25519).outcome.is_accepted());
    assert!(is_alert(&result_for(&report, ProbeGroup::Secp256r1).outcome, "handshake_failure"));
}

#[tokio::test]
async fn a_server_with_only_x25519_has_no_post_quantum() {
    let port = spawn_tls_server(vec![kx_group::X25519]).await;
    let report = probe_port(port, Duration::from_secs(10)).await;
    assert_eq!(report.verdict, Verdict::NoPostQuantum);
    for group in [ProbeGroup::X25519MlKem768, ProbeGroup::SecP256r1MlKem768, ProbeGroup::SecP384r1MlKem1024, ProbeGroup::MlKem1024] {
        let outcome = &result_for(&report, group).outcome;
        assert!(is_alert(outcome, "handshake_failure"), "{group:?}: {outcome:?}");
    }
    assert!(result_for(&report, ProbeGroup::X25519).outcome.is_accepted());
}

#[tokio::test]
async fn the_ported_secp384r1mlkem1024_group_is_accepted_by_a_server_using_the_same_glue() {
    let port = spawn_tls_server(vec![SECP384R1_MLKEM1024, kx_group::X25519]).await;
    let report = probe_port(port, Duration::from_secs(10)).await;
    let result = result_for(&report, ProbeGroup::SecP384r1MlKem1024);
    assert_eq!(result.outcome, Outcome::Accepted { negotiated: Some("SecP384r1MLKEM1024".to_owned()) });
    assert_eq!(report.verdict, Verdict::PqCapable { groups: vec![ProbeGroup::SecP384r1MlKem1024] });
}

#[tokio::test]
async fn a_server_with_pure_mlkem1024_reports_it_accepted() {
    let port = spawn_tls_server(vec![kx_group::MLKEM1024, kx_group::X25519]).await;
    let report = probe_port(port, Duration::from_secs(10)).await;
    let result = result_for(&report, ProbeGroup::MlKem1024);
    assert_eq!(result.outcome, Outcome::Accepted { negotiated: Some("MLKEM1024".to_owned()) });
    assert_eq!(report.verdict, Verdict::PqCapable { groups: vec![ProbeGroup::MlKem1024] });
}

#[tokio::test]
async fn a_server_that_drops_large_hellos_with_no_alert_is_pq_intolerant() {
    let port = spawn_large_hello_intolerant_server().await;
    let report = probe_port(port, Duration::from_secs(10)).await;
    assert_eq!(report.verdict, Verdict::PqIntolerant);
    for group in [ProbeGroup::X25519MlKem768, ProbeGroup::SecP256r1MlKem768, ProbeGroup::SecP384r1MlKem1024, ProbeGroup::MlKem1024] {
        let outcome = &result_for(&report, group).outcome;
        assert_eq!(*outcome, Outcome::Reset, "{group:?}");
    }
    assert!(result_for(&report, ProbeGroup::X25519).outcome.is_accepted());
    assert!(report.note.as_deref().is_some_and(|note| note.contains("Heuristic")));
}

#[tokio::test]
async fn a_port_with_nothing_listening_is_unreachable() {
    let (listener, port) = bind_loopback().await;
    drop(listener);
    let report = probe_port(port, Duration::from_secs(5)).await;
    assert_eq!(report.verdict, Verdict::Unreachable);
    assert!(report.groups.iter().all(|result| !result.connected));
    assert!(matches!(result_for(&report, ProbeGroup::X25519MlKem768).outcome, Outcome::Error { .. }));
}

#[tokio::test]
async fn a_server_that_never_answers_times_out_and_is_inconclusive() {
    let port = spawn_silent_server().await;
    let report = probe_port(port, Duration::from_millis(200)).await;
    assert!(report.groups.iter().all(|result| result.outcome == Outcome::TimedOut && result.connected));
    // TCP connected but no group was ever accepted, so it is neither unreachable nor classifiable: inconclusive.
    assert_eq!(report.verdict, Verdict::Inconclusive);
}

#[tokio::test]
async fn run_exits_zero_for_a_pq_capable_host_and_one_for_a_classical_one() {
    let capable = spawn_tls_server(vec![kx_group::X25519MLKEM768, kx_group::X25519]).await;
    let classical = spawn_tls_server(vec![kx_group::X25519]).await;
    let capable_host = format!("127.0.0.1:{capable}");
    let classical_host = format!("127.0.0.1:{classical}");
    assert!(exit_is(run(args(std::slice::from_ref(&capable_host), 10_000)).await, 0));
    assert!(exit_is(run(args(std::slice::from_ref(&classical_host), 10_000)).await, 1));
    assert!(exit_is(run(args(&[capable_host, classical_host], 10_000)).await, 1));
}

#[tokio::test]
async fn run_exits_two_for_an_unreachable_host_even_beside_a_classical_one() {
    let (listener, dead) = bind_loopback().await;
    drop(listener);
    let classical = spawn_tls_server(vec![kx_group::X25519]).await;
    let hosts = [format!("127.0.0.1:{classical}"), format!("127.0.0.1:{dead}")];
    assert!(exit_is(run(args(&hosts, 5_000)).await, 2));
}

#[tokio::test]
async fn run_exits_two_for_bad_arguments() {
    assert!(exit_is(run(args(&["bad host".to_owned()], 1000)).await, 2));
    assert!(exit_is(run(args(&["127.0.0.1:0".to_owned()], 1000)).await, 2));
    let mut with_bad_sni = args(&["127.0.0.1:9".to_owned()], 1000);
    with_bad_sni.sni = Some("not a name".to_owned());
    assert!(exit_is(run(with_bad_sni).await, 2));
}

#[derive(Debug, clap::Parser)]
struct Cli {
    #[command(flatten)]
    args: Args,
}

#[test]
fn the_command_line_defaults() {
    let cli = Cli::try_parse_from(["probe", "example.com", "[::1]:8443"]).expect("valid arguments");
    assert_eq!(cli.args.hosts, ["example.com", "[::1]:8443"]);
    assert_eq!(cli.args.timeout_ms, 5000);
    assert!(!cli.args.json);
    assert_eq!(cli.args.sni, None);
}

#[test]
fn the_command_line_options() {
    let cli = Cli::try_parse_from(["probe", "--json", "--timeout-ms", "250", "--sni", "a.example", "10.0.0.1"]).expect("valid arguments");
    assert!(cli.args.json);
    assert_eq!(cli.args.timeout_ms, 250);
    assert_eq!(cli.args.sni.as_deref(), Some("a.example"));
}

#[test]
fn the_command_line_refuses_no_hosts_and_a_zero_timeout() {
    assert!(Cli::try_parse_from(["probe"]).is_err());
    assert!(Cli::try_parse_from(["probe", "--timeout-ms", "0", "example.com"]).is_err());
    assert!(Cli::try_parse_from(["probe", "--timeout-ms", "abc", "example.com"]).is_err());
}
