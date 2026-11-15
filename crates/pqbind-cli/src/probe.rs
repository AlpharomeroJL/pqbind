// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Test which TLS 1.3 key exchange groups a host accepts, and tell a host without post-quantum groups from a path that breaks on the larger hello.
//!
//! For each host, one at a time, and for each group, one at a time (never more than one connection open), the probe opens a TCP
//! connection and runs a TLS 1.3 handshake that offers that one group alone: `X25519MLKEM768`, `SecP256r1MLKEM768`,
//! `SecP384r1MLKEM1024`, pure `MLKEM1024`, then the classical baselines `X25519` and `secp256r1`. It then classifies the host
//! (`classify`) and prints a table or one JSON document (`report`).
//!
//! The probe tests key exchange only. It does NOT validate certificates, and its output says so.

mod attempt;
mod classify;
mod kx;
mod report;
mod target;

#[cfg(test)]
mod tests;

use std::process::ExitCode;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;

use self::attempt::{elapsed_ms, probe_group, resolve};
use self::classify::{GroupResult, Outcome, ProbeGroup, classify, exit_code};
use self::report::{HostReport, render_json, render_table};
use self::target::{Target, parse_target, server_name_for};

/// The largest `--timeout-ms` accepted: ten minutes.
const MAX_TIMEOUT_MS: u64 = 600_000;

/// The arguments of `pqbind probe`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// Hosts to probe: `host`, `host:port` or `[ipv6]:port`. The port defaults to 443.
    #[arg(required = true, value_name = "HOST[:PORT]")]
    pub hosts: Vec<String>,

    /// How long to wait for each attempt (connect and handshake), in milliseconds.
    #[arg(long, default_value_t = 5000, value_name = "N", value_parser = clap::value_parser!(u64).range(1..=MAX_TIMEOUT_MS))]
    pub timeout_ms: u64,

    /// Print one JSON document instead of a table.
    #[arg(long)]
    pub json: bool,

    /// Send this name as the TLS server name (SNI) instead of the host.
    #[arg(long, value_name = "NAME")]
    pub sni: Option<String>,
}

/// Run the probe. Exit code 0 when every host is post-quantum capable, 1 when any host has no post-quantum key exchange or looks
/// intolerant of the larger hello, 2 when any host is unreachable or inconclusive or the arguments are bad (2 wins over 1).
pub async fn run(args: Args) -> ExitCode {
    let mut targets = Vec::with_capacity(args.hosts.len());
    for typed in &args.hosts {
        match parse_target(typed) {
            Ok(target) => targets.push(target),
            Err(error) => {
                eprintln!("pqbind probe: cannot use '{typed}': {error}");
                return ExitCode::from(2);
            }
        }
    }
    let sni = match &args.sni {
        None => None,
        Some(name) => match server_name_for(name) {
            Ok(server_name) => Some(server_name),
            Err(error) => {
                eprintln!("pqbind probe: cannot use --sni '{name}': {error}");
                return ExitCode::from(2);
            }
        },
    };
    let limit = Duration::from_millis(args.timeout_ms);

    // One host after another, so the probe never hammers anyone.
    let mut reports = Vec::with_capacity(targets.len());
    for target in &targets {
        reports.push(probe_target(target, sni.as_ref(), limit).await);
    }

    let verdicts: Vec<_> = reports.iter().map(|report| report.verdict.clone()).collect();
    let code = exit_code(&verdicts);
    if args.json {
        match render_json(&reports, code) {
            Ok(text) => println!("{text}"),
            Err(_) => {
                eprintln!("pqbind probe: could not write the JSON output");
                return ExitCode::from(2);
            }
        }
    } else {
        print!("{}", render_table(&reports));
    }
    ExitCode::from(code)
}

/// Probe one host: every group, one after another. Not validated: the certificate is never checked.
async fn probe_target(target: &Target, sni: Option<&ServerName<'static>>, limit: Duration) -> HostReport {
    let started = Instant::now();
    let name = sni.unwrap_or(&target.server_name);
    let groups = match resolve(&target.host, target.port, limit).await {
        Ok(addresses) => probe_groups(&addresses, name, limit).await,
        Err(outcome) => ProbeGroup::ALL.iter().map(|&group| GroupResult::new(group, outcome.clone(), false, 0)).collect(),
    };
    let verdict = classify(&groups);
    HostReport {
        host: target.label.clone(),
        port: target.port,
        note: verdict.note().map(str::to_owned),
        verdict,
        groups,
        elapsed_ms: elapsed_ms(started),
    }
}

/// Every group against one resolved host, in order. When the first attempt cannot even open a TCP connection, the rest are
/// skipped (and recorded as skipped) rather than repeating a connection that cannot work.
async fn probe_groups(addresses: &[std::net::SocketAddr], name: &ServerName<'static>, limit: Duration) -> Vec<GroupResult> {
    let mut results: Vec<GroupResult> = Vec::with_capacity(ProbeGroup::ALL.len());
    for group in ProbeGroup::ALL {
        let first_failed_to_connect = results.first().is_some_and(|first| !first.connected);
        if first_failed_to_connect {
            results.push(GroupResult::new(group, Outcome::Error { kind: "skipped_after_connect_failure".to_owned() }, false, 0));
        } else {
            results.push(probe_group(addresses, name, group, limit).await);
        }
    }
    results
}
