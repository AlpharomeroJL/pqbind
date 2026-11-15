// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Run `pqbind demo`: real QUIC or TLS connections on 127.0.0.1 where attackers who hold classical keys still fail the hybrid proof.
//!
//! `run_scenarios` is the engine: it runs every scenario and returns a [`Report`] a test can inspect. [`run`] prints that report as a
//! story and a summary table, and exits 0 only when every scenario behaved as expected, so the demo is also a self test. The parts:
//!
//! - `scenarios`: the eight scenarios, their stories and what each must show.
//! - `attackers`: the attackers, who build frames by hand.
//! - `ends`: an honest end of the handshake.
//! - `cast`: the keys of one run.
//! - `report`: the expectations, the verdicts and the report types.
//! - `runner`: runs the scenarios in order.
//! - `print`: writes the demo to the terminal.

mod attackers;
mod cast;
mod ends;
mod print;
mod report;
mod runner;
mod scenarios;

#[cfg(test)]
mod tests;

use std::process::ExitCode;

use self::print::{print_intro, print_scenario, print_summary};
use self::runner::run_scenarios;
use crate::common::Transport;

/// The application label the demo's peers use.
const LABEL: &[u8] = b"pqbind-demo/v1";

/// The arguments of `pqbind demo`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// The transport to run the demo over.
    #[arg(long, value_enum, default_value_t = Transport::Quic)]
    pub transport: Transport,
}

/// Run `pqbind demo`.
pub async fn run(args: Args) -> ExitCode {
    print_intro(args.transport);
    match run_scenarios(args.transport, print_scenario).await {
        Ok(report) => {
            print_summary(&report);
            if report.all_passed() { ExitCode::SUCCESS } else { ExitCode::from(1) }
        }
        Err(error) => {
            eprintln!("pqbind demo: the demo could not run: {error}");
            ExitCode::from(2)
        }
    }
}
