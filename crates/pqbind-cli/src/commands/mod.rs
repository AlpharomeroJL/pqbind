// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: List the subcommands of `pqbind` (`demo`, `serve`, `verify`, `keygen`, `enroll` and `probe`) and run the one the user chose.

pub mod demo;
pub mod enroll;
pub mod keygen;
pub mod probe;
pub mod serve;
pub mod verify;

use std::process::ExitCode;

use clap::Subcommand;

/// A subcommand, with its arguments.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the attack demonstration on 127.0.0.1 (also a self test: it exits 0 only if every scenario behaved as expected).
    Demo(demo::Args),
    /// Run a small pqbind server that greets enrolled clients.
    Serve(serve::Args),
    /// Connect to a pqbind server and check its proof against a pinned key.
    Verify(verify::Args),
    /// Make a new hybrid identity (seed file, optional public key file) and print its pin.
    Keygen(keygen::Args),
    /// Manage the file of enrolled clients: add a key after checking its pin, list the clients, revoke one.
    Enroll(enroll::Args),
    /// Report which post-quantum key exchange groups a host accepts.
    Probe(probe::Args),
}

/// Run `command` to its end and return the process exit code.
///
/// The commands that hold handshakes are boxed: each one's future is a state machine that keeps connections, keys and buffers, and
/// `block_on` would otherwise keep the largest of them on the stack of the calling thread.
pub async fn run(command: Command) -> ExitCode {
    match command {
        Command::Demo(args) => Box::pin(demo::run(args)).await,
        Command::Serve(args) => Box::pin(serve::run(args)).await,
        Command::Verify(args) => Box::pin(verify::run(args)).await,
        Command::Keygen(args) => keygen::run(&args),
        Command::Enroll(args) => enroll::run(&args),
        Command::Probe(args) => Box::pin(probe::run(args)).await,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Command, demo, keygen, probe, run, serve, verify};
    use crate::common::Transport;

    /// The most a command's future may hold in itself, in bytes. Measured in a debug build on 2026-11-15: 1.4 to 3 KiB. Before the
    /// scenarios were boxed the demo's was 16.8 KiB, and `block_on` keeps the future it runs on the stack of the calling thread.
    const COMMAND_FUTURE_LIMIT: usize = 8 * 1024;

    /// The most the dispatch future may hold: it only holds the boxed future of the command it runs.
    const DISPATCH_FUTURE_LIMIT: usize = 1024;

    fn size_of_future<F: std::future::Future>(future: &F) -> usize {
        std::mem::size_of_val(future)
    }

    #[test]
    fn the_futures_block_on_keeps_on_the_stack_stay_small() {
        let demo_args = || demo::Args { transport: Transport::Quic };
        assert!(size_of_future(&demo::run(demo_args())) < COMMAND_FUTURE_LIMIT, "demo::run");
        let verify_args = verify::Args {
            target: String::new(),
            pin: String::new(),
            identity: PathBuf::new(),
            ca: None,
            server_name: None,
            transport: Transport::Quic,
            app_label: String::new(),
            json: false,
        };
        assert!(size_of_future(&verify::execute(&verify_args)) < COMMAND_FUTURE_LIMIT, "verify::execute");
        let serve_args = serve::Args {
            listen: String::new(),
            identity: PathBuf::new(),
            enroll: Vec::new(),
            registry: None,
            transport: Transport::Quic,
            cert_out: None,
            app_label: String::new(),
            allow_non_loopback: false,
        };
        assert!(size_of_future(&serve::run(serve_args)) < COMMAND_FUTURE_LIMIT, "serve::run");
        let probe_args = probe::Args { hosts: Vec::new(), timeout_ms: 1, json: false, sni: None };
        assert!(size_of_future(&probe::run(probe_args)) < COMMAND_FUTURE_LIMIT, "probe::run");
        let keygen_args = keygen::Args { out: PathBuf::new(), public_out: None };
        assert!(size_of_future(&run(Command::Keygen(keygen_args))) < DISPATCH_FUTURE_LIMIT, "commands::run");
    }
}
