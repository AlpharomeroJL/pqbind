// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Start the `pqbind` command line and dispatch to its subcommands: `demo`, `serve`, `verify`, `keygen` and `probe`.

mod cert;
mod common;
mod demo;
mod keygen;
mod net;
mod probe;
mod serve;
#[cfg(test)]
mod testutil;
mod verify;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Post-quantum authentication for connections that already exist.
#[derive(Debug, Parser)]
#[command(name = "pqbind", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the attack demonstration on 127.0.0.1 (also a self test: it exits 0 only if every scenario behaved as expected).
    Demo(demo::Args),
    /// Run a small pqbind server that greets enrolled clients.
    Serve(serve::Args),
    /// Connect to a pqbind server and check its proof against a pinned key.
    Verify(verify::Args),
    /// Make a new hybrid identity (seed file, optional public key file) and print its pin.
    Keygen(keygen::Args),
    /// Report which post-quantum key exchange groups a host accepts.
    Probe(probe::Args),
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            // `--help` and `--version` print to stdout and succeed; a usage error prints to stderr and exits 2.
            let _ = error.print();
            return ExitCode::from(u8::try_from(error.exit_code()).unwrap_or(2));
        }
    };
    // The lattice signature code keeps large buffers on the stack, and an unoptimized build keeps even more. The platform default for a
    // main thread (1 MiB on Windows) is too small for it, so the command runs on a thread with a stack that is.
    let spawned = std::thread::Builder::new().name("pqbind".to_owned()).stack_size(MAIN_STACK_BYTES).spawn(move || execute(cli.command));
    match spawned {
        Ok(handle) => handle.join().unwrap_or_else(|_| {
            eprintln!("pqbind: the command stopped unexpectedly");
            ExitCode::from(2)
        }),
        Err(error) => {
            eprintln!("pqbind: cannot start the command thread: {error}");
            ExitCode::from(2)
        }
    }
}

/// The stack of the thread the command runs on.
const MAIN_STACK_BYTES: usize = 64 * 1024 * 1024;

/// The stack of each runtime worker thread, which runs the tasks `serve` spawns.
const WORKER_STACK_BYTES: usize = 32 * 1024 * 1024;

fn execute(command: Command) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().thread_stack_size(WORKER_STACK_BYTES).build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("pqbind: cannot start the async runtime: {error}");
            return ExitCode::from(2);
        }
    };
    runtime.block_on(async {
        match command {
            Command::Demo(args) => demo::run(args).await,
            Command::Serve(args) => serve::run(args).await,
            Command::Verify(args) => verify::run(args).await,
            Command::Keygen(args) => keygen::run(&args),
            Command::Probe(args) => probe::run(args).await,
        }
    })
}
