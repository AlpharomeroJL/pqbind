// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Start the thread and the async runtime a command runs on, with stack sizes chosen from measurement.
//!
//! The ML-DSA-87 key expansion of the `ml-dsa` crate keeps its working set on the stack, and the platform default of a main thread (1 MiB
//! on Windows) is too small for it in a debug build. Measured minimums are in the comment on the two constants below.
//!
//! Two environment variables override the stack sizes, for measuring and for a platform with unusual limits. They are not part of the
//! documented command line: `PQBIND_STACK_KIB` sets the stack of the command thread and `PQBIND_WORKER_STACK_KIB` the stack of each
//! runtime worker thread, both in KiB. A value that is not a whole number of at least 64 is ignored.

use std::process::ExitCode;

use crate::commands::{self, Command};

/// The environment variable that overrides the command thread's stack, in KiB.
const COMMAND_STACK_ENV: &str = "PQBIND_STACK_KIB";

/// The environment variable that overrides each runtime worker's stack, in KiB.
const WORKER_STACK_ENV: &str = "PQBIND_WORKER_STACK_KIB";

/// The smallest stack an override may ask for, in KiB, and the largest (1 GiB).
const OVERRIDE_RANGE_KIB: std::ops::RangeInclusive<usize> = 64..=1_048_576;

/// The stack of the thread a command runs on, in KiB: 2 MiB.
///
/// Measured on 2026-11-15 on Windows 11 with Rust 1.94.1, as the smallest `PQBIND_STACK_KIB` at which the command still ran, over
/// QUIC and over TLS (the numbers were the same for both):
///
/// | command | debug build | release build |
/// |---|---|---|
/// | `demo` | 992 KiB | 464 KiB |
/// | `verify` | 992 KiB | 464 KiB |
/// | `serve` (start up) | 992 KiB | 464 KiB |
///
/// What sets the floor is the `ml-dsa` key expansion (`ml_dsa::SigningKey::from_seed`), which a command calls once when it loads or
/// makes an identity: alone, on a thread of its own, it needs about 960 KiB in a debug build and 480 KiB in a release build. This
/// crate's own code adds about 32 KiB on top of that in a debug build and nothing measurable in a release build. 2048 KiB is twice
/// the debug figure, which is the larger one.
const COMMAND_STACK_KIB: usize = 2048;

/// The stack of each runtime worker thread, in KiB: 1.25 MiB.
///
/// Workers run the tasks `serve` spawns for each connection, which verify one hybrid proof and make one. Measured the same way with
/// `PQBIND_WORKER_STACK_KIB` while a client connected over QUIC and over TLS: 592 KiB in a debug build and 208 KiB in a release build.
/// Name resolution and the client's endpoint tasks need less than 100 KiB. 1280 KiB is twice the debug figure, rounded up.
const WORKER_STACK_KIB: usize = 1280;

/// The stack in bytes: the override in `text` when it is a number in range, `default_kib` otherwise.
fn stack_bytes(text: Option<&str>, default_kib: usize) -> usize {
    let kib = text.and_then(|text| text.trim().parse::<usize>().ok()).filter(|kib| OVERRIDE_RANGE_KIB.contains(kib)).unwrap_or(default_kib);
    kib.saturating_mul(1024)
}

fn stack_from_env(name: &str, default_kib: usize) -> usize {
    stack_bytes(std::env::var(name).ok().as_deref(), default_kib)
}

/// Run `command` on a thread with the command stack, on a multi-thread runtime with the worker stack, and return its exit code.
pub fn run(command: Command) -> ExitCode {
    let command_stack = stack_from_env(COMMAND_STACK_ENV, COMMAND_STACK_KIB);
    let worker_stack = stack_from_env(WORKER_STACK_ENV, WORKER_STACK_KIB);
    let spawned =
        std::thread::Builder::new().name("pqbind".to_owned()).stack_size(command_stack).spawn(move || execute(command, worker_stack));
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

fn execute(command: Command, worker_stack: usize) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().thread_stack_size(worker_stack).build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("pqbind: cannot start the async runtime: {error}");
            return ExitCode::from(2);
        }
    };
    runtime.block_on(commands::run(command))
}

#[cfg(test)]
mod tests {
    use super::{COMMAND_STACK_KIB, WORKER_STACK_KIB, stack_bytes};

    #[test]
    fn no_override_gives_the_default() {
        assert_eq!(stack_bytes(None, 4096), 4096 * 1024);
    }

    #[test]
    fn a_number_in_range_overrides_the_default() {
        assert_eq!(stack_bytes(Some("512"), 4096), 512 * 1024);
        assert_eq!(stack_bytes(Some(" 64\n"), 4096), 64 * 1024);
    }

    #[test]
    fn a_value_that_is_not_a_number_in_range_is_ignored() {
        for text in ["", "abc", "-5", "0", "63", "1048577", "99999999999999999999", "1.5"] {
            assert_eq!(stack_bytes(Some(text), 4096), 4096 * 1024, "{text:?}");
        }
    }

    #[test]
    fn the_defaults_are_in_the_range_an_override_may_use() {
        assert!(super::OVERRIDE_RANGE_KIB.contains(&COMMAND_STACK_KIB));
        assert!(super::OVERRIDE_RANGE_KIB.contains(&WORKER_STACK_KIB));
    }
}
