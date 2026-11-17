// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Start the `pqbind` command line: read the arguments and hand the chosen subcommand to the runtime.

mod commands;
mod common;
mod keyfiles;
mod registry_file;
mod runtime;
#[cfg(test)]
mod testutil;
mod transport;

use std::process::ExitCode;

use clap::Parser;

use crate::commands::Command;

/// Post-quantum authentication for connections that already exist.
#[derive(Debug, Parser)]
#[command(name = "pqbind", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

fn main() -> ExitCode {
    match Cli::try_parse() {
        Ok(cli) => runtime::run(cli.command),
        Err(error) => {
            // `--help` and `--version` print to stdout and succeed; a usage error prints to stderr and exits 2.
            let _ = error.print();
            ExitCode::from(u8::try_from(error.exit_code()).unwrap_or(2))
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::Cli;

    #[test]
    fn the_command_line_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn the_six_subcommands_are_the_ones_the_documentation_names() {
        let command = Cli::command();
        let names: Vec<&str> = command.get_subcommands().map(clap::Command::get_name).collect();
        assert_eq!(names, ["demo", "serve", "verify", "keygen", "enroll", "probe"]);
    }

    #[test]
    fn every_documented_flag_still_parses() {
        let lines: [&[&str]; 11] = [
            &["pqbind", "enroll", "add", "--registry", "c.reg", "--key", "c.pub", "--pin", "ab"],
            &["pqbind", "enroll", "add", "--registry", "c.reg", "--key", "c.pub"],
            &["pqbind", "enroll", "list", "--registry", "c.reg"],
            &["pqbind", "enroll", "revoke", "--registry", "c.reg", "--pin", "abcdef0123456789"],
            &["pqbind", "serve", "--listen", "127.0.0.1:4433", "--identity", "s.seed", "--registry", "c.reg"],
            &["pqbind", "demo"],
            &["pqbind", "demo", "--transport", "tls"],
            &["pqbind", "keygen", "--out", "client.seed", "--public-out", "client.pub"],
            &["pqbind", "serve", "--listen", "127.0.0.1:4433", "--identity", "s.seed", "--enroll", "c.pub", "--cert-out", "s.pem"],
            &["pqbind", "verify", "127.0.0.1:4433", "--pin", "ab", "--identity", "c.seed", "--ca", "s.pem", "--json"],
            &["pqbind", "probe", "cloudflare.com", "google.com", "--json", "--timeout-ms", "250", "--sni", "a.example"],
        ];
        for line in lines {
            assert!(Cli::try_parse_from(line).is_ok(), "{line:?}");
        }
    }

    #[test]
    fn a_missing_or_unknown_argument_is_a_usage_error() {
        for line in [
            &["pqbind"][..],
            &["pqbind", "nope"],
            &["pqbind", "serve", "--listen", "127.0.0.1:1"],
            &["pqbind", "demo", "--transport", "udp"],
        ] {
            assert!(Cli::try_parse_from(line).is_err(), "{line:?}");
        }
    }
}
