// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Describe how one verification ended: the report, its exit code, its JSON form and its text form.

use serde::Serialize;

use crate::common::{CliError, Transport};

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
pub enum Failure {
    /// The server answered with its single refusal.
    Refused,
    /// The server could not prove it holds the pinned key.
    ServerIdentity,
    /// Anything else, as one sentence.
    Other(String),
}

impl From<CliError> for Failure {
    fn from(error: CliError) -> Self {
        Self::Other(error.to_string())
    }
}

impl Report {
    /// A report for a verification that has not finished: the error report, with nothing known yet.
    pub fn begin(target: &str, transport: Transport) -> Self {
        Self {
            result: "error",
            verified: false,
            exit_code: 2,
            target: target.to_owned(),
            transport: transport.name(),
            expected_server_pin: None,
            client_pin: None,
            greeting: None,
            detail: String::new(),
        }
    }

    /// The report of a verification that took too long.
    pub fn timed_out(target: &str, transport: Transport) -> Self {
        let mut report = Self::begin(target, transport);
        report.detail = "timed out after 60 seconds".to_owned();
        report
    }

    /// Record that the server proved the pinned key and accepted this client.
    pub fn succeed(&mut self, greeting: Option<String>) {
        self.result = "verified";
        self.verified = true;
        self.exit_code = 0;
        self.detail = "the server proved the pinned key and accepted this client".to_owned();
        self.greeting = greeting;
    }

    /// Record why the verification did not succeed.
    pub fn fail(&mut self, failure: Failure) {
        match failure {
            Failure::Refused => {
                self.result = "refused";
                self.exit_code = 1;
                self.detail = "the server refused this connection: this client is not enrolled there, or the pin is not that server's pin, or the proof did not verify".to_owned();
            }
            Failure::ServerIdentity => {
                self.result = "server_identity";
                self.exit_code = 1;
                self.detail = "the server could not prove it holds the pinned key".to_owned();
            }
            Failure::Other(message) => {
                self.detail = message;
            }
        }
    }

    /// Print the report as text: a result goes to stdout, an error to stderr.
    pub fn print_text(&self) {
        println!("pqbind verify {} ({})", self.target, self.transport);
        if let Some(pin) = &self.expected_server_pin {
            println!("  pinned server key: {}...", short_hex(pin));
        }
        if let Some(pin) = &self.client_pin {
            println!("  this client:       {}...", short_hex(pin));
        }
        match self.result {
            "verified" => {
                println!("  result:            VERIFIED, {}", self.detail);
                match &self.greeting {
                    Some(greeting) => println!("  server says:       {greeting}"),
                    None => println!("  server says:       (no greeting line arrived)"),
                }
            }
            "refused" => println!("  result:            REFUSED, {}", self.detail),
            "server_identity" => println!("  result:            SERVER IDENTITY FAILED, {}", self.detail),
            _ => eprintln!("pqbind verify: {}", self.detail),
        }
    }

    /// Print the report as one JSON object.
    pub fn print_json(&self) {
        match serde_json::to_string(self) {
            Ok(text) => println!("{text}"),
            Err(error) => eprintln!("pqbind verify: cannot write the JSON report: {error}"),
        }
    }
}

fn short_hex(hex: &str) -> String {
    hex.chars().take(16).collect()
}

#[cfg(test)]
mod tests {
    use super::{Failure, Report};
    use crate::common::Transport;

    #[test]
    fn each_ending_sets_the_result_and_the_exit_code_the_documentation_promises() {
        let mut report = Report::begin("127.0.0.1:1", Transport::Tls);
        assert_eq!((report.result, report.exit_code, report.verified), ("error", 2, false));
        assert_eq!(report.transport, "tls");

        report.succeed(Some("hello".to_owned()));
        assert_eq!((report.result, report.exit_code, report.verified), ("verified", 0, true));
        assert_eq!(report.greeting.as_deref(), Some("hello"));

        let mut report = Report::begin("t", Transport::Quic);
        report.fail(Failure::Refused);
        assert_eq!((report.result, report.exit_code), ("refused", 1));

        let mut report = Report::begin("t", Transport::Quic);
        report.fail(Failure::ServerIdentity);
        assert_eq!((report.result, report.exit_code), ("server_identity", 1));

        let mut report = Report::begin("t", Transport::Quic);
        report.fail(Failure::Other("no route".to_owned()));
        assert_eq!((report.result, report.exit_code, report.detail.as_str()), ("error", 2, "no route"));
    }

    #[test]
    fn a_timeout_is_an_error_report_that_says_so() {
        let report = Report::timed_out("t", Transport::Quic);
        assert_eq!((report.result, report.exit_code), ("error", 2));
        assert_eq!(report.detail, "timed out after 60 seconds");
    }
}
