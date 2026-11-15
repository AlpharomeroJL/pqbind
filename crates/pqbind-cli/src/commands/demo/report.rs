// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Define what a demo scenario must show (a [`Spec`]), compare it with what happened and hold the outcome (a [`ScenarioResult`] and a [`Report`]).

use pqbind::Error;

use crate::common::Transport;

/// What a scenario's end must do for the scenario to pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
    /// The handshake returns `Ok`.
    Accept,
    /// The handshake returns this error.
    Reject(Error),
}

/// What a scenario is and what it must show.
pub struct Spec {
    /// A short id: `a`, `b1`, `b2`, `c`, `d`, `e`, `f1` or `f2`.
    pub id: &'static str,
    /// What the scenario is called.
    pub title: &'static str,
    /// Who holds what, in plain words.
    pub story: &'static str,
    /// What should happen, in one sentence.
    pub expect: &'static str,
    /// What the client end is called in the tables.
    pub client_name: &'static str,
    /// What the server end is called in the tables.
    pub server_name: &'static str,
    /// What the client end must do, when a real client runs.
    pub client: Option<Want>,
    /// What the server end must do, when a real server runs.
    pub server: Option<Want>,
    /// A sentence to print after the verdict.
    pub note: Option<&'static str>,
}

/// How one scenario ended.
#[derive(Debug, Clone)]
pub struct ScenarioResult {
    /// A short id: `a`, `b1`, `b2`, `c`, `d`, `e`, `f1` or `f2`.
    pub id: &'static str,
    /// What the scenario is called.
    pub title: &'static str,
    /// Who holds what, in plain words.
    pub story: &'static str,
    /// What should happen, in one sentence.
    pub expected: String,
    /// What should happen, as handshake results.
    pub expected_short: String,
    /// What happened, as handshake results.
    pub observed_short: String,
    /// What happened, line by line.
    pub observed: Vec<String>,
    /// How the client end of the pqbind handshake ended, when a real client ran one.
    #[cfg(test)]
    pub client: Option<Result<(), Error>>,
    /// How the server end of the pqbind handshake ended, when a real server ran one.
    #[cfg(test)]
    pub server: Option<Result<(), Error>>,
    /// Whether the scenario behaved as expected.
    pub passed: bool,
    /// A sentence to print after the verdict (the limit scenarios use it).
    pub note: Option<&'static str>,
}

/// Every scenario of one demo run.
#[derive(Debug, Clone)]
pub struct Report {
    /// The transport the scenarios ran over.
    pub transport: Transport,
    /// The scenarios in the order they ran.
    pub scenarios: Vec<ScenarioResult>,
}

impl Report {
    /// Whether every scenario behaved as expected.
    pub fn all_passed(&self) -> bool {
        !self.scenarios.is_empty() && self.scenarios.iter().all(|scenario| scenario.passed)
    }

    /// The scenario with this id.
    #[cfg(test)]
    pub fn find(&self, id: &str) -> Option<&ScenarioResult> {
        self.scenarios.iter().find(|scenario| scenario.id == id)
    }
}

fn got_text(got: &Result<(), Error>) -> String {
    match got {
        Ok(()) => "Ok".to_owned(),
        Err(error) => format!("Err({error:?})"),
    }
}

fn meets(want: Want, got: &Result<(), Error>) -> bool {
    match want {
        Want::Accept => got.is_ok(),
        Want::Reject(error) => *got == Err(error),
    }
}

/// The result a `Want` names, in the form an observed result takes, so the wanted and the observed print the same way.
const fn wanted_result(want: Want) -> Result<(), Error> {
    match want {
        Want::Accept => Ok(()),
        Want::Reject(error) => Err(error),
    }
}

fn outcomes_text(client: Option<&Result<(), Error>>, server: Option<&Result<(), Error>>, names: (&str, &str)) -> String {
    let mut parts = Vec::new();
    if let Some(got) = client {
        parts.push(format!("{} {}", names.0, got_text(got)));
    }
    if let Some(got) = server {
        parts.push(format!("{} {}", names.1, got_text(got)));
    }
    parts.join(", ")
}

/// Judge what happened against what `spec` asked for. `consistent` is false when something else about the scenario went wrong (an
/// attacker's own code failed, or an end did not authenticate the key it should have).
pub fn conclude(
    spec: &Spec,
    client: Option<Result<(), Error>>,
    server: Option<Result<(), Error>>,
    mut observed: Vec<String>,
    consistent: bool,
) -> ScenarioResult {
    let matches = |want: Option<Want>, got: &Option<Result<(), Error>>| match (want, got) {
        (None, _) => true,
        (Some(want), Some(got)) => meets(want, got),
        (Some(_), None) => false,
    };
    let passed = matches(spec.client, &client) && matches(spec.server, &server) && consistent;
    let names = (spec.client_name, spec.server_name);
    let wanted_client = spec.client.map(wanted_result);
    let wanted_server = spec.server.map(wanted_result);
    let expected_short = outcomes_text(wanted_client.as_ref(), wanted_server.as_ref(), names);
    let observed_short = outcomes_text(client.as_ref(), server.as_ref(), names);
    observed.insert(0, observed_short.clone());
    ScenarioResult {
        id: spec.id,
        title: spec.title,
        story: spec.story,
        expected: spec.expect.to_owned(),
        expected_short,
        observed_short,
        observed,
        #[cfg(test)]
        client,
        #[cfg(test)]
        server,
        passed,
        note: spec.note,
    }
}

#[cfg(test)]
mod tests {
    use pqbind::Error;

    use super::{Spec, Want, conclude};

    fn spec(client: Option<Want>, server: Option<Want>) -> Spec {
        Spec {
            id: "x",
            title: "A test scenario",
            story: "A story.",
            expect: "something",
            client_name: "client",
            server_name: "server",
            client,
            server,
            note: None,
        }
    }

    #[test]
    fn a_scenario_passes_only_when_every_wanted_end_did_what_was_wanted() {
        let spec = spec(Some(Want::Reject(Error::Refused)), Some(Want::Accept));
        let good = conclude(&spec, Some(Err(Error::Refused)), Some(Ok(())), Vec::new(), true);
        assert!(good.passed);
        assert_eq!(good.expected_short, "client Err(Refused), server Ok");
        assert_eq!(good.observed_short, good.expected_short);
        assert_eq!(good.observed.first(), Some(&good.observed_short), "the first observed line is the summary");

        let wrong_error = conclude(&spec, Some(Err(Error::ServerIdentity)), Some(Ok(())), Vec::new(), true);
        assert!(!wrong_error.passed);
        let missing_end = conclude(&spec, None, Some(Ok(())), Vec::new(), true);
        assert!(!missing_end.passed, "a wanted end that never ran is a failure");
        let inconsistent = conclude(&spec, Some(Err(Error::Refused)), Some(Ok(())), Vec::new(), false);
        assert!(!inconsistent.passed, "a failed side check fails the scenario");
    }

    #[test]
    fn an_end_that_is_not_wanted_is_not_judged() {
        let spec = spec(Some(Want::Reject(Error::ServerIdentity)), None);
        let result = conclude(&spec, Some(Err(Error::ServerIdentity)), Some(Err(Error::Refused)), Vec::new(), true);
        assert!(result.passed);
        assert_eq!(result.expected_short, "client Err(ServerIdentity)");
    }
}
