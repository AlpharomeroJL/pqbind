// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Test the whole demo over real loopback connections: every scenario's outcome over QUIC and over TLS, in order.

use pqbind::Error;

use super::report::Report;
use super::runner::run_scenarios;
use crate::common::Transport;

async fn report(transport: Transport) -> Report {
    let mut seen = Vec::new();
    let report = run_scenarios(transport, |scenario| seen.push(scenario.id)).await.expect("the demo runs");
    assert_eq!(seen, ["a", "b1", "b2", "c", "d", "e", "f1", "f2"], "every scenario ran in order and was reported as it finished");
    report
}

fn assert_every_outcome(report: &Report) {
    let get = |id: &str| report.find(id).unwrap_or_else(|| panic!("scenario {id}"));
    // a: the honest pair.
    assert_eq!((get("a").client, get("a").server), (Some(Ok(())), Some(Ok(()))));
    // b1: forged server proof, the client refuses it as a server identity failure.
    assert_eq!(get("b1").client, Some(Err(Error::ServerIdentity)));
    // b2: the real accept code with the attacker's own key refuses the client, and the client sees a refusal.
    assert_eq!((get("b2").client, get("b2").server), (Some(Err(Error::Refused)), Some(Err(Error::Refused))));
    // c: the forged client proof is refused by the real server.
    assert_eq!(get("c").server, Some(Err(Error::Refused)));
    // d: the relayed proof is refused by the server, and the client is told.
    assert_eq!((get("d").client, get("d").server), (Some(Err(Error::Refused)), Some(Err(Error::Refused))));
    // e: not enrolled.
    assert_eq!((get("e").client, get("e").server), (Some(Err(Error::Refused)), Some(Err(Error::Refused))));
    // f: the whole key is accepted, and the report says it is the limit.
    for id in ["f1", "f2"] {
        assert_eq!((get(id).client, get(id).server), (Some(Ok(())), Some(Ok(()))), "{id}");
        assert!(get(id).note.is_some_and(|note| note.contains("outside its threat model")), "{id}");
    }
    for scenario in &report.scenarios {
        assert!(scenario.passed, "{} did not behave as expected: {scenario:?}", scenario.id);
        assert!(!scenario.observed.is_empty() && !scenario.expected.is_empty());
    }
    assert!(report.all_passed());
    assert!(
        report.scenarios.iter().all(|scenario| !scenario.title.contains('\u{2014}') && !scenario.story.contains('\u{2014}')),
        "no em dashes"
    );
}

#[tokio::test]
async fn over_quic_every_scenario_behaves_as_expected() {
    assert_every_outcome(&report(Transport::Quic).await);
}

#[tokio::test]
async fn over_tls_every_scenario_behaves_as_expected() {
    assert_every_outcome(&report(Transport::Tls).await);
}

#[test]
fn a_report_with_a_failed_scenario_is_not_a_pass() {
    let empty = Report { transport: Transport::Quic, scenarios: Vec::new() };
    assert!(!empty.all_passed(), "an empty report is not a pass");
}
