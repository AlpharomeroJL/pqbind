// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Test the pure probe logic: group names and code points, the verdict rules, the exit codes and the JSON shapes.

use super::classify::{
    GroupKind, GroupResult, Outcome, ProbeGroup, Verdict, alert_name, classify, exit_code, group_name_for_code, snake_head,
};

fn accepted() -> Outcome {
    Outcome::Accepted { negotiated: None }
}

fn rejected() -> Outcome {
    Outcome::Rejected { alert: "handshake_failure".to_owned() }
}

fn error() -> Outcome {
    Outcome::Error { kind: "tls_peer_misbehaved".to_owned() }
}

/// A full set of results: `pq` is the outcome of the four post-quantum groups, `x25519` and `p256` of the classical ones.
fn set(pq: Outcome, x25519: Outcome, p256: Outcome) -> Vec<GroupResult> {
    ProbeGroup::ALL
        .iter()
        .map(|&group| {
            let outcome = match group {
                ProbeGroup::X25519 => x25519.clone(),
                ProbeGroup::Secp256r1 => p256.clone(),
                _ => pq.clone(),
            };
            GroupResult::new(group, outcome, true, 1)
        })
        .collect()
}

fn with(mut results: Vec<GroupResult>, group: ProbeGroup, outcome: Outcome) -> Vec<GroupResult> {
    for result in &mut results {
        if result.group == group {
            result.outcome = outcome.clone();
        }
    }
    results
}

#[test]
fn group_order_and_names() {
    let names: Vec<&str> = ProbeGroup::ALL.iter().map(|group| group.name()).collect();
    assert_eq!(names, ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM1024", "X25519", "secp256r1"]);
}

#[test]
fn group_kinds() {
    assert_eq!(ProbeGroup::X25519MlKem768.kind(), GroupKind::Hybrid);
    assert_eq!(ProbeGroup::SecP384r1MlKem1024.kind(), GroupKind::Hybrid);
    assert_eq!(ProbeGroup::MlKem1024.kind(), GroupKind::PureMlKem);
    assert!(ProbeGroup::MlKem1024.is_post_quantum());
    assert!(!ProbeGroup::X25519.is_post_quantum());
    assert!(!ProbeGroup::Secp256r1.is_post_quantum());
}

#[test]
fn code_points_match_the_iana_registry() {
    assert_eq!(ProbeGroup::X25519MlKem768.code_point(), 0x11ec);
    assert_eq!(ProbeGroup::SecP256r1MlKem768.code_point(), 0x11eb);
    assert_eq!(ProbeGroup::SecP384r1MlKem1024.code_point(), 0x11ed);
    assert_eq!(ProbeGroup::MlKem1024.code_point(), 0x0202);
}

#[test]
fn group_names_from_code_points() {
    assert_eq!(group_name_for_code(0x11ed), "SecP384r1MLKEM1024");
    assert_eq!(group_name_for_code(0x001d), "X25519");
    assert_eq!(group_name_for_code(0x0018), "secp384r1");
    assert_eq!(group_name_for_code(0xfe00), "group_0xfe00");
}

#[test]
fn alert_names() {
    assert_eq!(alert_name(40), "handshake_failure");
    assert_eq!(alert_name(70), "protocol_version");
    assert_eq!(alert_name(47), "illegal_parameter");
    assert_eq!(alert_name(200), "alert_200");
}

#[test]
fn snake_head_keeps_only_the_leading_name() {
    assert_eq!(snake_head("PeerIncompatible(NoKxGroupsInCommon)"), "peer_incompatible");
    assert_eq!(snake_head("General(\"secret.example\")"), "general");
    assert_eq!(snake_head("(odd)"), "unknown");
}

#[test]
fn any_accepted_pq_group_is_pq_capable() {
    let results = with(set(rejected(), accepted(), accepted()), ProbeGroup::X25519MlKem768, accepted());
    assert_eq!(classify(&results), Verdict::PqCapable { groups: vec![ProbeGroup::X25519MlKem768] });
}

#[test]
fn pure_ml_kem_counts_as_pq_capable() {
    let results = with(set(rejected(), accepted(), accepted()), ProbeGroup::MlKem1024, accepted());
    assert_eq!(classify(&results), Verdict::PqCapable { groups: vec![ProbeGroup::MlKem1024] });
}

#[test]
fn pq_capable_lists_every_accepted_pq_group_in_order() {
    let results = with(
        with(set(rejected(), accepted(), accepted()), ProbeGroup::SecP384r1MlKem1024, accepted()),
        ProbeGroup::X25519MlKem768,
        accepted(),
    );
    assert_eq!(classify(&results), Verdict::PqCapable { groups: vec![ProbeGroup::X25519MlKem768, ProbeGroup::SecP384r1MlKem1024] });
}

#[test]
fn pq_capable_even_when_the_classical_baselines_fail() {
    let results = with(set(rejected(), rejected(), rejected()), ProbeGroup::X25519MlKem768, accepted());
    assert!(matches!(classify(&results), Verdict::PqCapable { .. }));
}

#[test]
fn classical_accepted_and_pq_all_alerts_is_no_post_quantum() {
    assert_eq!(classify(&set(rejected(), accepted(), rejected())), Verdict::NoPostQuantum);
}

#[test]
fn one_classical_group_is_enough_for_no_post_quantum() {
    assert_eq!(classify(&set(rejected(), rejected(), accepted())), Verdict::NoPostQuantum);
}

#[test]
fn classical_accepted_and_pq_timed_out_is_intolerant() {
    assert_eq!(classify(&set(Outcome::TimedOut, accepted(), accepted())), Verdict::PqIntolerant);
}

#[test]
fn classical_accepted_and_pq_reset_is_intolerant() {
    assert_eq!(classify(&set(Outcome::Reset, accepted(), rejected())), Verdict::PqIntolerant);
}

#[test]
fn mixed_alerts_and_silence_is_intolerant() {
    let results = with(set(rejected(), accepted(), accepted()), ProbeGroup::MlKem1024, Outcome::Reset);
    assert_eq!(classify(&results), Verdict::PqIntolerant);
}

#[test]
fn a_pq_error_that_is_not_an_alert_or_silence_is_inconclusive() {
    let results = with(set(Outcome::Reset, accepted(), accepted()), ProbeGroup::X25519MlKem768, error());
    assert_eq!(classify(&results), Verdict::Inconclusive);
}

#[test]
fn nothing_connected_is_unreachable() {
    let results: Vec<GroupResult> = ProbeGroup::ALL
        .iter()
        .map(|&group| GroupResult::new(group, Outcome::Error { kind: "connection_refused".to_owned() }, false, 0))
        .collect();
    assert_eq!(classify(&results), Verdict::Unreachable);
}

#[test]
fn connect_timeouts_everywhere_are_unreachable() {
    let results: Vec<GroupResult> = ProbeGroup::ALL.iter().map(|&group| GroupResult::new(group, Outcome::TimedOut, false, 5000)).collect();
    assert_eq!(classify(&results), Verdict::Unreachable);
}

#[test]
fn connected_but_silent_everywhere_is_inconclusive() {
    assert_eq!(classify(&set(Outcome::TimedOut, Outcome::TimedOut, Outcome::TimedOut)), Verdict::Inconclusive);
}

#[test]
fn connected_but_every_attempt_rejected_is_inconclusive() {
    assert_eq!(classify(&set(rejected(), rejected(), rejected())), Verdict::Inconclusive);
}

#[test]
fn no_results_is_inconclusive() {
    assert_eq!(classify(&[]), Verdict::Inconclusive);
}

#[test]
fn only_classical_results_with_a_classical_accept_is_inconclusive() {
    let results: Vec<GroupResult> = vec![GroupResult::new(ProbeGroup::X25519, accepted(), true, 1)];
    assert_eq!(classify(&results), Verdict::Inconclusive);
}

#[test]
fn exit_code_zero_only_when_every_host_is_pq_capable() {
    let capable = Verdict::PqCapable { groups: vec![ProbeGroup::X25519MlKem768] };
    assert_eq!(exit_code(std::slice::from_ref(&capable)), 0);
    assert_eq!(exit_code(&[capable.clone(), capable]), 0);
}

#[test]
fn exit_code_one_for_no_pq_or_intolerant() {
    let capable = Verdict::PqCapable { groups: vec![ProbeGroup::X25519MlKem768] };
    assert_eq!(exit_code(&[capable.clone(), Verdict::NoPostQuantum]), 1);
    assert_eq!(exit_code(&[Verdict::PqIntolerant, capable]), 1);
    assert_eq!(exit_code(&[Verdict::NoPostQuantum, Verdict::PqIntolerant]), 1);
}

#[test]
fn exit_code_two_wins_over_one() {
    assert_eq!(exit_code(&[Verdict::NoPostQuantum, Verdict::Unreachable]), 2);
    assert_eq!(exit_code(&[Verdict::Inconclusive, Verdict::PqIntolerant]), 2);
    assert_eq!(exit_code(&[Verdict::Unreachable]), 2);
}

#[test]
fn exit_code_two_when_nothing_was_probed() {
    assert_eq!(exit_code(&[]), 2);
}

#[test]
fn json_shapes() {
    let result = GroupResult::new(ProbeGroup::X25519MlKem768, Outcome::Accepted { negotiated: Some("X25519MLKEM768".to_owned()) }, true, 7);
    let value = serde_json::to_value(&result).unwrap_or_default();
    assert_eq!(value["group"], "X25519MLKEM768");
    assert_eq!(value["kind"], "hybrid");
    assert_eq!(value["status"], "accepted");
    assert_eq!(value["negotiated"], "X25519MLKEM768");
    assert_eq!(value["connected"], true);
    assert_eq!(value["elapsed_ms"], 7);
    let verdict = serde_json::to_value(Verdict::NoPostQuantum).unwrap_or_default();
    assert_eq!(verdict["verdict"], "no_post_quantum");
    let rejected = serde_json::to_value(GroupResult::new(ProbeGroup::X25519, rejected(), true, 1)).unwrap_or_default();
    assert_eq!(rejected["status"], "rejected");
    assert_eq!(rejected["alert"], "handshake_failure");
}
