// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Name the groups the probe tries, record what each attempt ended in, and turn the per-group results of one host into a verdict and an exit code. Pure functions only: no sockets, no TLS library.

use serde::{Serialize, Serializer};

/// What kind of key exchange a group is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupKind {
    /// A classical elliptic-curve group and ML-KEM joined (post-quantum).
    Hybrid,
    /// ML-KEM alone (post-quantum, not hybrid).
    PureMlKem,
    /// A classical group, the baseline.
    Classical,
}

/// A TLS 1.3 key exchange group the probe offers, one at a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeGroup {
    X25519MlKem768,
    SecP256r1MlKem768,
    SecP384r1MlKem1024,
    MlKem1024,
    X25519,
    Secp256r1,
}

impl ProbeGroup {
    /// Every group, in the order the probe tries them: hybrids, then pure ML-KEM, then the classical baselines.
    pub const ALL: [ProbeGroup; 6] = [
        ProbeGroup::X25519MlKem768,
        ProbeGroup::SecP256r1MlKem768,
        ProbeGroup::SecP384r1MlKem1024,
        ProbeGroup::MlKem1024,
        ProbeGroup::X25519,
        ProbeGroup::Secp256r1,
    ];

    /// The IANA TLS Supported Groups code point.
    #[must_use]
    pub fn code_point(self) -> u16 {
        match self {
            ProbeGroup::X25519MlKem768 => 0x11ec,
            ProbeGroup::SecP256r1MlKem768 => 0x11eb,
            ProbeGroup::SecP384r1MlKem1024 => 0x11ed,
            ProbeGroup::MlKem1024 => 0x0202,
            ProbeGroup::X25519 => 0x001d,
            ProbeGroup::Secp256r1 => 0x0017,
        }
    }

    /// The name shown to the user and written to JSON.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ProbeGroup::X25519MlKem768 => "X25519MLKEM768",
            ProbeGroup::SecP256r1MlKem768 => "SecP256r1MLKEM768",
            ProbeGroup::SecP384r1MlKem1024 => "SecP384r1MLKEM1024",
            ProbeGroup::MlKem1024 => "MLKEM1024",
            ProbeGroup::X25519 => "X25519",
            ProbeGroup::Secp256r1 => "secp256r1",
        }
    }

    /// Hybrid, pure ML-KEM or classical.
    #[must_use]
    pub fn kind(self) -> GroupKind {
        match self {
            ProbeGroup::X25519MlKem768 | ProbeGroup::SecP256r1MlKem768 | ProbeGroup::SecP384r1MlKem1024 => GroupKind::Hybrid,
            ProbeGroup::MlKem1024 => GroupKind::PureMlKem,
            ProbeGroup::X25519 | ProbeGroup::Secp256r1 => GroupKind::Classical,
        }
    }

    /// True for the hybrid groups and pure ML-KEM.
    #[must_use]
    pub fn is_post_quantum(self) -> bool {
        self.kind() != GroupKind::Classical
    }
}

impl Serialize for ProbeGroup {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.name())
    }
}

/// The name of a group from its code point, for the group a server reports having negotiated.
#[must_use]
pub fn group_name_for_code(code: u16) -> String {
    if let Some(group) = ProbeGroup::ALL.iter().find(|group| group.code_point() == code) {
        return group.name().to_owned();
    }
    match code {
        0x0018 => "secp384r1".to_owned(),
        0x0019 => "secp521r1".to_owned(),
        0x0201 => "MLKEM768".to_owned(),
        other => format!("group_0x{other:04x}"),
    }
}

/// The RFC 8446 name of a TLS alert, for example `handshake_failure`.
#[must_use]
pub fn alert_name(code: u8) -> String {
    let name = match code {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        22 => "record_overflow",
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        109 => "missing_extension",
        110 => "unsupported_extension",
        112 => "unrecognized_name",
        113 => "bad_certificate_status_response",
        115 => "unknown_psk_identity",
        116 => "certificate_required",
        120 => "no_application_protocol",
        121 => "encrypted_client_hello_required",
        other => return format!("alert_{other}"),
    };
    name.to_owned()
}

/// The leading identifier of a `Debug` string, in snake case: `PeerIncompatible(Foo)` becomes `peer_incompatible`.
/// Only the type or variant name is kept, so no value (a host name, for example) can leak into an error kind.
#[must_use]
pub fn snake_head(debug: &str) -> String {
    let mut out = String::new();
    for ch in debug.chars().take_while(|ch| ch.is_ascii_alphanumeric()) {
        if ch.is_ascii_uppercase() {
            if !out.is_empty() {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    if out.is_empty() { "unknown".to_owned() } else { out }
}

/// How one attempt ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    /// The handshake completed. `negotiated` is the group rustls reports, when it reports one.
    Accepted { negotiated: Option<String> },
    /// The server answered with a TLS alert.
    Rejected { alert: String },
    /// No answer within the per-attempt timeout.
    TimedOut,
    /// The connection was reset or closed with no alert.
    Reset,
    /// Anything else: a DNS or TCP failure, or a TLS error that was not an alert from the server. `kind` is a short fixed label.
    Error { kind: String },
}

impl Outcome {
    /// True for `Accepted`.
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        matches!(self, Outcome::Accepted { .. })
    }

    /// True for `TimedOut` and `Reset`: the peer said nothing in words.
    #[must_use]
    pub fn is_silent(&self) -> bool {
        matches!(self, Outcome::TimedOut | Outcome::Reset)
    }

    /// One line for the table.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Outcome::Accepted { negotiated: Some(name) } => format!("accepted (negotiated {name})"),
            Outcome::Accepted { negotiated: None } => "accepted".to_owned(),
            Outcome::Rejected { alert } => format!("rejected (alert {alert})"),
            Outcome::TimedOut => "timed out".to_owned(),
            Outcome::Reset => "reset (closed with no alert)".to_owned(),
            Outcome::Error { kind } => format!("error ({kind})"),
        }
    }
}

/// The result of one attempt with one group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GroupResult {
    pub group: ProbeGroup,
    pub kind: GroupKind,
    #[serde(flatten)]
    pub outcome: Outcome,
    /// Whether the TCP connection was established. A host where no attempt connected is unreachable.
    pub connected: bool,
    pub elapsed_ms: u64,
}

impl GroupResult {
    #[must_use]
    pub fn new(group: ProbeGroup, outcome: Outcome, connected: bool, elapsed_ms: u64) -> Self {
        Self { group, kind: group.kind(), outcome, connected, elapsed_ms }
    }
}

/// What the probe concluded about a host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// At least one post-quantum group (hybrid or pure ML-KEM) was accepted.
    PqCapable {
        /// The post-quantum groups the host accepted. It serializes as `pq_groups`, so it does not collide with the host's own `groups`
        /// list of per-group results (two keys of one name in a JSON object are ambiguous, and most parsers keep only the last).
        #[serde(rename = "pq_groups")]
        groups: Vec<ProbeGroup>,
    },
    /// A classical group was accepted and every post-quantum attempt ended in a TLS alert.
    NoPostQuantum,
    /// A classical group was accepted but post-quantum attempts timed out or were reset with no alert. A heuristic.
    PqIntolerant,
    /// No attempt connected at all.
    Unreachable,
    /// The results fit none of the rules above.
    Inconclusive,
}

impl Verdict {
    /// A short label for the table.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Verdict::PqCapable { groups } => {
                let names: Vec<&str> = groups.iter().map(|group| group.name()).collect();
                format!("PQ capable ({})", names.join(", "))
            }
            Verdict::NoPostQuantum => "no post-quantum key exchange".to_owned(),
            Verdict::PqIntolerant => "PQ intolerant (suspected)".to_owned(),
            Verdict::Unreachable => "unreachable".to_owned(),
            Verdict::Inconclusive => "inconclusive".to_owned(),
        }
    }

    /// An explanation to print under the verdict, where one is needed.
    #[must_use]
    pub fn note(&self) -> Option<&'static str> {
        match self {
            Verdict::PqIntolerant => Some(
                "Heuristic: the host completed a classical handshake but timed out or dropped the connection with no alert on the larger post-quantum hello. That suggests a middlebox or server that breaks on a big ClientHello; it is not proof.",
            ),
            Verdict::NoPostQuantum => Some("The host answered each post-quantum attempt with a TLS alert and accepted a classical group."),
            Verdict::Unreachable => Some("No attempt could open a TCP connection."),
            Verdict::Inconclusive => Some("The results do not show whether the host supports post-quantum key exchange."),
            Verdict::PqCapable { .. } => None,
        }
    }
}

/// Classify one host from its per-group results.
#[must_use]
pub fn classify(results: &[GroupResult]) -> Verdict {
    if results.is_empty() {
        return Verdict::Inconclusive;
    }
    let accepted_pq: Vec<ProbeGroup> =
        results.iter().filter(|result| result.group.is_post_quantum() && result.outcome.is_accepted()).map(|result| result.group).collect();
    if !accepted_pq.is_empty() {
        return Verdict::PqCapable { groups: accepted_pq };
    }
    if !results.iter().any(|result| result.connected) {
        return Verdict::Unreachable;
    }
    if !results.iter().any(|result| !result.group.is_post_quantum() && result.outcome.is_accepted()) {
        return Verdict::Inconclusive;
    }
    let pq: Vec<&GroupResult> = results.iter().filter(|result| result.group.is_post_quantum()).collect();
    if pq.is_empty() {
        return Verdict::Inconclusive;
    }
    if pq.iter().all(|result| matches!(result.outcome, Outcome::Rejected { .. })) {
        return Verdict::NoPostQuantum;
    }
    let only_alerts_or_silence = pq.iter().all(|result| matches!(result.outcome, Outcome::Rejected { .. }) || result.outcome.is_silent());
    if only_alerts_or_silence && pq.iter().any(|result| result.outcome.is_silent()) {
        return Verdict::PqIntolerant;
    }
    Verdict::Inconclusive
}

/// The process exit code for a set of host verdicts: 0 when every host is `PqCapable`; 1 when any host is `NoPostQuantum` or
/// `PqIntolerant`; 2 when any host is `Unreachable` or `Inconclusive`. 2 wins over 1. An empty set probed nothing, so it is 2.
#[must_use]
pub fn exit_code(verdicts: &[Verdict]) -> u8 {
    if verdicts.is_empty() || verdicts.iter().any(|verdict| matches!(verdict, Verdict::Unreachable | Verdict::Inconclusive)) {
        return 2;
    }
    if verdicts.iter().any(|verdict| matches!(verdict, Verdict::NoPostQuantum | Verdict::PqIntolerant)) {
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let results: Vec<GroupResult> =
            ProbeGroup::ALL.iter().map(|&group| GroupResult::new(group, Outcome::TimedOut, false, 5000)).collect();
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
        let result =
            GroupResult::new(ProbeGroup::X25519MlKem768, Outcome::Accepted { negotiated: Some("X25519MLKEM768".to_owned()) }, true, 7);
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
}
