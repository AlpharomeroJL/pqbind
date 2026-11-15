// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Hold the probe's results for each host and render them as a table or as one JSON document.

use serde::Serialize;

use super::classify::{GroupResult, Verdict};

/// What the output says about certificates, in the table and in the JSON.
pub const CERTIFICATE_NOTE: &str = "certificate not validated";

/// Everything the probe found about one host.
#[derive(Clone, Debug, Serialize)]
pub struct HostReport {
    /// The host exactly as the user typed it.
    pub host: String,
    pub port: u16,
    #[serde(flatten)]
    pub verdict: Verdict,
    /// An explanation of the verdict, where one is needed. For `pq_intolerant` it says the verdict is a heuristic.
    pub note: Option<String>,
    pub groups: Vec<GroupResult>,
    pub elapsed_ms: u64,
}

/// The whole JSON document.
#[derive(Debug, Serialize)]
pub struct Report<'a> {
    pub tool: &'static str,
    pub certificate_validated: bool,
    pub certificate_note: &'static str,
    pub hosts: &'a [HostReport],
    pub exit_code: u8,
}

/// The JSON document for these hosts, as one pretty-printed string.
pub fn render_json(hosts: &[HostReport], exit_code: u8) -> Result<String, serde_json::Error> {
    let report = Report { tool: "pqbind probe", certificate_validated: false, certificate_note: CERTIFICATE_NOTE, hosts, exit_code };
    serde_json::to_string_pretty(&report)
}

/// The human-readable table for these hosts.
#[must_use]
pub fn render_table(hosts: &[HostReport]) -> String {
    let mut out = format!("pqbind probe ({CERTIFICATE_NOTE}: only the key exchange is tested)\n");
    for host in hosts {
        out.push('\n');
        out.push_str(&format!("{}\n", host.host));
        out.push_str(&format!("  verdict: {}\n", host.verdict.label()));
        if let Some(note) = &host.note {
            out.push_str(&format!("  note: {note}\n"));
        }
        let rows: Vec<(String, String, String)> = host
            .groups
            .iter()
            .map(|group| (group.group.name().to_owned(), group.outcome.describe(), format!("{} ms", group.elapsed_ms)))
            .collect();
        let name_width = rows.iter().map(|row| row.0.len()).max().unwrap_or(0);
        let result_width = rows.iter().map(|row| row.1.len()).max().unwrap_or(0);
        for (name, result, time) in &rows {
            out.push_str(&format!("  {name:<name_width$}  {result:<result_width$}  {time}\n"));
        }
        out.push_str(&format!("  total: {} ms\n", host.elapsed_ms));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::probe::classify::{Outcome, ProbeGroup};

    fn sample() -> HostReport {
        let verdict = Verdict::PqIntolerant;
        HostReport {
            host: "example.test:443".to_owned(),
            port: 443,
            note: verdict.note().map(str::to_owned),
            verdict,
            groups: vec![
                GroupResult::new(ProbeGroup::X25519MlKem768, Outcome::Reset, true, 3),
                GroupResult::new(ProbeGroup::X25519, Outcome::Accepted { negotiated: Some("X25519".to_owned()) }, true, 4),
            ],
            elapsed_ms: 9,
        }
    }

    #[test]
    fn the_table_says_the_certificate_is_not_validated_and_the_verdict_is_a_heuristic() {
        let table = render_table(&[sample()]);
        assert!(table.contains("certificate not validated"));
        assert!(table.contains("Heuristic"));
        assert!(table.contains("example.test:443"));
        assert!(table.contains("reset (closed with no alert)"));
        assert!(!table.contains('\u{2014}'));
    }

    #[test]
    fn a_pq_capable_hosts_json_has_no_duplicate_keys() {
        // Regression: the verdict's list of accepted PQ groups used to be flattened into the host object under the key `groups`,
        // next to the per-group results, which also used `groups`. A parser then silently dropped one of them.
        let verdict = Verdict::PqCapable { groups: vec![ProbeGroup::X25519MlKem768] };
        let host = HostReport {
            host: "example.test:443".to_owned(),
            port: 443,
            note: verdict.note().map(str::to_owned),
            verdict,
            groups: vec![GroupResult::new(
                ProbeGroup::X25519MlKem768,
                Outcome::Accepted { negotiated: Some("X25519MLKEM768".to_owned()) },
                true,
                3,
            )],
            elapsed_ms: 3,
        };
        let json = render_json(&[host], 0).unwrap_or_default();
        assert_eq!(json.matches("\"groups\"").count(), 1, "the key `groups` appears once in the host object: {json}");
        let value: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
        assert_eq!(value["hosts"][0]["verdict"], "pq_capable");
        assert_eq!(value["hosts"][0]["pq_groups"][0], "X25519MLKEM768");
        assert_eq!(value["hosts"][0]["groups"][0]["group"], "X25519MLKEM768");
    }

    #[test]
    fn the_json_has_the_verdict_the_groups_and_the_elapsed_time() {
        let json = render_json(&[sample()], 1).unwrap_or_default();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
        assert_eq!(value["certificate_validated"], false);
        assert_eq!(value["certificate_note"], "certificate not validated");
        assert_eq!(value["exit_code"], 1);
        let host = &value["hosts"][0];
        assert_eq!(host["verdict"], "pq_intolerant");
        assert_eq!(host["host"], "example.test:443");
        assert_eq!(host["elapsed_ms"], 9);
        assert_eq!(host["groups"][0]["group"], "X25519MLKEM768");
        assert_eq!(host["groups"][0]["status"], "reset");
        assert_eq!(host["groups"][1]["status"], "accepted");
    }
}
