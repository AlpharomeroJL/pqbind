// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Print the demo to the terminal: the introduction, each scenario as a story as it finishes, and the summary table.

use super::report::{Report, ScenarioResult};
use crate::common::Transport;

/// The paragraph under the title, which says what the demo assumes.
const INTRO: &str = "A client and a server talk over a connection that already exists. After the transport handshake each signs the connection's own TLS exporter value, both transport identities and both key pins with a hybrid Ed25519 + ML-DSA-87 key. Assume a quantum attacker has broken everything classical: the TLS certificate key and the Ed25519 half of every pqbind key. The scenarios below run each attack for real and show what stops it, and the one thing that cannot be stopped.";

/// Break `text` into lines of at most `width` bytes at white space (a longer word gets a line of its own).
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

fn print_paragraph(label: &str, text: &str) {
    for (index, line) in wrap(text, 84).iter().enumerate() {
        let head = if index == 0 { label } else { "" };
        println!("    {head:<10}{line}");
    }
}

fn verdict_word(passed: bool) -> &'static str {
    if passed { "as expected" } else { "NOT AS EXPECTED" }
}

/// Print the title and the introduction.
pub fn print_intro(transport: Transport) {
    println!("pqbind demo (transport: {}; everything stays on 127.0.0.1)", transport.name());
    println!();
    for line in wrap(INTRO, 96) {
        println!("{line}");
    }
    println!();
}

/// Print one scenario as a story, as it finishes.
pub fn print_scenario(result: &ScenarioResult) {
    println!("[{}] {}", result.id, result.title);
    print_paragraph("Story:", result.story);
    print_paragraph("Expected:", &format!("{} ({})", result.expected, result.expected_short));
    for (index, line) in result.observed.iter().enumerate() {
        print_paragraph(if index == 0 { "Observed:" } else { "" }, line);
    }
    print_paragraph("Verdict:", verdict_word(result.passed));
    if let Some(note) = result.note {
        print_paragraph("Note:", note);
    }
    println!();
}

/// Print the summary table and the closing line.
pub fn print_summary(report: &Report) {
    println!("Summary (transport: {})", report.transport.name());
    println!("{:<4}{:<70}{:<46}{:<46}Verdict", "ID", "Scenario", "Expected", "Observed");
    for scenario in &report.scenarios {
        println!(
            "{:<4}{:<70}{:<46}{:<46}{}",
            scenario.id,
            scenario.title,
            scenario.expected_short,
            scenario.observed_short,
            verdict_word(scenario.passed)
        );
    }
    println!();
    let failed = report.scenarios.iter().filter(|scenario| !scenario.passed).count();
    if failed == 0 {
        println!("All {} scenarios behaved as expected.", report.scenarios.len());
    } else {
        println!("{failed} of {} scenarios did NOT behave as expected.", report.scenarios.len());
    }
}

#[cfg(test)]
mod tests {
    use super::wrap;

    #[test]
    fn text_wraps_at_white_space_without_losing_words() {
        let lines = wrap("one two three four five", 9);
        assert_eq!(lines, ["one two", "three", "four five"]);
        assert!(lines.iter().all(|line| line.len() <= 9));
        assert_eq!(wrap("a verylongwordthatdoesnotfit b", 5), ["a", "verylongwordthatdoesnotfit", "b"]);
        assert!(wrap("   ", 10).is_empty());
    }
}
