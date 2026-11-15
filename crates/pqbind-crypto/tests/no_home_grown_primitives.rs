// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Check that this crate contains no hand-written cryptographic primitive: no known primitive constants in the source, and no dependency outside a short list of established crates.
//!
//! This is a guard, not a proof. It catches the usual ways a primitive sneaks in (an S-box, a hash initial value, a round constant, a
//! lattice modulus) and a new dependency nobody decided on. Each check has a positive control that shows the scanner finds what it
//! looks for.

use std::fs;
use std::path::{Path, PathBuf};

/// Fragments of well-known primitive constants. Finding one in `src/` means someone wrote a primitive by hand.
const FORBIDDEN_FRAGMENTS: &[(&str, &str)] = &[
    ("0x6a09e667", "SHA-256 initial hash value"),
    ("0xbb67ae85", "SHA-256 initial hash value"),
    ("0xcbbb9d5d", "SHA-384 initial hash value"),
    ("0x428a2f98", "SHA-256 round constant"),
    ("0xd728ae22", "SHA-512 round constant"),
    ("0x7c, 0x77, 0x7b", "AES S-box"),
    ("0x8000000080008000", "Keccak round constant"),
    ("0x0000000000008082", "Keccak round constant"),
    ("0x61707865", "ChaCha sigma word"),
    ("expand 32-byte k", "ChaCha constant"),
    ("8380417", "the ML-DSA modulus"),
    ("0x7fe001", "the ML-DSA modulus"),
    ("0xed, 0xd3, 0xf5, 0x5c", "the Ed25519 group order"),
];

/// The only crates this crate may depend on. Adding one is a decision, so it must be added here on purpose.
const ALLOWED_DEPENDENCIES: &[&str] = &["ed25519-dalek", "hkdf", "ml-dsa", "rand", "sha2", "thiserror", "zeroize"];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

/// The part of a source file that ships: everything before its `#[cfg(test)]` module. A test may hold a primitive constant on purpose
/// (the Ed25519 group order, to build a malleated signature that must be refused); only shipped code must not.
fn production_part(text: &str) -> &str {
    text.split("\n#[cfg(test)]").next().unwrap_or(text)
}

/// The forbidden fragments `text` contains, as (fragment, what it is).
fn forbidden_in(text: &str) -> Vec<(&'static str, &'static str)> {
    let lowered = text.to_ascii_lowercase();
    FORBIDDEN_FRAGMENTS.iter().filter(|(fragment, _)| lowered.contains(&fragment.to_ascii_lowercase())).copied().collect()
}

/// The names under `[dependencies]` in a manifest.
fn dependencies_of(manifest: &str) -> Vec<String> {
    let mut in_section = false;
    let mut names = Vec::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_section = line == "[dependencies]";
            continue;
        }
        if in_section && !line.is_empty() && !line.starts_with('#') {
            if let Some((name, _)) = line.split_once('=') {
                names.push(name.trim().to_owned());
            }
        }
    }
    names
}

#[test]
fn the_scanner_finds_each_kind_of_primitive_it_looks_for() {
    // Positive controls: if these did not fire, the real scan below would prove nothing.
    for (fragment, what) in FORBIDDEN_FRAGMENTS {
        let sample = format!("const TABLE: u64 = {fragment};");
        assert!(forbidden_in(&sample).iter().any(|(found, _)| found == fragment), "the scanner misses {what}");
    }
    assert!(forbidden_in("let digest = Sha384::digest(data);").is_empty(), "ordinary code is not flagged");
    // The production-code filter: a constant in a test module is skipped, the same constant before it is still caught.
    let in_tests = "fn real() {}\n#[cfg(test)]\nmod tests { const L: [u8; 4] = [0xed, 0xd3, 0xf5, 0x5c]; }\n";
    let in_production = "const L: [u8; 4] = [0xed, 0xd3, 0xf5, 0x5c];\nfn real() {}\n#[cfg(test)]\nmod tests {}\n";
    assert!(forbidden_in(production_part(in_tests)).is_empty(), "a test-only constant is not flagged");
    assert!(!forbidden_in(production_part(in_production)).is_empty(), "the same constant in shipped code is flagged");
    assert_eq!(
        dependencies_of(
            "[package]\nname = \"x\"\n[dependencies]\nfoo = \"1\"\n# note\nbar = { workspace = true }\n[dev-dependencies]\nbaz = \"1\"\n"
        ),
        ["foo", "bar"]
    );
}

#[test]
fn no_source_file_contains_a_known_primitive_constant() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    assert!(files.len() >= 8, "the scan found the crate's source files");
    for file in files {
        let text = fs::read_to_string(&file).expect("a readable source file");
        let found = forbidden_in(production_part(&text));
        assert!(found.is_empty(), "{} contains a primitive constant: {found:?}", file.display());
    }
}

#[test]
fn the_crate_depends_only_on_the_allowed_crates() {
    let manifest = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).expect("the manifest");
    let dependencies = dependencies_of(&manifest);
    assert!(!dependencies.is_empty(), "the scan found the dependency list");
    for name in &dependencies {
        assert!(ALLOWED_DEPENDENCIES.contains(&name.as_str()), "`{name}` is not an allowed dependency; add it to the list on purpose");
    }
}
