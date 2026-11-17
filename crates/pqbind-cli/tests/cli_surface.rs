// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Run the real `pqbind` binary as a child process and check what a user sees: help, exit codes, key files, the demo and a server with a client.
//!
//! These tests protect the command line surface across refactors, and they run the binary with its default stacks, so a change that makes
//! a command need more stack than the defaults give fails here instead of on a user's machine.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

fn pqbind() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pqbind"))
}

fn run(arguments: &[&str]) -> Output {
    pqbind().args(arguments).output().expect("the pqbind binary runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("the process ended with an exit code")
}

/// A fresh directory under the system temp directory that removes itself.
struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("pqbind-cli-surface-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a temporary directory");
        Self(path)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn text(path: &Path) -> String {
    path.to_str().expect("a path that is text").to_owned()
}

#[test]
fn help_lists_the_six_subcommands_and_exits_zero() {
    let output = run(&["--help"]);
    assert_eq!(code(&output), 0);
    let help = stdout(&output);
    for name in ["demo", "serve", "verify", "keygen", "enroll", "probe"] {
        assert!(help.contains(name), "{name} is missing from the help:\n{help}");
    }
}

#[test]
fn the_version_is_printed_to_stdout() {
    let output = run(&["--version"]);
    assert_eq!(code(&output), 0);
    assert!(stdout(&output).starts_with("pqbind "), "{}", stdout(&output));
}

#[test]
fn a_usage_error_exits_two_and_writes_to_stderr() {
    for arguments in [&[][..], &["nope"], &["demo", "--transport", "udp"], &["serve", "--listen", "127.0.0.1:1"]] {
        let output = run(arguments);
        assert_eq!(code(&output), 2, "{arguments:?}");
        assert!(!stderr(&output).is_empty(), "{arguments:?}");
    }
}

#[test]
fn keygen_writes_the_files_prints_the_pin_and_never_overwrites() {
    let dir = Dir::new("keygen");
    let seed = text(&dir.file("client.seed"));
    let public = text(&dir.file("client.pub"));
    let output = run(&["keygen", "--out", &seed, "--public-out", &public]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let printed = stdout(&output);
    assert!(printed.contains("pin:") && printed.contains("seed file:") && printed.contains("public key:"), "{printed}");
    assert!(dir.file("client.seed").exists() && dir.file("client.pub").exists());

    let again = run(&["keygen", "--out", &seed]);
    assert_eq!(code(&again), 2);
    assert!(stderr(&again).contains("refusing to overwrite"), "{}", stderr(&again));
}

#[test]
fn verify_without_a_ca_exits_two_and_names_the_option() {
    let dir = Dir::new("verify-no-ca");
    let seed = text(&dir.file("client.seed"));
    assert_eq!(code(&run(&["keygen", "--out", &seed])), 0);
    let pin = "ab".repeat(48);
    let output = run(&["verify", "127.0.0.1:9", "--pin", &pin, "--identity", &seed, "--json"]);
    assert_eq!(code(&output), 2);
    let json = stdout(&output);
    assert!(json.contains("\"result\":\"error\"") && json.contains("--ca"), "{json}");
}

#[test]
fn probe_exits_two_for_an_address_it_cannot_use() {
    let output = run(&["probe", "127.0.0.1:0"]);
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("pqbind probe"), "{}", stderr(&output));
}

#[test]
fn the_demo_passes_over_both_transports_with_the_default_stacks() {
    for transport in ["quic", "tls"] {
        let output = run(&["demo", "--transport", transport]);
        assert_eq!(code(&output), 0, "{transport}: {}{}", stdout(&output), stderr(&output));
        assert!(stdout(&output).contains("All 8 scenarios behaved as expected."), "{transport}");
    }
}

/// A running `pqbind serve` that is killed when this value drops.
struct Server {
    child: Child,
    listening: String,
    pin: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start `pqbind serve` on loopback port 0 and read its address and pin from what it prints.
fn start_server(dir: &Dir, transport: &str, enroll: &Path) -> Server {
    start_server_with(dir, transport, "--enroll", enroll)
}

/// Start `pqbind serve` with `flag` (`--enroll` or `--registry`) naming the file of enrolled clients.
fn start_server_with(dir: &Dir, transport: &str, flag: &str, enrolled: &Path) -> Server {
    let mut child = pqbind()
        .args(["serve", "--listen", "127.0.0.1:0", "--transport", transport])
        .arg("--identity")
        .arg(dir.file(&format!("server-{transport}.seed")))
        .arg(flag)
        .arg(enrolled)
        .arg("--cert-out")
        .arg(dir.file(&format!("server-{transport}.pem")))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the server starts");
    let lines = BufReader::new(child.stdout.take().expect("a piped stdout")).lines();
    let (sender, receiver) = mpsc::channel();
    // The thread keeps reading until the server ends, so the server never writes to a closed pipe (its log lines would panic it).
    std::thread::spawn(move || {
        for line in lines.map_while(Result::ok) {
            let _ = sender.send(line);
        }
    });
    let (mut listening, mut pin) = (String::new(), String::new());
    while let Ok(line) = receiver.recv_timeout(Duration::from_secs(60)) {
        if let Some(rest) = line.trim().strip_prefix("listening:") {
            listening = rest.trim().to_owned();
        } else if let Some(rest) = line.trim().strip_prefix("server pin:") {
            pin = rest.trim().to_owned();
        } else if line.contains("Waiting for connections") {
            break;
        }
    }
    assert!(!listening.is_empty() && pin.len() == 96, "the server did not say where it listens: {listening:?} {pin:?}");
    Server { child, listening, pin }
}

#[test]
fn a_server_authenticates_an_enrolled_client_and_refuses_a_stranger_with_the_default_stacks() {
    for transport in ["quic", "tls"] {
        let dir = Dir::new(&format!("serve-{transport}"));
        let (enrolled_seed, enrolled_pub) = (text(&dir.file("enrolled.seed")), text(&dir.file("enrolled.pub")));
        let stranger_seed = text(&dir.file("stranger.seed"));
        assert_eq!(code(&run(&["keygen", "--out", &enrolled_seed, "--public-out", &enrolled_pub])), 0);
        assert_eq!(code(&run(&["keygen", "--out", &stranger_seed])), 0);
        let server = start_server(&dir, transport, &dir.file("enrolled.pub"));
        let ca = text(&dir.file(&format!("server-{transport}.pem")));

        let verify = |seed: &str| {
            run(&["verify", &server.listening, "--pin", &server.pin, "--identity", seed, "--ca", &ca, "--transport", transport, "--json"])
        };
        let good = verify(&enrolled_seed);
        assert_eq!(code(&good), 0, "{transport}: {}{}", stdout(&good), stderr(&good));
        assert!(stdout(&good).contains("\"result\":\"verified\""), "{transport}: {}", stdout(&good));
        let bad = verify(&stranger_seed);
        assert_eq!(code(&bad), 1, "{transport}: {}{}", stdout(&bad), stderr(&bad));
        assert!(stdout(&bad).contains("\"result\":\"refused\""), "{transport}: {}", stdout(&bad));
    }
}

#[test]
fn enroll_checks_the_pin_lists_and_revokes_through_the_real_binary() {
    let dir = Dir::new("enroll-surface");
    let (seed, public, registry) = (text(&dir.file("c.seed")), text(&dir.file("c.pub")), text(&dir.file("clients.reg")));
    let made = run(&["keygen", "--out", &seed, "--public-out", &public]);
    let pin = stdout(&made)
        .lines()
        .find_map(|line| line.trim().strip_prefix("pin:").map(|rest| rest.trim().to_owned()))
        .expect("keygen prints the pin");
    assert_eq!(pin.len(), 96, "{pin}");

    // Without a terminal and without a pin, nothing is enrolled.
    let unchecked = run(&["enroll", "add", "--registry", &registry, "--key", &public]);
    assert_eq!(code(&unchecked), 2);
    assert!(stderr(&unchecked).contains("--pin"), "{}", stderr(&unchecked));
    assert!(!dir.file("clients.reg").exists());

    // A wrong pin is refused, and the right one enrolls.
    let wrong = run(&["enroll", "add", "--registry", &registry, "--key", &public, "--pin", &"00".repeat(48)]);
    assert_eq!(code(&wrong), 2);
    assert!(stderr(&wrong).contains("does not match"), "{}", stderr(&wrong));
    let added = run(&["enroll", "add", "--registry", &registry, "--key", &public, "--pin", &pin]);
    assert_eq!(code(&added), 0, "{}", stderr(&added));
    let listed = run(&["enroll", "list", "--registry", &registry]);
    assert!(stdout(&listed).contains(&pin), "{}", stdout(&listed));

    // A server that reads the registry authenticates the client over both transports.
    let attempt = |server: &Server, transport: &str| {
        let ca = text(&dir.file(&format!("server-{transport}.pem")));
        run(&["verify", &server.listening, "--pin", &server.pin, "--identity", &seed, "--ca", &ca, "--transport", transport, "--json"])
    };
    for transport in ["quic", "tls"] {
        let server = start_server_with(&dir, transport, "--registry", &dir.file("clients.reg"));
        let good = attempt(&server, transport);
        assert_eq!(code(&good), 0, "{transport}: {}{}", stdout(&good), stderr(&good));
    }

    // After the revoke, a server that is started again refuses the same client over both transports.
    let revoked = run(&["enroll", "revoke", "--registry", &registry, "--pin", &pin[..24]]);
    assert_eq!(code(&revoked), 0, "{}", stderr(&revoked));
    assert!(stdout(&revoked).contains("restart"), "{}", stdout(&revoked));
    let empty = run(&["enroll", "list", "--registry", &registry]);
    assert!(stdout(&empty).contains("no clients"), "{}", stdout(&empty));
    for transport in ["quic", "tls"] {
        let server = start_server_with(&dir, transport, "--registry", &dir.file("clients.reg"));
        let bad = attempt(&server, transport);
        assert_eq!(code(&bad), 1, "{transport}: {}{}", stdout(&bad), stderr(&bad));
        assert!(stdout(&bad).contains("\"result\":\"refused\""), "{transport}: {}", stdout(&bad));
    }
}

#[test]
fn serve_refuses_a_registry_that_is_missing_or_damaged_instead_of_starting_with_nobody_enrolled() {
    let dir = Dir::new("serve-bad-registry");
    let (identity, missing) = (text(&dir.file("s.seed")), text(&dir.file("none.reg")));
    let output = run(&["serve", "--listen", "127.0.0.1:0", "--identity", &identity, "--registry", &missing]);
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("pqbind enroll add"), "{}", stderr(&output));
    std::fs::write(dir.file("damaged.reg"), [1, 0, 0, 0, 9]).expect("write");
    let damaged = run(&["serve", "--listen", "127.0.0.1:0", "--identity", &identity, "--registry", &text(&dir.file("damaged.reg"))]);
    assert_eq!(code(&damaged), 2);
    assert!(stderr(&damaged).contains("damaged"), "{}", stderr(&damaged));
}
