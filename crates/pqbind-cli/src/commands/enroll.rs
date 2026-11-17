// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Run `pqbind enroll`: add a client's public key to the enrolled-clients file after the user has checked its pin, list the file and revoke a client.
//!
//! `add` never enrolls a key unchecked. The user either passes the pin the key's owner gave them, which must match the key, or types
//! `yes` after reading the pin the command prints. When the command cannot ask (input is not a terminal) and no pin was given, it refuses.
//! Clients are enrolled for the anonymous transport identity, which is what `serve` uses.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Subcommand;
use pqbind::{Enrollment, PeerId, Pin};

use crate::common::{CliError, CliResult, from_hex, now_millis, to_hex};
use crate::keyfiles::load_public;
use crate::registry_file::{load, load_or_new, save};

/// The fewest hex digits of a pin that `revoke` accepts, so a short prefix cannot match by accident.
const MIN_PIN_PREFIX: usize = 16;

/// The arguments of `pqbind enroll`.
#[derive(Debug, clap::Args)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

/// What to do with the enrolled-clients file.
#[derive(Debug, Subcommand)]
pub enum Action {
    /// Enroll a client's public key (from `keygen --public-out`) after you have checked its pin.
    Add(AddArgs),
    /// List the enrolled clients.
    List(ListArgs),
    /// Revoke an enrolled client by its pin.
    Revoke(RevokeArgs),
}

/// The arguments of `pqbind enroll add`.
#[derive(Debug, clap::Args)]
pub struct AddArgs {
    /// The enrolled-clients file. It is created when it does not exist.
    #[arg(long)]
    pub registry: PathBuf,
    /// The client's public key file.
    #[arg(long)]
    pub key: PathBuf,
    /// The pin the key's owner gave you (96 hex digits). It must match the key. Without it the command shows the pin and asks you to confirm.
    #[arg(long)]
    pub pin: Option<String>,
}

/// The arguments of `pqbind enroll list`.
#[derive(Debug, clap::Args)]
pub struct ListArgs {
    /// The enrolled-clients file.
    #[arg(long)]
    pub registry: PathBuf,
}

/// The arguments of `pqbind enroll revoke`.
#[derive(Debug, clap::Args)]
pub struct RevokeArgs {
    /// The enrolled-clients file.
    #[arg(long)]
    pub registry: PathBuf,
    /// The pin of the client to revoke: all 96 hex digits, or the first 16 or more when they identify one client.
    #[arg(long)]
    pub pin: String,
}

/// Run `pqbind enroll`.
pub fn run(args: &Args) -> ExitCode {
    let result = match &args.action {
        Action::Add(add_args) => add(add_args, std::io::stdin().is_terminal(), &mut ask_on_terminal),
        Action::List(list_args) => list(list_args),
        Action::Revoke(revoke_args) => revoke(revoke_args),
    };
    match result {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("pqbind enroll: {error}");
            ExitCode::from(2)
        }
    }
}

/// Show the pin and read one line; only `yes` confirms.
fn ask_on_terminal(pin: &Pin) -> bool {
    println!("This key has the pin:\n  {}", pin.to_hex());
    println!("Compare it with the pin the key's owner gave you, through a channel you trust.");
    print!("Enroll this key? Type yes to confirm: ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).is_ok() && line.trim() == "yes"
}

/// Enroll a key. `interactive` says whether `confirm` can reach a person.
pub fn add(args: &AddArgs, interactive: bool, confirm: &mut dyn FnMut(&Pin) -> bool) -> CliResult<String> {
    let key = load_public(&args.key)?;
    let pin = key.pin();
    match &args.pin {
        Some(text) => {
            let given =
                Pin::from_hex(text.trim()).map_err(|_| CliError::new("--pin must be 96 hex digits, the pin the key's owner gave you"))?;
            if given != pin {
                return Err(CliError::new(format!(
                    "the pin you gave does not match the key in {} (that key has pin {}); nothing was enrolled",
                    args.key.display(),
                    pin.to_hex()
                )));
            }
        }
        None if !interactive => {
            return Err(CliError::new(
                "cannot ask you to confirm the pin because input is not a terminal; pass --pin with the pin the key's owner gave you, \
                 so that a key is never enrolled unchecked",
            ));
        }
        None => {
            if !confirm(&pin) {
                return Err(CliError::new("not confirmed; nothing was enrolled"));
            }
        }
    }
    let (registry, _) = load_or_new(&args.registry)?;
    if registry.list().iter().any(|entry| entry.key == key && entry.peer_id == PeerId::anonymous()) {
        return Ok(format!("already enrolled: {}\n  {} client(s) in {}", pin.to_hex(), registry.len(), args.registry.display()));
    }
    registry.enroll(Enrollment { key, peer_id: PeerId::anonymous(), enrolled_at_unix_millis: now_millis() });
    save(&args.registry, &registry)?;
    Ok(format!("enrolled: {}\n  {} client(s) in {}", pin.to_hex(), registry.len(), args.registry.display()))
}

/// List the enrolled clients, one per line.
pub fn list(args: &ListArgs) -> CliResult<String> {
    let registry = load(&args.registry)?;
    let entries = registry.list();
    if entries.is_empty() {
        return Ok(format!("no clients are enrolled in {}", args.registry.display()));
    }
    let mut lines = vec![format!("{} client(s) in {}", entries.len(), args.registry.display())];
    for entry in &entries {
        let id =
            if entry.peer_id == PeerId::anonymous() { "anonymous".to_owned() } else { format!("id {}", to_hex(entry.peer_id.as_bytes())) };
        lines.push(format!("  {}  {}  enrolled {}", entry.key.pin().to_hex(), id, utc_date(entry.enrolled_at_unix_millis)));
    }
    Ok(lines.join("\n"))
}

/// Revoke the one client whose pin starts with `args.pin`.
pub fn revoke(args: &RevokeArgs) -> CliResult<String> {
    let prefix = args.pin.trim().to_ascii_lowercase();
    if prefix.len() < MIN_PIN_PREFIX
        || prefix.len() > 96
        || from_hex(&format!("{prefix}{}", if prefix.len() % 2 == 1 { "0" } else { "" })).is_none()
    {
        return Err(CliError::new(format!("--pin must be {MIN_PIN_PREFIX} to 96 hex digits of the client's pin")));
    }
    let registry = load(&args.registry)?;
    let matches: Vec<Enrollment> = registry.list().into_iter().filter(|entry| entry.key.pin().to_hex().starts_with(&prefix)).collect();
    let [entry] = matches.as_slice() else {
        return Err(CliError::new(if matches.is_empty() {
            format!("no enrolled client has a pin starting with {prefix}")
        } else {
            format!("{} enrolled clients have a pin starting with {prefix}; give more digits", matches.len())
        }));
    };
    registry.revoke(&entry.key, &entry.peer_id);
    save(&args.registry, &registry)?;
    Ok(format!(
        "revoked: {}\n  {} client(s) left in {}\n  A running `pqbind serve` reads the file only when it starts: restart it for the revocation to apply.",
        entry.key.pin().to_hex(),
        registry.len(),
        args.registry.display()
    ))
}

/// A date such as `2026-11-17` (UTC) for milliseconds since the Unix epoch.
fn utc_date(unix_millis: i64) -> String {
    let days = unix_millis.div_euclid(86_400_000);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 { shifted_month + 3 } else { shifted_month - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use pqbind::HybridIdentity;

    use super::{AddArgs, ListArgs, RevokeArgs, add, list, revoke, utc_date};
    use crate::keyfiles::write_public;
    use crate::testutil::TempDir;

    fn key_file(dir: &Path, name: &str, fill: u8) -> (std::path::PathBuf, String) {
        let identity = HybridIdentity::from_seed(&[fill; 32]).expect("seed");
        let path = dir.join(name);
        write_public(&path, &identity.public()).expect("public key file");
        (path, identity.pin().to_hex())
    }

    fn add_args(dir: &Path, key: &Path, pin: Option<&str>) -> AddArgs {
        AddArgs { registry: dir.join("clients.reg"), key: key.to_path_buf(), pin: pin.map(str::to_owned) }
    }

    fn never(_: &pqbind::Pin) -> bool {
        panic!("the command must not ask here")
    }

    #[test]
    fn a_key_with_the_right_pin_is_enrolled_and_listed() {
        let dir = TempDir::new("enroll-add");
        let (key, pin) = key_file(dir.path(), "a.pub", 1);
        let report = add(&add_args(dir.path(), &key, Some(&pin)), false, &mut never).expect("enrolled");
        assert!(report.starts_with("enrolled:") && report.contains("1 client(s)"), "{report}");
        let listed = list(&ListArgs { registry: dir.path().join("clients.reg") }).expect("list");
        assert!(listed.contains(&pin) && listed.contains("anonymous"), "{listed}");
        let again = add(&add_args(dir.path(), &key, Some(&pin.to_uppercase())), false, &mut never).expect("again");
        assert!(again.starts_with("already enrolled"), "an upper-case pin matches and a second add changes nothing: {again}");
    }

    #[test]
    fn a_pin_that_does_not_match_the_key_enrolls_nothing() {
        let dir = TempDir::new("enroll-wrong-pin");
        let (key, _) = key_file(dir.path(), "a.pub", 1);
        let (_, other_pin) = key_file(dir.path(), "b.pub", 2);
        let error = add(&add_args(dir.path(), &key, Some(&other_pin)), false, &mut never).expect_err("mismatch");
        assert!(error.to_string().contains("does not match"), "{error}");
        let error = add(&add_args(dir.path(), &key, Some("abc")), false, &mut never).expect_err("not a pin");
        assert!(error.to_string().contains("96 hex digits"), "{error}");
        assert!(!dir.path().join("clients.reg").exists(), "no registry file was made");
    }

    #[test]
    fn without_a_pin_the_key_is_enrolled_only_if_a_person_confirms_it() {
        let dir = TempDir::new("enroll-confirm");
        let (key, pin) = key_file(dir.path(), "a.pub", 1);
        let args = add_args(dir.path(), &key, None);
        let error = add(&args, false, &mut never).expect_err("no terminal");
        assert!(error.to_string().contains("--pin"), "{error}");
        let mut shown = None;
        let error = add(&args, true, &mut |pin: &pqbind::Pin| {
            shown = Some(pin.to_hex());
            false
        })
        .expect_err("declined");
        assert!(error.to_string().contains("not confirmed"), "{error}");
        assert_eq!(shown.as_deref(), Some(pin.as_str()), "the person was shown this key's pin");
        assert!(!dir.path().join("clients.reg").exists(), "a declined key leaves no file");
        assert!(add(&args, true, &mut |_: &pqbind::Pin| true).is_ok());
    }

    #[test]
    fn revoke_takes_one_client_off_by_a_pin_prefix_and_refuses_unclear_prefixes() {
        let dir = TempDir::new("enroll-revoke");
        let (first, first_pin) = key_file(dir.path(), "a.pub", 1);
        let (second, second_pin) = key_file(dir.path(), "b.pub", 2);
        add(&add_args(dir.path(), &first, Some(&first_pin)), false, &mut never).expect("first");
        add(&add_args(dir.path(), &second, Some(&second_pin)), false, &mut never).expect("second");
        let registry = dir.path().join("clients.reg");
        let revoke_with = |pin: &str| revoke(&RevokeArgs { registry: registry.clone(), pin: pin.to_owned() });
        assert!(revoke_with("abc").is_err(), "too short");
        assert!(revoke_with(&"z".repeat(20)).is_err(), "not hex");
        assert!(revoke_with(&"0".repeat(96)).expect_err("none").to_string().contains("no enrolled client"));
        let report = revoke_with(&first_pin[..20]).expect("revoked");
        assert!(report.contains("1 client(s) left") && report.contains("restart"), "{report}");
        let listed = list(&ListArgs { registry }).expect("list");
        assert!(!listed.contains(&first_pin) && listed.contains(&second_pin), "{listed}");
    }

    #[test]
    fn dates_are_utc_calendar_dates() {
        assert_eq!(utc_date(0), "1970-01-01");
        assert_eq!(utc_date(951_782_400_000), "2000-02-29");
        assert_eq!(utc_date(1_795_000_000_000), "2026-11-18");
        assert_eq!(utc_date(-1), "1969-12-31");
    }
}
