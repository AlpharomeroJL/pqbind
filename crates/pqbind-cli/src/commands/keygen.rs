// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Run `pqbind keygen`: make a new hybrid identity, write its seed (and optionally its public key) and print its pin.
//!
//! A seed file is never overwritten: the command stops instead, and it checks both targets before it writes anything.

use std::path::PathBuf;
use std::process::ExitCode;

use pqbind::Pin;

use crate::common::{CliError, CliResult};
use crate::keyfiles::{Permissions, create_identity, write_public};

/// The arguments of `pqbind keygen`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// Where to write the seed (64 hex digits). The command refuses to overwrite an existing file.
    #[arg(long)]
    pub out: PathBuf,
    /// Where to write the public key (hex), for a server to enroll this client with `--enroll`.
    #[arg(long)]
    pub public_out: Option<PathBuf>,
}

/// What `keygen` made.
#[derive(Debug)]
pub struct Made {
    /// The pin of the new identity.
    pub pin: Pin,
    /// What was done about the seed file's permissions.
    pub permissions: Permissions,
}

/// Make a new identity as `args` ask.
pub fn generate(args: &Args) -> CliResult<Made> {
    // Check both targets before writing anything, so a refusal leaves no half-made pair behind.
    for path in std::iter::once(&args.out).chain(args.public_out.as_ref()) {
        if path.exists() {
            return Err(CliError::new(format!(
                "{} already exists; refusing to overwrite it (delete it yourself if you mean to replace it)",
                path.display()
            )));
        }
    }
    let (identity, permissions) = create_identity(&args.out)?;
    if let Some(public_out) = &args.public_out {
        write_public(public_out, &identity.public())?;
    }
    Ok(Made { pin: identity.pin(), permissions })
}

/// Run `pqbind keygen`.
pub fn run(args: &Args) -> ExitCode {
    match generate(args) {
        Ok(made) => {
            println!("pqbind keygen: made a new hybrid identity (Ed25519 + ML-DSA-87)");
            println!("  seed file:   {} (keep it secret; it is the whole private key)", args.out.display());
            println!("  permissions: {}", made.permissions.describe());
            if let Some(public_out) = &args.public_out {
                println!("  public key:  {} (give it to a server's --enroll)", public_out.display());
            }
            println!("  pin:         {}", made.pin.to_hex());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("pqbind keygen: {error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Args, generate};
    use crate::common::from_hex;
    use crate::keyfiles::{load_identity, load_public};
    use crate::testutil::TempDir;

    #[test]
    fn keygen_writes_valid_hex_and_the_files_load_back_to_the_same_identity() {
        let dir = TempDir::new("keygen-ok");
        let args = Args { out: dir.path().join("id.seed"), public_out: Some(dir.path().join("id.pub")) };
        let made = generate(&args).expect("keygen");

        let seed_text = std::fs::read_to_string(&args.out).expect("seed file");
        assert_eq!(seed_text.trim().len(), 64, "64 hex digits");
        assert_eq!(seed_text.trim(), seed_text.trim().to_lowercase(), "lowercase");
        assert_eq!(from_hex(&seed_text).map(|bytes| bytes.len()), Some(32));

        let identity = load_identity(&args.out).expect("load the seed");
        assert_eq!(identity.pin(), made.pin);
        assert_eq!(made.pin.to_hex().len(), 96);

        let public = load_public(args.public_out.as_ref().expect("public path")).expect("load the public key");
        assert_eq!(public, identity.public());
    }

    #[test]
    fn keygen_refuses_to_overwrite_a_seed_or_a_public_key_file() {
        let dir = TempDir::new("keygen-overwrite");
        let seed = dir.path().join("id.seed");
        std::fs::write(&seed, "precious").expect("write");
        let error = generate(&Args { out: seed.clone(), public_out: None }).expect_err("must refuse");
        assert!(error.to_string().contains("refusing to overwrite"), "{error}");
        assert_eq!(std::fs::read_to_string(&seed).expect("read"), "precious", "the file is untouched");

        // A public key file that exists stops the command before any seed is written.
        let public = dir.path().join("id.pub");
        std::fs::write(&public, "x").expect("write");
        let fresh = dir.path().join("fresh.seed");
        assert!(generate(&Args { out: fresh.clone(), public_out: Some(public) }).is_err());
        assert!(!fresh.exists(), "no half-made pair");
    }
}
