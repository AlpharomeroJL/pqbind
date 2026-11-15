// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Make hybrid identities, write and read their seed and public key files, and run `pqbind keygen`.
//!
//! A seed file holds the 32-byte seed as 64 lowercase hex digits. A public key file holds the encoded public key as hex. A seed file is
//! never overwritten: the command stops instead.

use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pqbind::identity::SEED_LEN;
use pqbind::{HybridIdentity, Pin, PublicIdentity};

use crate::common::{CliError, CliResult, from_hex, to_hex};

/// What was done about who may read a secret file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permissions {
    /// The file was created readable and writable by its owner only (mode 0600).
    #[cfg_attr(not(unix), allow(dead_code))]
    OwnerOnly,
    /// This platform has no way to do that with the standard library only, so the file keeps its folder's access rules.
    NotSet,
}

impl Permissions {
    /// One sentence for the user.
    pub const fn describe(self) -> &'static str {
        match self {
            Self::OwnerOnly => "owner-only (mode 0600)",
            Self::NotSet => {
                "not set: the standard library cannot restrict a file on this platform, so the file keeps the access rules of its folder; restrict it yourself (for example with icacls on Windows)"
            }
        }
    }
}

#[cfg(unix)]
fn restrict(options: &mut OpenOptions) -> Permissions {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
    Permissions::OwnerOnly
}

#[cfg(not(unix))]
fn restrict(_options: &mut OpenOptions) -> Permissions {
    Permissions::NotSet
}

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

/// Create a file that must not exist yet and write `contents` to it.
fn write_new(path: &Path, contents: &str, secret: bool) -> CliResult<Permissions> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let permissions = if secret { restrict(&mut options) } else { Permissions::NotSet };
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == ErrorKind::AlreadyExists {
            CliError::new(format!(
                "{} already exists; refusing to overwrite it (delete it yourself if you mean to replace it)",
                path.display()
            ))
        } else {
            CliError::new(format!("cannot create {}: {error}", path.display()))
        }
    })?;
    if let Err(error) = file.write_all(contents.as_bytes()).and_then(|()| file.flush()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(CliError::new(format!("cannot write {}: {error}", path.display())));
    }
    Ok(permissions)
}

fn wipe(text: String) {
    let mut bytes = text.into_bytes();
    bytes.fill(0);
    std::hint::black_box(&bytes);
}

/// Make a new identity and write its seed to `path`, which must not exist.
pub fn create_identity(path: &Path) -> CliResult<(HybridIdentity, Permissions)> {
    let identity = HybridIdentity::generate()?;
    let seed = identity.to_seed();
    let text = format!("{}\n", to_hex(seed.expose_secret()));
    let permissions = write_new(path, &text, true);
    wipe(text);
    Ok((identity, permissions?))
}

/// Read an identity from a seed file.
pub fn load_identity(path: &Path) -> CliResult<HybridIdentity> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| CliError::new(format!("cannot read the identity file {}: {error}", path.display())))?;
    let decoded = from_hex(&text);
    wipe(text);
    let bad = || CliError::new(format!("the identity file {} must hold a seed of {} hex digits", path.display(), SEED_LEN * 2));
    let mut bytes = decoded.ok_or_else(bad)?;
    let seed = <[u8; SEED_LEN]>::try_from(bytes.as_slice()).map_err(|_| bad());
    bytes.fill(0);
    let mut seed = seed?;
    let identity = HybridIdentity::from_seed(&seed);
    seed.fill(0);
    Ok(identity?)
}

/// Read the identity in `path`, or make and save a new one when the file does not exist. The flag says whether it was created.
pub fn load_or_create_identity(path: &Path) -> CliResult<(HybridIdentity, Option<Permissions>)> {
    if path.exists() {
        return Ok((load_identity(path)?, None));
    }
    let (identity, permissions) = create_identity(path)?;
    Ok((identity, Some(permissions)))
}

/// Write a public key to `path`, which must not exist.
pub fn write_public(path: &Path, key: &PublicIdentity) -> CliResult<()> {
    write_new(path, &format!("{}\n", to_hex(key.as_bytes())), false).map(drop)
}

/// Read a public key from a file `write_public` made.
pub fn load_public(path: &Path) -> CliResult<PublicIdentity> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| CliError::new(format!("cannot read the public key file {}: {error}", path.display())))?;
    let bytes = from_hex(&text).ok_or_else(|| CliError::new(format!("the public key file {} is not hex", path.display())))?;
    PublicIdentity::from_bytes(&bytes)
        .map_err(|_| CliError::new(format!("the public key file {} does not hold a valid pqbind public key", path.display())))
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
    use super::{Args, generate, load_identity, load_public};
    use crate::common::from_hex;
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

    #[test]
    fn a_seed_file_that_is_not_64_hex_digits_is_refused() {
        let dir = TempDir::new("keygen-bad-seed");
        let path = dir.path().join("bad.seed");
        for text in ["", "zz", "00ff", &"a".repeat(63), &"g".repeat(64)] {
            std::fs::write(&path, text).expect("write");
            assert!(load_identity(&path).is_err(), "{text:?}");
        }
    }
}
