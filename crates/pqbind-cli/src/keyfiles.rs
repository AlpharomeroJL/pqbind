// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Write and read the seed and public key files of hybrid identities, never overwriting a file and restricting a secret file where the platform allows.
//!
//! A seed file holds the 32-byte seed as 64 lowercase hex digits. A public key file holds the encoded public key as hex. `keygen`,
//! `serve` and `verify` all go through this module.

use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::path::Path;

use pqbind::identity::SEED_LEN;
use pqbind::{HybridIdentity, PublicIdentity};

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

#[cfg(test)]
mod tests {
    use super::{load_identity, load_or_create_identity, load_public, write_public};
    use crate::testutil::TempDir;

    #[test]
    fn an_identity_is_created_once_and_loaded_after_that() {
        let dir = TempDir::new("keyfiles-create-once");
        let path = dir.path().join("id.seed");
        let (first, created) = load_or_create_identity(&path).expect("created");
        assert!(created.is_some(), "the first call makes the file");
        let (second, created) = load_or_create_identity(&path).expect("loaded");
        assert!(created.is_none(), "the second call only reads it");
        assert_eq!(first.pin(), second.pin());
    }

    #[test]
    fn a_public_key_file_is_never_overwritten_and_loads_back() {
        let dir = TempDir::new("keyfiles-public");
        let path = dir.path().join("id.pub");
        let (identity, _) = load_or_create_identity(&dir.path().join("id.seed")).expect("identity");
        write_public(&path, &identity.public()).expect("written");
        assert!(write_public(&path, &identity.public()).is_err(), "a second write refuses");
        assert_eq!(load_public(&path).expect("loaded"), identity.public());
        std::fs::write(&path, "not hex").expect("write");
        assert!(load_public(&path).is_err());
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
