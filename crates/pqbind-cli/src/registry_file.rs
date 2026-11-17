// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Read and save the file that lists the enrolled clients, replacing it in one step and never reading a damaged file as an empty list.
//!
//! The file holds the library's own encoded list (`MemoryRegistry::encode`), which starts with a version byte. `enroll` writes it and
//! `serve --registry` reads it. A file that does not decode is an error: a server that lost its list must not look like a server that
//! never revoked anyone.

use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use pqbind::MemoryRegistry;

use crate::common::{CliError, CliResult};

/// Read the registry in `path`. A missing file is an error that says how to make one.
pub fn load(path: &Path) -> CliResult<MemoryRegistry> {
    match load_if_present(path)? {
        Some(registry) => Ok(registry),
        None => Err(CliError::new(format!(
            "the registry file {} does not exist; make it by enrolling a client with `pqbind enroll add --registry {} --key <client public key file>`",
            path.display(),
            path.display()
        ))),
    }
}

/// Read the registry in `path`, or start an empty one when the file does not exist. The flag says whether the file existed.
pub fn load_or_new(path: &Path) -> CliResult<(MemoryRegistry, bool)> {
    Ok(load_if_present(path)?.map_or_else(|| (MemoryRegistry::new(), false), |registry| (registry, true)))
}

fn load_if_present(path: &Path) -> CliResult<Option<MemoryRegistry>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(CliError::new(format!("cannot read the registry file {}: {error}", path.display()))),
    };
    MemoryRegistry::decode(&bytes).map(Some).map_err(|_| {
        CliError::new(format!(
            "the registry file {} is damaged or was made by another version of pqbind; it was not read as an empty list and was left as it is",
            path.display()
        ))
    })
}

/// Save `registry` to `path`: write a sibling file first, then move it over the old one, so a failure never leaves a half-written list.
pub fn save(path: &Path, registry: &MemoryRegistry) -> CliResult<()> {
    let temporary = sibling(path);
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .and_then(|mut file| file.write_all(&registry.encode()).and_then(|()| file.sync_all()));
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(CliError::new(format!("cannot write the registry file next to {}: {error}", path.display())));
    }
    std::fs::rename(&temporary, path).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        CliError::new(format!("cannot replace the registry file {}: {error}", path.display()))
    })
}

fn sibling(path: &Path) -> PathBuf {
    let mut name = path.file_name().map_or_else(|| "registry".into(), std::ffi::OsStr::to_os_string);
    name.push(format!(".{}.tmp", std::process::id()));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use pqbind::{Enrollment, HybridIdentity, MemoryRegistry, PeerId};

    use super::{load, load_or_new, save};
    use crate::testutil::TempDir;

    fn registry_with_one() -> MemoryRegistry {
        let registry = MemoryRegistry::new();
        let key = HybridIdentity::from_seed(&[5; 32]).expect("seed").public();
        registry.enroll(Enrollment { key, peer_id: PeerId::anonymous(), enrolled_at_unix_millis: 7 });
        registry
    }

    #[test]
    fn a_saved_registry_loads_back_and_a_second_save_replaces_it() {
        let dir = TempDir::new("registry-file-roundtrip");
        let path = dir.path().join("clients.reg");
        save(&path, &registry_with_one()).expect("saved");
        assert_eq!(load(&path).expect("loaded").list(), registry_with_one().list());
        save(&path, &MemoryRegistry::new()).expect("replaced");
        assert!(load(&path).expect("loaded").is_empty());
        let leftovers = std::fs::read_dir(dir.path()).expect("dir").count();
        assert_eq!(leftovers, 1, "no temporary file is left behind");
    }

    #[test]
    fn a_missing_file_is_an_error_to_load_and_an_empty_registry_to_start() {
        let dir = TempDir::new("registry-file-missing");
        let path = dir.path().join("none.reg");
        let error = load(&path).expect_err("missing");
        assert!(error.to_string().contains("pqbind enroll add"), "{error}");
        let (registry, existed) = load_or_new(&path).expect("new");
        assert!(registry.is_empty() && !existed);
    }

    #[test]
    fn a_damaged_file_is_never_read_as_an_empty_list_and_is_left_alone() {
        let dir = TempDir::new("registry-file-damaged");
        let path = dir.path().join("clients.reg");
        save(&path, &registry_with_one()).expect("saved");
        let mut bytes = std::fs::read(&path).expect("read");
        bytes.truncate(bytes.len() - 1);
        std::fs::write(&path, &bytes).expect("damage it");
        for result in [load(&path).map(drop), load_or_new(&path).map(drop)] {
            let error = result.expect_err("a damaged file");
            assert!(error.to_string().contains("damaged"), "{error}");
        }
        assert_eq!(std::fs::read(&path).expect("read"), bytes, "the file was not touched");
    }
}
