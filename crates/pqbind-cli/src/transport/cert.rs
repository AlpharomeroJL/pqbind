// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Make a self-signed TLS certificate for loopback names and load trusted certificates from PEM files.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use pqbind::PeerId;
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::common::{CliError, CliResult, fail};

/// A self-signed TLS certificate and its private key, valid for `localhost`, `127.0.0.1` and `::1`.
pub struct Tls {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    cert_pem: String,
}

impl Tls {
    /// A new certificate and key.
    pub fn generate() -> CliResult<Self> {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).map_err(fail("certificate parameters"))?;
        params.subject_alt_names.push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        params.subject_alt_names.push(rcgen::SanType::IpAddress(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        let key = rcgen::KeyPair::generate().map_err(fail("TLS key generation"))?;
        let cert = params.self_signed(&key).map_err(fail("certificate signing"))?;
        Ok(Self { cert_der: cert.der().to_vec(), key_der: key.serialize_der(), cert_pem: cert.pem() })
    }

    /// The certificate.
    pub fn certificate(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.cert_der.clone())
    }

    /// The private key.
    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()))
    }

    /// The transport identity of this certificate, as the adapters compute it for a peer that presented it.
    pub fn id(&self) -> PeerId {
        PeerId::of_certificate(&self.cert_der)
    }

    /// The certificate as PEM text (public data).
    pub fn pem(&self) -> &str {
        &self.cert_pem
    }

    /// A trust store that holds exactly this certificate.
    pub fn roots(&self) -> CliResult<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(self.certificate()).map_err(fail("trusting the certificate"))?;
        Ok(roots)
    }
}

/// A trust store from the certificates in a PEM file.
pub fn load_roots(path: &Path) -> CliResult<RootCertStore> {
    let bytes = std::fs::read(path).map_err(|error| CliError::new(format!("cannot read the CA file {}: {error}", path.display())))?;
    let mut roots = RootCertStore::empty();
    let mut count = 0_usize;
    for item in CertificateDer::pem_slice_iter(&bytes) {
        let cert = item.map_err(|error| CliError::new(format!("the CA file {} is not valid PEM: {error}", path.display())))?;
        roots.add(cert).map_err(|error| {
            CliError::new(format!("the CA file {} holds a certificate that cannot be trusted: {error}", path.display()))
        })?;
        count += 1;
    }
    if count == 0 {
        return Err(CliError::new(format!("the CA file {} holds no certificate", path.display())));
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::{Tls, load_roots};
    use crate::testutil::TempDir;

    #[test]
    fn a_certificate_round_trips_through_its_pem_text() {
        let tls = Tls::generate().expect("certificate");
        let dir = TempDir::new("cert-pem");
        let path = dir.path().join("cert.pem");
        std::fs::write(&path, tls.pem()).expect("write");
        let roots = load_roots(&path).expect("roots");
        assert_eq!(roots.roots.len(), 1);
        std::fs::write(&path, "not a certificate").expect("write");
        assert!(load_roots(&path).is_err());
        assert!(load_roots(&dir.path().join("missing.pem")).is_err());
    }
}
