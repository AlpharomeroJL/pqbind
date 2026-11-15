// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Turn the `host:port` a user typed into addresses, and connect to the first one that answers.

use std::net::SocketAddr;

use rustls::RootCertStore;

use crate::common::{CliError, CliResult, Transport};
use crate::transport::{Raw, dial};

/// Split `host:port` (also `[::1]:4433` and `1.2.3.4:5`) into the host and the port.
pub fn split_target(text: &str) -> CliResult<(String, u16)> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    let bad = || CliError::new(format!("the target must be host:port, for example 127.0.0.1:4433, not {text:?}"));
    let (host, port) = text.rsplit_once(':').ok_or_else(bad)?;
    let host = host.trim_matches(['[', ']']);
    if host.is_empty() {
        return Err(bad());
    }
    Ok((host.to_owned(), port.parse::<u16>().map_err(|_| bad())?))
}

/// Every address `host` resolves to, in the order the resolver gave them.
pub async fn resolve(host: &str, port: u16) -> CliResult<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| CliError::new(format!("cannot resolve {host}: {error}")))?
        .map(|addr| SocketAddr::new(addr.ip().to_canonical(), addr.port()))
        .collect();
    if addrs.is_empty() {
        return Err(CliError::new(format!("{host} has no address")));
    }
    Ok(addrs)
}

/// Connect to the first address that answers (a name such as `localhost` may resolve to an IPv6 address nothing listens on).
pub async fn dial_any(transport: Transport, addrs: &[SocketAddr], server_name: &str, roots: &RootCertStore) -> CliResult<Raw> {
    let mut last = CliError::new("no address to connect to");
    for remote in addrs {
        match dial(transport, *remote, server_name, roots.clone()).await {
            Ok(raw) => return Ok(raw),
            Err(error) => last = error,
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::split_target;

    #[test]
    fn a_target_splits_into_host_and_port() {
        assert_eq!(split_target("127.0.0.1:4433").expect("ok"), ("127.0.0.1".to_owned(), 4433));
        assert_eq!(split_target("[::1]:9").expect("ok"), ("::1".to_owned(), 9));
        assert_eq!(split_target("example.test:443").expect("ok"), ("example.test".to_owned(), 443));
        for bad in ["", "example.test", ":80", "host:notaport", "host:99999"] {
            assert!(split_target(bad).is_err(), "{bad:?}");
        }
    }
}
