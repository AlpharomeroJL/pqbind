// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Parse a `host`, `host:port` or `[ipv6]:port` argument into the host, the port and the TLS server name.

use std::fmt;
use std::net::Ipv6Addr;

use rustls::pki_types::ServerName;

/// The port used when the argument gives none.
pub const DEFAULT_PORT: u16 = 443;

/// A host to probe.
#[derive(Clone, Debug)]
pub struct Target {
    /// The argument exactly as the user typed it. This is the only form of the host name that is ever printed.
    pub label: String,
    /// The host without brackets: a DNS name or an IP address.
    pub host: String,
    pub port: u16,
    /// The name sent as SNI and handed to the certificate verifier (which ignores it).
    pub server_name: ServerName<'static>,
}

/// Why an argument is not a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetError {
    Empty,
    BadPort,
    BadBrackets,
    BadHost,
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TargetError::Empty => "the host is empty",
            TargetError::BadPort => "the port is not a number from 1 to 65535",
            TargetError::BadBrackets => "an IPv6 address needs the form [address] or [address]:port",
            TargetError::BadHost => "not a valid host name or IP address",
        })
    }
}

/// Parse a host argument: `host`, `host:port`, `[ipv6]`, `[ipv6]:port` or a bare IPv6 address. The port defaults to 443.
pub fn parse_target(input: &str) -> Result<Target, TargetError> {
    let (host, port) = split_host_port(input)?;
    if host.is_empty() {
        return Err(TargetError::Empty);
    }
    let server_name = server_name_for(host)?;
    Ok(Target { label: input.to_owned(), host: host.to_owned(), port, server_name })
}

/// A TLS server name from a name typed by the user (the host, or the `--sni` override).
pub fn server_name_for(name: &str) -> Result<ServerName<'static>, TargetError> {
    if name.is_empty() {
        return Err(TargetError::Empty);
    }
    ServerName::try_from(name.to_owned()).map_err(|_| TargetError::BadHost)
}

fn split_host_port(input: &str) -> Result<(&str, u16), TargetError> {
    if let Some(rest) = input.strip_prefix('[') {
        let (inner, after) = rest.split_once(']').ok_or(TargetError::BadBrackets)?;
        if inner.parse::<Ipv6Addr>().is_err() {
            return Err(TargetError::BadBrackets);
        }
        return match after {
            "" => Ok((inner, DEFAULT_PORT)),
            _ => match after.strip_prefix(':') {
                Some(port) => Ok((inner, parse_port(port)?)),
                None => Err(TargetError::BadBrackets),
            },
        };
    }
    match input.matches(':').count() {
        0 => Ok((input, DEFAULT_PORT)),
        1 => match input.split_once(':') {
            Some((host, port)) => Ok((host, parse_port(port)?)),
            None => Err(TargetError::BadHost),
        },
        _ => {
            if input.parse::<Ipv6Addr>().is_ok() {
                Ok((input, DEFAULT_PORT))
            } else {
                Err(TargetError::BadBrackets)
            }
        }
    }
}

fn parse_port(text: &str) -> Result<u16, TargetError> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(TargetError::BadPort);
    }
    match text.parse::<u16>() {
        Ok(0) | Err(_) => Err(TargetError::BadPort),
        Ok(port) => Ok(port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(input: &str) -> (String, u16) {
        match parse_target(input) {
            Ok(target) => (target.host, target.port),
            Err(error) => (format!("error: {error}"), 0),
        }
    }

    #[test]
    fn a_bare_host_gets_port_443() {
        assert_eq!(parsed("example.com"), ("example.com".to_owned(), 443));
    }

    #[test]
    fn host_and_port() {
        assert_eq!(parsed("example.com:8443"), ("example.com".to_owned(), 8443));
        assert_eq!(parsed("127.0.0.1:1"), ("127.0.0.1".to_owned(), 1));
        assert_eq!(parsed("127.0.0.1:65535"), ("127.0.0.1".to_owned(), 65535));
    }

    #[test]
    fn ipv6_in_brackets() {
        assert_eq!(parsed("[::1]:443"), ("::1".to_owned(), 443));
        assert_eq!(parsed("[::1]:9000"), ("::1".to_owned(), 9000));
        assert_eq!(parsed("[2001:db8::1]"), ("2001:db8::1".to_owned(), 443));
    }

    #[test]
    fn a_bare_ipv6_address_uses_the_default_port() {
        assert_eq!(parsed("::1"), ("::1".to_owned(), 443));
    }

    #[test]
    fn the_label_is_the_typed_argument() {
        assert_eq!(parse_target("[::1]:443").map(|target| target.label), Ok("[::1]:443".to_owned()));
    }

    #[test]
    fn bad_ports_are_refused() {
        for input in
            ["example.com:0", "example.com:65536", "example.com:abc", "example.com:", "example.com:-1", "example.com:+80", "[::1]:"]
        {
            assert_eq!(parse_target(input).map(|_| ()), Err(TargetError::BadPort), "{input}");
        }
    }

    #[test]
    fn bad_brackets_are_refused() {
        for input in ["[::1", "[::1]x", "[example.com]:443", "[]", "1:2:3:4:5", "[::1]:443:1"] {
            assert!(parse_target(input).is_err(), "{input}");
        }
        assert_eq!(parse_target("[::1").map(|_| ()), Err(TargetError::BadBrackets));
    }

    #[test]
    fn empty_and_invalid_hosts_are_refused() {
        assert_eq!(parse_target("").map(|_| ()), Err(TargetError::Empty));
        assert_eq!(parse_target(":443").map(|_| ()), Err(TargetError::Empty));
        assert_eq!(parse_target("bad host").map(|_| ()), Err(TargetError::BadHost));
        assert_eq!(parse_target("-.example.com").map(|_| ()), Err(TargetError::BadHost));
    }

    #[test]
    fn server_names_for_sni() {
        assert!(server_name_for("example.com").is_ok());
        assert_eq!(server_name_for("").map(|_| ()), Err(TargetError::Empty));
        assert_eq!(server_name_for("not a name").map(|_| ()), Err(TargetError::BadHost));
    }

    #[test]
    fn an_ip_host_gets_an_ip_server_name() {
        assert!(matches!(parse_target("127.0.0.1:9").map(|target| target.server_name), Ok(ServerName::IpAddress(_))));
    }
}
