// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Hold what every command shares: the error type, the transport choice, hex and pin text helpers and the default application label.

use std::fmt;

use pqbind::Pin;
use pqbind::binding::MAX_APP_LABEL_LEN;

/// The application label `serve` and `verify` use unless the user passes another one.
pub const DEFAULT_APP_LABEL: &str = "pqbind-cli/v1";

/// A failure a command reports to the user as one plain sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    message: String,
}

impl CliError {
    /// An error with this message.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

impl From<pqbind::Error> for CliError {
    fn from(error: pqbind::Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<pqbind_crypto::CryptoError> for CliError {
    fn from(error: pqbind_crypto::CryptoError) -> Self {
        Self::new(error.to_string())
    }
}

/// What a command returns.
pub type CliResult<T> = Result<T, CliError>;

/// A closure that turns any displayable error into a [`CliError`] that starts with `context`.
pub fn fail<E: fmt::Display>(context: &'static str) -> impl FnOnce(E) -> CliError {
    move |error| CliError::new(format!("{context}: {error}"))
}

/// Which transport a command runs pqbind over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Transport {
    /// QUIC (quinn), one bidirectional stream per connection.
    Quic,
    /// TLS 1.3 over TCP (rustls).
    Tls,
}

impl Transport {
    /// The name the command line uses.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Quic => "quic",
            Self::Tls => "tls",
        }
    }
}

fn digit(value: u8) -> char {
    char::from_digit(u32::from(value), 16).unwrap_or('0')
}

/// Lowercase hex of `bytes`.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(digit(byte >> 4));
        out.push(digit(byte & 0x0f));
    }
    out
}

/// The bytes of hex text (either case, surrounding white space ignored), or `None` for an odd length or a character that is not a hex digit.
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.trim().as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| {
            let &[first, second] = pair else { return None };
            let high = char::from(first).to_digit(16)?;
            let low = char::from(second).to_digit(16)?;
            u8::try_from((high << 4) | low).ok()
        })
        .collect()
}

/// The first 16 hex digits of a pin, which is enough to tell two pins apart on a screen.
pub fn short_pin(pin: &Pin) -> String {
    pin.to_hex().chars().take(16).collect()
}

/// The bytes of an application label, checked against the length the library allows.
pub fn label_bytes(label: &str) -> CliResult<Vec<u8>> {
    if label.is_empty() || label.len() > MAX_APP_LABEL_LEN {
        return Err(CliError::new(format!("the application label must be 1 to {MAX_APP_LABEL_LEN} bytes long")));
    }
    Ok(label.as_bytes().to_vec())
}

/// Now, in milliseconds since the Unix epoch (0 if the clock is before it).
pub fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{from_hex, label_bytes, to_hex};

    #[test]
    fn hex_round_trips_in_either_case_and_bad_text_is_refused() {
        assert_eq!(to_hex(&[0, 1, 0xab, 0xff]), "0001abff");
        assert_eq!(from_hex("0001ABff"), Some(vec![0, 1, 0xab, 0xff]));
        assert_eq!(from_hex("  00ff\n"), Some(vec![0, 0xff]));
        assert_eq!(from_hex("abc"), None, "odd length");
        assert_eq!(from_hex("zz"), None, "not hex");
        assert_eq!(from_hex(""), Some(Vec::new()));
    }

    #[test]
    fn a_label_must_be_one_to_255_bytes() {
        assert!(label_bytes("pqbind-cli/v1").is_ok());
        assert!(label_bytes("").is_err());
        assert!(label_bytes(&"a".repeat(256)).is_err());
    }
}
