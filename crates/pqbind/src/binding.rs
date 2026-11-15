// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Hold the TLS exporter value that ties a proof to one connection, with the application label both peers read it under.
//!
//! The exporter value is 64 bytes read from the live TLS 1.3 or QUIC session (RFC 5705 and RFC 8446 section 7.5). It is unique to the
//! two ends of that session, so a proof signed over it holds on that connection alone. The application label is passed as the exporter
//! context, so two applications on one transport never share a value.

use zeroize::Zeroize;

use crate::error::Error;

/// The exporter label every pqbind adapter uses.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-pqbind-v1";

/// The length of the exporter value, in bytes.
pub const EXPORTER_LEN: usize = 64;

/// The longest application label, in bytes.
pub const MAX_APP_LABEL_LEN: usize = 255;

/// The exporter value of one connection, with the application label it was read under. It prints nothing and wipes itself on drop.
pub struct Binding {
    app_label: Vec<u8>,
    exporter: [u8; EXPORTER_LEN],
}

impl Binding {
    /// A binding from an exporter value the caller already read, with the label it was read under.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] when the label is empty or longer than [`MAX_APP_LABEL_LEN`].
    pub fn new(app_label: &[u8], exporter: [u8; EXPORTER_LEN]) -> Result<Self, Error> {
        if app_label.is_empty() || app_label.len() > MAX_APP_LABEL_LEN {
            return Err(Error::InvalidInput);
        }
        Ok(Self { app_label: app_label.to_vec(), exporter })
    }

    /// Read the exporter value through `export`, which a transport adapter wires to its own `export_keying_material`. The closure gets
    /// the output buffer, [`EXPORTER_LABEL`] and the application label as the context, so an adapter cannot pass the wrong ones.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] for a bad label, and [`Error::Crypto`] when the transport gives no exporter value.
    pub fn derive<E>(app_label: &[u8], export: impl FnOnce(&mut [u8], &'static [u8], &[u8]) -> Result<(), E>) -> Result<Self, Error> {
        if app_label.is_empty() || app_label.len() > MAX_APP_LABEL_LEN {
            return Err(Error::InvalidInput);
        }
        let mut exporter = [0_u8; EXPORTER_LEN];
        export(&mut exporter, EXPORTER_LABEL, app_label).map_err(|_| Error::Crypto)?;
        Ok(Self { app_label: app_label.to_vec(), exporter })
    }

    /// The application label.
    #[must_use]
    pub fn app_label(&self) -> &[u8] {
        &self.app_label
    }

    /// The exporter value.
    #[must_use]
    pub const fn exporter(&self) -> &[u8; EXPORTER_LEN] {
        &self.exporter
    }
}

impl Drop for Binding {
    fn drop(&mut self) {
        self.exporter.zeroize();
    }
}

impl std::fmt::Debug for Binding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Binding(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::{Binding, EXPORTER_LABEL, EXPORTER_LEN, MAX_APP_LABEL_LEN};
    use crate::error::Error;

    #[test]
    fn a_label_must_be_one_to_255_bytes() {
        assert!(Binding::new(b"app/v1", [0; EXPORTER_LEN]).is_ok());
        assert!(matches!(Binding::new(b"", [0; EXPORTER_LEN]), Err(Error::InvalidInput)));
        assert!(matches!(Binding::new(&[b'a'; MAX_APP_LABEL_LEN + 1], [0; EXPORTER_LEN]), Err(Error::InvalidInput)));
    }

    #[test]
    fn derive_passes_the_fixed_label_and_the_application_label_as_context() {
        let binding = Binding::derive(b"my-app/v1", |out, label, context| {
            assert_eq!(label, EXPORTER_LABEL);
            assert_eq!(context, b"my-app/v1");
            assert_eq!(out.len(), EXPORTER_LEN);
            out.fill(9);
            Ok::<(), ()>(())
        })
        .expect("derive");
        assert_eq!(binding.exporter(), &[9; EXPORTER_LEN]);
        assert_eq!(binding.app_label(), b"my-app/v1");
        assert!(matches!(Binding::derive(b"x", |_, _, _| Err::<(), ()>(())), Err(Error::Crypto)));
    }

    #[test]
    fn debug_output_names_no_exporter_value() {
        assert_eq!(format!("{:?}", Binding::new(b"a", [7; EXPORTER_LEN]).expect("binding")), "Binding(..)");
    }
}
