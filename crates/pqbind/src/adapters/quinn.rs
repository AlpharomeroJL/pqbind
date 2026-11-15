// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Read the exporter value from a quinn connection and carry frames over a quinn bidirectional stream.
//!
//! The client calls [`open`] and the server calls [`accept`]; each returns [`StreamFrames`] over one bidirectional stream, with the
//! connection's [`Binding`] read under the exporter label and the application label. Run [`crate::connect`] and [`crate::accept`] on
//! the result, then take the streams back with [`StreamFrames::into_parts`] for application data.

use ::quinn::rustls::pki_types::CertificateDer;
use ::quinn::{Connection, RecvStream, SendStream};

use crate::binding::Binding;
use crate::error::Error;
use crate::frame::StreamFrames;
use crate::identity::PeerId;

fn binding(connection: &Connection, app_label: &[u8]) -> Result<Binding, Error> {
    Binding::derive(app_label, |out, label, context| connection.export_keying_material(out, label, context))
}

/// Client side: open the bidirectional stream and read the exporter value.
///
/// A stream opened by the client is not visible to the server until the client writes the first frame on it. pqbind's HELLO does
/// that immediately, so call [`crate::connect`] right after this returns and the server's [`accept`] resolves then.
///
/// # Errors
///
/// [`Error::InvalidInput`] for a bad label, [`Error::Crypto`] when the connection gives no exporter value, and [`Error::Io`] when
/// the connection is closed.
pub async fn open(connection: &Connection, app_label: &[u8]) -> Result<StreamFrames<RecvStream, SendStream>, Error> {
    let binding = binding(connection, app_label)?;
    let (send, recv) = connection.open_bi().await.map_err(|_| Error::Io)?;
    Ok(StreamFrames::new(recv, send, binding))
}

/// Server side: accept the bidirectional stream and read the exporter value.
///
/// This returns only once the client has written its first frame on the stream (see [`open`]); pqbind's HELLO is that frame.
///
/// # Errors
///
/// [`Error::InvalidInput`] for a bad label, [`Error::Crypto`] when the connection gives no exporter value, and [`Error::Io`] when
/// the connection is closed.
pub async fn accept(connection: &Connection, app_label: &[u8]) -> Result<StreamFrames<RecvStream, SendStream>, Error> {
    let binding = binding(connection, app_label)?;
    let (send, recv) = connection.accept_bi().await.map_err(|_| Error::Io)?;
    Ok(StreamFrames::new(recv, send, binding))
}

/// The transport identity of the remote end: [`PeerId::of_certificate`] of the leaf certificate when the peer presented one, and
/// [`PeerId::anonymous`] otherwise.
#[must_use]
pub fn peer_id(connection: &Connection) -> PeerId {
    connection
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
        .and_then(|chain| chain.first().map(|leaf| PeerId::of_certificate(leaf.as_ref())))
        .unwrap_or_else(PeerId::anonymous)
}
