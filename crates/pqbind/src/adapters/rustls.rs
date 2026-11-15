// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Read the exporter value from a rustls TLS 1.3 connection and carry frames over its stream.
//!
//! Use [`frames`] on a finished `tokio-rustls` stream (client or server side, converted with `.into()` to
//! [`tokio_rustls::TlsStream`]) and run [`crate::connect`] or [`crate::accept`] over the result. Pass [`peer_id`] as the peer's
//! transport identity.
//!
//! # TLS 1.3 only
//!
//! The exporter is accepted only on a TLS 1.3 connection. A TLS 1.2 exporter is not bound to the whole handshake unless the extended
//! master secret was negotiated, so a TLS 1.2 connection is refused with [`Error::Unsupported`].

use ::rustls::{ConnectionCommon, ProtocolVersion};
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio_rustls::TlsStream;

use crate::binding::Binding;
use crate::error::Error;
use crate::frame::StreamFrames;
use crate::identity::PeerId;

/// Read the exporter value of a TLS 1.3 session under `app_label`.
fn binding_of<D>(connection: &ConnectionCommon<D>, app_label: &[u8]) -> Result<Binding, Error> {
    if connection.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
        return Err(Error::Unsupported);
    }
    Binding::derive(app_label, |out, label, context| connection.export_keying_material(out, label, Some(context)).map(drop))
}

/// The frames [`frames`] gives: one reader half and one writer half of a finished TLS stream.
pub type TlsFrames<IO> = StreamFrames<ReadHalf<TlsStream<IO>>, WriteHalf<TlsStream<IO>>>;

/// Take a finished TLS 1.3 stream, read the exporter value from its session and give frames over its two halves.
///
/// `app_label` is the application label both ends must use. The handshake has completed when the stream exists, so the exporter is
/// available.
///
/// # Errors
///
/// [`Error::Unsupported`] unless the negotiated version is TLS 1.3, [`Error::InvalidInput`] for an empty or over-long label, and
/// [`Error::Crypto`] when the session gives no exporter value.
pub fn frames<IO>(stream: TlsStream<IO>, app_label: &[u8]) -> Result<TlsFrames<IO>, Error>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
{
    let binding = match &stream {
        TlsStream::Client(client) => binding_of(&**client.get_ref().1, app_label)?,
        TlsStream::Server(server) => binding_of(&**server.get_ref().1, app_label)?,
    };
    let (reader, writer) = tokio::io::split(stream);
    Ok(StreamFrames::new(reader, writer, binding))
}

/// The transport identity of the remote end: [`PeerId::of_certificate`] of the leaf certificate it presented, or
/// [`PeerId::anonymous`] when it presented none.
#[must_use]
pub fn peer_id<IO>(stream: &TlsStream<IO>) -> PeerId {
    stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(<[_]>::first)
        .map_or_else(PeerId::anonymous, |leaf| PeerId::of_certificate(leaf.as_ref()))
}
