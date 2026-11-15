// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Read the exporter value from an iroh connection and carry frames over an iroh bidirectional stream.
//!
//! iroh is a QUIC library whose endpoints are identified by a 32-byte node id, which is also the public key of the endpoint's TLS
//! certificate. After the QUIC handshake the node id of the remote end is authenticated by iroh, so it is the transport identity
//! this adapter hands to the handshake ([`peer_id`] and [`own_id`]).
//!
//! # Use
//!
//! 1. The client calls [`open`] and the server calls [`accept`] on the established [`Connection`], with the same application label.
//! 2. Each end runs [`crate::connect`] or [`crate::accept`] over the returned [`IrohFrames`], with [`own_id`] and [`peer_id`] as the
//!    two transport identities.
//! 3. After the handshake returns `Ok`, [`StreamFrames::into_parts`] gives the receive and send streams back for application data.
//!
//! # QUIC streams are created by their first byte
//!
//! A QUIC stream is invisible to the peer until the first bytes are sent on it, so [`accept`] returns only once the client has sent
//! its first frame. The client's [`crate::connect`] sends the HELLO frame first, so the two calls meet. Both calls give up after
//! [`DEFAULT_STEP_TIMEOUT`] and return [`Error::Io`].

use std::time::Duration;

use ::iroh::endpoint::{Connection, RecvStream, SendStream};
use ::iroh::{Endpoint, EndpointId};

use crate::binding::Binding;
use crate::error::Error;
use crate::frame::{DEFAULT_STEP_TIMEOUT, StreamFrames};
use crate::identity::PeerId;

/// Frames over the two halves of one iroh bidirectional stream. The streams carry tokio `AsyncRead` and `AsyncWrite`, so this is the
/// ordinary [`StreamFrames`]: four-byte big-endian length, then the frame, [`crate::MAX_FRAME_LEN`] limit, a time limit on every step.
pub type IrohFrames = StreamFrames<RecvStream, SendStream>;

/// Open the bidirectional stream as the client and read the exporter value of the connection.
///
/// `app_label` is the application label both ends read the exporter value under (1 to 255 bytes).
///
/// # Errors
///
/// [`Error::InvalidInput`] for a bad label, [`Error::Crypto`] when the connection gives no exporter value, and [`Error::Io`] when
/// the connection closed or the stream did not open within [`DEFAULT_STEP_TIMEOUT`].
pub async fn open(connection: &Connection, app_label: &[u8]) -> Result<IrohFrames, Error> {
    let binding = binding_of(connection, app_label)?;
    let (writer, reader) = within(DEFAULT_STEP_TIMEOUT, connection.open_bi()).await?;
    Ok(StreamFrames::new(reader, writer, binding))
}

/// Accept the bidirectional stream as the server and read the exporter value of the connection.
///
/// The stream becomes visible when the client sends its first frame (see the module documentation).
///
/// # Errors
///
/// [`Error::InvalidInput`] for a bad label, [`Error::Crypto`] when the connection gives no exporter value, and [`Error::Io`] when
/// the connection closed or no stream arrived within [`DEFAULT_STEP_TIMEOUT`].
pub async fn accept(connection: &Connection, app_label: &[u8]) -> Result<IrohFrames, Error> {
    let binding = binding_of(connection, app_label)?;
    let (writer, reader) = within(DEFAULT_STEP_TIMEOUT, connection.accept_bi()).await?;
    Ok(StreamFrames::new(reader, writer, binding))
}

/// The transport identity of the remote end: its iroh node id, 32 bytes, as iroh authenticated it in the QUIC handshake.
#[must_use]
pub fn peer_id(connection: &Connection) -> PeerId {
    peer_id_of(&connection.remote_id())
}

/// The transport identity of a local endpoint: its node id, 32 bytes. The remote end sees the same bytes from its [`peer_id`].
#[must_use]
pub fn own_id(endpoint: &Endpoint) -> PeerId {
    peer_id_of(&endpoint.id())
}

/// Read the exporter value of `connection` under the pqbind label and `app_label` as the context.
fn binding_of(connection: &Connection, app_label: &[u8]) -> Result<Binding, Error> {
    Binding::derive(app_label, |output, label, context| connection.export_keying_material(output, label, context))
}

/// A node id as a [`PeerId`]. A node id is 32 bytes, far under the identity limit, so the anonymous fallback is unreachable; if it
/// were ever taken, the two ends would sign different identities and every proof would fail, never succeed.
fn peer_id_of(id: &EndpointId) -> PeerId {
    PeerId::new(id.as_bytes().as_slice()).unwrap_or_else(|_| PeerId::anonymous())
}

/// Wait for `future` for at most `limit`; a timeout and a transport failure are both [`Error::Io`].
async fn within<T, E>(limit: Duration, future: impl Future<Output = Result<T, E>>) -> Result<T, Error> {
    tokio::time::timeout(limit, future).await.map_err(|_| Error::Io)?.map_err(|_| Error::Io)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ::iroh::SecretKey;

    use super::{IrohFrames, peer_id_of, within};
    use crate::error::Error;
    use crate::frame::FrameIo;

    fn assert_frame_io<T: FrameIo + Unpin>() {}

    #[test]
    fn the_iroh_frames_type_is_a_frame_transport() {
        assert_frame_io::<IrohFrames>();
    }

    #[test]
    fn a_node_id_becomes_a_peer_id_of_its_32_bytes() {
        let first = SecretKey::from_bytes(&[1; 32]).public();
        let second = SecretKey::from_bytes(&[2; 32]).public();
        let id = peer_id_of(&first);
        assert_eq!(id.as_bytes(), first.as_bytes().as_slice());
        assert_eq!(id.as_bytes().len(), 32);
        assert!(!id.is_anonymous());
        assert_eq!(id, peer_id_of(&first), "the same node id gives the same identity");
        assert_ne!(id, peer_id_of(&second), "another node id gives another identity");
    }

    #[tokio::test]
    async fn a_step_that_finishes_passes_its_value_and_a_failure_or_silence_is_an_io_error() {
        let limit = Duration::from_millis(50);
        assert_eq!(within(limit, async { Ok::<u8, ()>(7) }).await, Ok(7));
        assert_eq!(within(limit, async { Err::<u8, ()>(()) }).await, Err(Error::Io));
        assert_eq!(within(limit, std::future::pending::<Result<u8, ()>>()).await, Err(Error::Io));
    }
}
