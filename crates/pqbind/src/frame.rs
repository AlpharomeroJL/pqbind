// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Define the length-prefixed frame reader and writer, and the stream trait the handshake runs over.
//!
//! The handshake is generic over [`FrameIo`], so it does not depend on one transport. [`StreamFrames`] implements it for any pair of
//! tokio streams (a QUIC bidirectional stream, a TLS stream split in two), each frame being a four-byte big-endian length and the bytes.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::binding::Binding;

/// The largest frame either end sends or accepts, in bytes. The largest handshake frame is under eight kilobytes.
pub const MAX_FRAME_LEN: usize = 16 * 1024;

/// How long a stream waits for the peer at each step by default.
pub const DEFAULT_STEP_TIMEOUT: Duration = Duration::from_secs(30);

/// The frame transport failed: a closed or broken stream, a frame over the limit, or a step that timed out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the frame transport failed")]
pub struct FrameError;

/// A channel that carries whole frames and knows the binding of the connection under it.
pub trait FrameIo: Send {
    /// The exporter value and application label of the connection under this channel.
    fn binding(&self) -> &Binding;

    /// Send one whole frame.
    ///
    /// # Errors
    ///
    /// [`FrameError`] when the frame is over [`MAX_FRAME_LEN`] or cannot be sent.
    fn send(&mut self, frame: &[u8]) -> impl Future<Output = Result<(), FrameError>> + Send;

    /// Receive the next whole frame.
    ///
    /// # Errors
    ///
    /// [`FrameError`] when the peer closed the channel, the frame is over [`MAX_FRAME_LEN`] or the wait timed out.
    fn recv(&mut self) -> impl Future<Output = Result<Vec<u8>, FrameError>> + Send;
}

/// Frames over a reader and a writer, with a time limit on every step. Take the streams back with [`StreamFrames::into_parts`] once
/// the handshake is over, to carry application data on them.
///
/// The time limit uses `tokio::time`, so the tokio runtime must have its time driver enabled (`enable_time` or `enable_all`);
/// without it the first send or receive panics.
pub struct StreamFrames<R, W> {
    reader: R,
    writer: W,
    binding: Binding,
    timeout: Duration,
}

impl<R, W> StreamFrames<R, W> {
    /// Frames over `reader` and `writer`, which belong to the connection `binding` describes.
    #[must_use]
    pub const fn new(reader: R, writer: W, binding: Binding) -> Self {
        Self { reader, writer, binding, timeout: DEFAULT_STEP_TIMEOUT }
    }

    /// The same frames with another time limit per step.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Give the streams back, for application data after the handshake.
    #[must_use]
    pub fn into_parts(self) -> (R, W) {
        (self.reader, self.writer)
    }
}

impl<R, W> std::fmt::Debug for StreamFrames<R, W> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("StreamFrames").finish_non_exhaustive()
    }
}

impl<R, W> FrameIo for StreamFrames<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    fn binding(&self) -> &Binding {
        &self.binding
    }

    async fn send(&mut self, frame: &[u8]) -> Result<(), FrameError> {
        if frame.len() > MAX_FRAME_LEN {
            return Err(FrameError);
        }
        let len = u32::try_from(frame.len()).map_err(|_| FrameError)?;
        let writer = &mut self.writer;
        let step = async {
            writer.write_all(&len.to_be_bytes()).await?;
            writer.write_all(frame).await?;
            writer.flush().await
        };
        tokio::time::timeout(self.timeout, step).await.map_err(|_| FrameError)?.map_err(|_| FrameError)
    }

    async fn recv(&mut self) -> Result<Vec<u8>, FrameError> {
        let reader = &mut self.reader;
        let step = async {
            let mut len = [0_u8; 4];
            reader.read_exact(&mut len).await.map_err(|_| FrameError)?;
            let len = usize::try_from(u32::from_be_bytes(len)).map_err(|_| FrameError)?;
            if len > MAX_FRAME_LEN {
                return Err(FrameError);
            }
            let mut frame = vec![0_u8; len];
            reader.read_exact(&mut frame).await.map_err(|_| FrameError)?;
            Ok(frame)
        };
        tokio::time::timeout(self.timeout, step).await.map_err(|_| FrameError)?
    }
}

/// A cursor over bytes that never panics: every read returns `None` when the bytes run out.
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    pub(crate) fn byte(&mut self) -> Option<u8> {
        let (first, rest) = self.rest.split_first()?;
        self.rest = rest;
        Some(*first)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.rest.split_first_chunk::<N>()?;
        self.rest = rest;
        Some(*head)
    }

    pub(crate) fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.rest.split_at_checked(len)?;
        self.rest = rest;
        Some(head)
    }

    pub(crate) const fn remaining(&self) -> &'a [u8] {
        self.rest
    }
}

#[cfg(test)]
mod tests {
    use super::{FrameIo, MAX_FRAME_LEN, Reader, StreamFrames};
    use crate::binding::{Binding, EXPORTER_LEN};

    fn binding() -> Binding {
        Binding::new(b"test/v1", [1; EXPORTER_LEN]).expect("binding")
    }

    #[tokio::test]
    async fn a_frame_crosses_a_stream_and_comes_out_whole() {
        let (left, right) = tokio::io::duplex(64 * 1024);
        let (left_read, left_write) = tokio::io::split(left);
        let (right_read, right_write) = tokio::io::split(right);
        let mut a = StreamFrames::new(left_read, left_write, binding());
        let mut b = StreamFrames::new(right_read, right_write, binding());
        a.send(b"hello").await.expect("send");
        a.send(&[]).await.expect("an empty frame");
        assert_eq!(b.recv().await.expect("recv"), b"hello");
        assert_eq!(b.recv().await.expect("recv"), Vec::<u8>::new());
    }

    #[tokio::test]
    async fn a_frame_over_the_limit_is_refused_on_both_ends() {
        let (left, right) = tokio::io::duplex(64 * 1024);
        let (left_read, left_write) = tokio::io::split(left);
        let (_right_read, right_write) = tokio::io::split(right);
        let mut a = StreamFrames::new(left_read, left_write, binding());
        assert!(a.send(&vec![0; MAX_FRAME_LEN + 1]).await.is_err(), "the sender refuses");
        // A hostile sender announces a huge frame; the receiver refuses before allocating it.
        tokio::io::AsyncWriteExt::write_all(&mut { right_write }, &u32::MAX.to_be_bytes()).await.expect("write");
        assert!(a.recv().await.is_err(), "the receiver refuses");
    }

    #[tokio::test]
    async fn a_cut_stream_and_a_silent_peer_both_end_in_an_error() {
        let (left, right) = tokio::io::duplex(1024);
        let (left_read, left_write) = tokio::io::split(left);
        let mut a = StreamFrames::new(left_read, left_write, binding()).with_timeout(std::time::Duration::from_millis(50));
        assert!(a.recv().await.is_err(), "a silent peer times out");
        drop(right);
        assert!(a.recv().await.is_err(), "a closed peer");
    }

    #[test]
    fn the_reader_returns_none_instead_of_panicking() {
        let mut reader = Reader::new(&[1, 2, 3]);
        assert_eq!(reader.byte(), Some(1));
        assert_eq!(reader.array::<2>(), Some([2, 3]));
        assert_eq!(reader.byte(), None);
        assert_eq!(reader.take(1), None);
        assert!(reader.remaining().is_empty());
        assert_eq!(Reader::new(&[1]).array::<2>(), None);
    }
}
