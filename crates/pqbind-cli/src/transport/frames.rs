// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Give the pqbind frames of either transport one type, and carry one short line of application data each way after the handshake.

use std::io;
use std::time::Duration;

use pqbind::{Binding, FrameError, FrameIo, StreamFrames};
use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::TlsStream;

/// A TLS 1.3 stream over TCP, on either side of the connection.
pub type TlsIo = TlsStream<TcpStream>;

/// The pqbind frames of either transport, as one type.
pub enum AnyFrames {
    /// Frames over a QUIC bidirectional stream.
    Quic(StreamFrames<RecvStream, SendStream>),
    /// Frames over a TLS 1.3 stream.
    Tls(StreamFrames<ReadHalf<TlsIo>, WriteHalf<TlsIo>>),
}

impl FrameIo for AnyFrames {
    fn binding(&self) -> &Binding {
        match self {
            Self::Quic(frames) => frames.binding(),
            Self::Tls(frames) => frames.binding(),
        }
    }

    async fn send(&mut self, frame: &[u8]) -> Result<(), FrameError> {
        match self {
            Self::Quic(frames) => frames.send(frame).await,
            Self::Tls(frames) => frames.send(frame).await,
        }
    }

    async fn recv(&mut self) -> Result<Vec<u8>, FrameError> {
        match self {
            Self::Quic(frames) => frames.recv().await,
            Self::Tls(frames) => frames.recv().await,
        }
    }
}

impl AnyFrames {
    /// Give the streams back, for application data after the handshake.
    pub fn into_streams(self) -> Streams {
        match self {
            Self::Quic(frames) => {
                let (recv, send) = frames.into_parts();
                Streams::Quic(recv, send)
            }
            Self::Tls(frames) => {
                let (read, write) = frames.into_parts();
                Streams::Tls(read, write)
            }
        }
    }
}

/// The two halves of a stream after the handshake, for one short line of application data each way.
pub enum Streams {
    /// A QUIC stream.
    Quic(RecvStream, SendStream),
    /// A TLS stream.
    Tls(ReadHalf<TlsIo>, WriteHalf<TlsIo>),
}

impl Streams {
    /// Send `text` and a newline.
    pub async fn send_line(&mut self, text: &str) -> io::Result<()> {
        let mut line = text.to_owned();
        line.push('\n');
        match self {
            Self::Quic(_, send) => send.write_all(line.as_bytes()).await.map_err(io::Error::other),
            Self::Tls(_, write) => {
                write.write_all(line.as_bytes()).await?;
                write.flush().await
            }
        }
    }

    /// Say nothing more: finish a QUIC stream, or shut down the write side of a TLS stream (which sends close_notify).
    pub async fn finish(&mut self) {
        match self {
            Self::Quic(_, send) => {
                let _ = send.finish();
            }
            Self::Tls(_, write) => {
                let _ = write.shutdown().await;
            }
        }
    }

    /// Read one line of at most `limit` bytes, waiting at most `wait`.
    pub async fn read_line(&mut self, limit: usize, wait: Duration) -> io::Result<String> {
        match self {
            Self::Quic(recv, _) => read_line_from(recv, limit, wait).await,
            Self::Tls(read, _) => read_line_from(read, limit, wait).await,
        }
    }
}

async fn read_line_from<R: AsyncRead + Unpin>(reader: &mut R, limit: usize, wait: Duration) -> io::Result<String> {
    let mut bytes = Vec::new();
    let read = async {
        loop {
            match reader.read_u8().await {
                Ok(b'\n') => return Ok(()),
                Ok(byte) => {
                    if bytes.len() >= limit {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "the line is too long"));
                    }
                    bytes.push(byte);
                }
                // A peer that ends the stream without a newline has still said what it said.
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof && !bytes.is_empty() => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    };
    tokio::time::timeout(wait, read).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "timed out waiting for the line"))??;
    String::from_utf8(bytes).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the line is not text"))
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::time::Duration;

    use tokio::io::{AsyncWriteExt, duplex};

    use super::read_line_from;

    const WAIT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn a_line_ends_at_the_newline() {
        let (mut reader, mut writer) = duplex(64);
        writer.write_all(b"hello\nrest").await.expect("write");
        assert_eq!(read_line_from(&mut reader, 16, WAIT).await.expect("a line"), "hello");
    }

    #[tokio::test]
    async fn a_peer_that_ends_the_stream_without_a_newline_has_still_said_what_it_said() {
        let (mut reader, mut writer) = duplex(64);
        writer.write_all(b"no newline").await.expect("write");
        drop(writer);
        assert_eq!(read_line_from(&mut reader, 16, WAIT).await.expect("a line"), "no newline");
    }

    #[tokio::test]
    async fn an_empty_stream_is_an_error() {
        let (mut reader, writer) = duplex(64);
        drop(writer);
        let error = read_line_from(&mut reader, 16, WAIT).await.expect_err("nothing was said");
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn a_line_over_the_limit_is_refused() {
        let (mut reader, mut writer) = duplex(64);
        writer.write_all(b"0123456789\n").await.expect("write");
        let error = read_line_from(&mut reader, 4, WAIT).await.expect_err("too long");
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn a_silent_peer_times_out() {
        let (mut reader, _writer) = duplex(64);
        let error = read_line_from(&mut reader, 16, Duration::from_millis(50)).await.expect_err("nothing arrives");
        assert_eq!(error.kind(), ErrorKind::TimedOut);
    }
}
