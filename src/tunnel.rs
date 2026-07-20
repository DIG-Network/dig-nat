//! Byte-stream adapter over a relay tunnel — turns the message-oriented [`RelayTunnel`] (RLY-002
//! send/recv of opaque payloads) into a tokio [`AsyncRead`] + [`AsyncWrite`] duplex stream, so the
//! SAME mTLS handshake + [`yamux`](crate::mux) multiplexing that runs over a direct TCP connection
//! runs UNCHANGED over the tier-6 relayed path.
//!
//! ## Why this exists (the security crux)
//!
//! The relayed tier is the last resort, but it MUST NOT be a weaker connection than a direct one. By
//! carrying the identical [`dig_tls`] mTLS session over this adapter, a relayed [`PeerConnection`]
//! presents the same CA-chained [`NodeCert`](dig_tls::NodeCert), the same `peer_id =
//! SHA-256(SPKI DER)` pin, and the same #1204 BLS binding as a direct connection. The relay only ever
//! forwards TLS records it cannot read — it is an untrusted byte forwarder, never a trusted party
//! (§5.4 recipient-sealing still applies as a layer ABOVE this transport). The mTLS layer, not the
//! relay, authenticates the peer.
//!
//! ## Framing
//!
//! A [`RelayTunnel`] forwards whole payloads A→relay→B in order. TLS is itself a length-delimited
//! record protocol, so this adapter needs no framing of its own: each `poll_write` ships up to
//! [`MAX_RELAY_PAYLOAD`](crate::relay::MAX_RELAY_PAYLOAD) bytes as one RLY-002 frame, and each
//! `poll_read` drains one inbound payload at a time (buffering the remainder across reads). Payload
//! order is preserved by the single relay socket; a dropped frame under backpressure surfaces as a
//! stream error, which fails the dial (acceptable for a last-resort tier — the strategy has already
//! exhausted every more-direct method).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::relay::{RelayTunnel, MAX_RELAY_PAYLOAD};

/// A duplex byte stream over one [`RelayTunnel`]: writes become RLY-002 relayed frames to the peer,
/// reads deliver the payloads the relay forwards back. Wrap it exactly like a [`tokio::net::TcpStream`]
/// — the mTLS connector/acceptor and yamux run over it identically.
pub struct RelayTunnelStream {
    /// The underlying relay tunnel (RLY-002 send/recv over the persistent reservation socket).
    tunnel: RelayTunnel,
    /// Bytes from the most recently received payload not yet copied to a reader, and the read cursor
    /// into them. A single inbound payload can satisfy several small `poll_read`s (e.g. TLS reads the
    /// 5-byte record header then the body), so the remainder is held here rather than dropped.
    read_carry: Vec<u8>,
    read_pos: usize,
}

impl RelayTunnelStream {
    /// Adapt a [`RelayTunnel`] into a byte-stream. The caller then runs the mTLS handshake over it.
    pub fn new(tunnel: RelayTunnel) -> Self {
        RelayTunnelStream {
            tunnel,
            read_carry: Vec::new(),
            read_pos: 0,
        }
    }
}

impl AsyncRead for RelayTunnelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Serve from the carry-over buffer first — one relay payload may fill many small reads.
        if this.read_pos >= this.read_carry.len() {
            match this.tunnel.poll_recv(cx) {
                Poll::Ready(Some(payload)) => {
                    this.read_carry = payload;
                    this.read_pos = 0;
                }
                // The reservation dropped: signal clean EOF so the mTLS layer reports a closed
                // connection rather than hanging.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }

        let remaining = &this.read_carry[this.read_pos..];
        let n = remaining.len().min(buf.remaining());
        buf.put_slice(&remaining[..n]);
        this.read_pos += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RelayTunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Ship at most one relay frame per call; the caller loops for a larger buffer. TLS records are
        // far smaller than the cap, so in practice one write == one record == one frame.
        let n = buf.len().min(MAX_RELAY_PAYLOAD);
        match self.tunnel.send(buf[..n].to_vec()) {
            Ok(()) => Poll::Ready(Ok(n)),
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // `send` hands the frame straight to the reservation's outbound sink — nothing is buffered here.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Dropping the stream drops the tunnel, which deregisters its routing; there is no half-close
        // to signal over RLY-002, so shutdown is a no-op success.
        Poll::Ready(Ok(()))
    }
}
