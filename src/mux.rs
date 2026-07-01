//! Stream multiplexing + byte-range streams over a single established peer connection.
//!
//! Every traversal tier (direct / UPnP / NAT-PMP / PCP / hole-punch / relayed) yields the SAME
//! thing: one mTLS byte stream to the peer. On top of that single stream this module layers
//! **[`yamux`]** multiplexing so the content/download layer can open **many cheap concurrent logical
//! streams** to the peer with no head-of-line blocking — the transport is **streaming-first**, never
//! "send request, buffer the whole response in memory".
//!
//! Two capabilities:
//!
//! 1. **Multiplexing** — [`PeerSession::open_stream`] opens an independent bidirectional
//!    [`PeerStream`] (a tokio [`AsyncRead`] + [`AsyncWrite`]); open N of them concurrently and read
//!    each incrementally with natural backpressure (yamux windows).
//! 2. **Byte-range streams** — [`PeerSession::open_range_stream`] opens a stream scoped to a
//!    `[offset, offset+len)` range of a named resource by writing a small [`RangeRequest`] preamble,
//!    then hands back the stream so the caller reads exactly those bytes as they arrive. A downloader
//!    opens range streams to DIFFERENT peers in parallel and reassembles — multi-source parallel
//!    download falls out of "streams are cheap + multiplexed + range-scoped".
//!
//! The uniform abstraction holds regardless of how the connection was established, and regardless of
//! whether the underlying byte stream is direct or (tier-6) relay-proxied.
//!
//! ## Wire alignment (normative)
//!
//! The control + range types here conform to the published **L7 peer-network spec** (docs.dig.net
//! "L7 · DIG Node peer network", §8 streaming, §9 byte-range fetch + availability). The shapes are
//! the `dig.getAvailability` / `dig.fetchRange` request/response and the streamed `RangeFrame`
//! (`{offset, length, bytes, complete}`, first frame adding `total_length` + `chunk_lens` +
//! `chunk_index` + `inclusion_proof` + `root`). Per-chunk integrity (split by `chunk_lens`, verify
//! the whole-resource inclusion proof vs the chain-anchored `root`, AES-256-GCM-SIV-open) is done by
//! the CONTENT layer above dig-nat; dig-nat carries these frames faithfully over the mux transport.

use std::io;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

/// One logical, bidirectional stream to the peer — a tokio [`AsyncRead`] + [`AsyncWrite`]. Reads
/// deliver bytes incrementally as they arrive (streaming, with yamux-window backpressure); many
/// [`PeerStream`]s coexist on one [`PeerSession`] without head-of-line blocking.
///
/// yamux streams are `futures` streams; this is the tokio-trait view via `tokio-util` compat.
pub type PeerStream = Compat<yamux::Stream>;

/// One item in a [`dig.getAvailability`](AvailabilityRequest) batch — a resource key at store, root,
/// or capsule/resource granularity (inferred from which fields are present, per the L7 spec §9):
/// `store_id` only → *has_store*; `+ root` → *has_root* (the capsule `store_id:root`); `+
/// retrieval_key` → *has_resource*. Hashes are 64-hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityItem {
    /// The store id (64-hex). Always present.
    pub store_id: String,
    /// The generation root (64-hex). Present for root/resource granularity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// The resource retrieval key (64-hex). Present for resource granularity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieval_key: Option<String>,
}

/// The **availability pre-check** (`dig.getAvailability`, L7 spec §9) — asked BEFORE any range fetch.
/// A multi-source download batches candidate peers × items in one call each and only fans byte-range
/// requests at peers that answer *available* — never opening range streams to peers that may not hold
/// the content. A message-style control call over the mux'd mTLS connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityRequest {
    /// The items to check, batched.
    pub items: Vec<AvailabilityItem>,
}

/// One answer in an [`AvailabilityResponse`], positionally aligned with the request `items`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityAnswer {
    /// Whether the peer holds the queried item. Always present.
    pub available: bool,
    /// (store granularity) generation roots the peer holds for the store, newest-first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roots: Option<Vec<String>>,
    /// (root/resource granularity) the ciphertext length — lets the caller plan its ranges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_length: Option<u64>,
    /// (root/resource granularity) the chunk count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_count: Option<u64>,
    /// Whether the peer holds the FULL resource/capsule (`true`) or only part (`false`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub complete: Option<bool>,
}

/// The peer's answer to an [`AvailabilityRequest`]: one [`AvailabilityAnswer`] per queried item,
/// positionally aligned with the request's `items`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityResponse {
    /// One answer per queried item, in request order.
    pub items: Vec<AvailabilityAnswer>,
}

/// A byte-range request (`dig.fetchRange`, L7 spec §9) written at the start of a range-scoped stream.
/// Identifies a resource (`store_id` + `retrieval_key` [+ `root`]) or a whole capsule
/// (`capsule: true`, identified by `store_id` [+ `root`]) and the `[offset, offset+length)` range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeRequest {
    /// The store id (64-hex).
    pub store_id: String,
    /// The resource retrieval key (64-hex). Omitted when `capsule` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieval_key: Option<String>,
    /// The generation root (64-hex). Optional — defaults to the chain-anchored tip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// Fetch a whole capsule / `.dig` (identified by `store_id` [+ `root`]) rather than one resource.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub capsule: bool,
    /// Start offset (bytes) into the resource ciphertext. Default `0`.
    #[serde(default)]
    pub offset: u64,
    /// Length (bytes) to return (widened to whole-chunk boundaries; clamped to the node window).
    pub length: u64,
}

/// One streamed `dig.fetchRange` frame (L7 spec §8 framing). Frames arrive in ascending `offset`
/// order and tile the requested range exactly; the caller reassembles by `offset` and stops on
/// `complete`. The **first frame** additionally carries the per-range verification metadata so a
/// single-peer range is independently verifiable against the chain-anchored `root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeFrame {
    /// This frame's start offset within the requested range.
    pub offset: u64,
    /// This frame's byte length.
    pub length: u64,
    /// The raw ciphertext bytes.
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
    /// Whether this is the final frame of the range.
    pub complete: bool,
    /// (first frame only) the full resource ciphertext length.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_length: Option<u64>,
    /// (first frame only) per-chunk ciphertext lengths of the whole resource, in order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_lens: Option<Vec<u64>>,
    /// (first frame only) index into `chunk_lens` of the first chunk in this frame.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_index: Option<u64>,
    /// (first frame only) merkle inclusion proof of the whole resource vs the generation `root`
    /// (base64, relayed verbatim); `null`/absent for `capsule: true` (self-verifying on install).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inclusion_proof: Option<String>,
    /// (first frame only) the generation root (64-hex) the inclusion proof is against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
}

impl AvailabilityRequest {
    /// Serialize as a `u32` big-endian length prefix + JSON body (the uniform control framing).
    pub fn encode(&self) -> Vec<u8> {
        encode_framed(self)
    }
    /// Read + decode an [`AvailabilityRequest`] from `r` (the peer/serving side).
    pub async fn decode<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Self> {
        decode_framed(r).await
    }
}

impl AvailabilityResponse {
    /// Serialize as a `u32` big-endian length prefix + JSON body.
    pub fn encode(&self) -> Vec<u8> {
        encode_framed(self)
    }
    /// Read + decode an [`AvailabilityResponse`] from `r` (the requesting side).
    pub async fn decode<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Self> {
        decode_framed(r).await
    }
}

impl RangeRequest {
    /// A range request for a content resource (`store_id` + `retrieval_key`).
    pub fn resource(
        store_id: impl Into<String>,
        retrieval_key: impl Into<String>,
        offset: u64,
        length: u64,
    ) -> Self {
        RangeRequest {
            store_id: store_id.into(),
            retrieval_key: Some(retrieval_key.into()),
            root: None,
            capsule: false,
            offset,
            length,
        }
    }

    /// Serialize as a `u32` big-endian length prefix + JSON body — the preamble a peer reads to learn
    /// the resource + range before streaming the frames.
    pub fn encode(&self) -> Vec<u8> {
        encode_framed(self)
    }
    /// Read + decode a [`RangeRequest`] preamble from `r` (the serving side of a range stream).
    pub async fn decode<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Self> {
        decode_framed(r).await
    }
}

impl RangeFrame {
    /// Serialize as a `u32` big-endian length prefix + JSON body (one framed frame on the stream).
    pub fn encode(&self) -> Vec<u8> {
        encode_framed(self)
    }
    /// Read + decode one [`RangeFrame`] from `r`. Returns `Ok(None)` at clean end-of-stream (the
    /// reader hit EOF on a frame boundary), so a consumer loops until `None` or `complete`.
    pub async fn decode<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Self>> {
        decode_framed_opt(r).await
    }
}

/// Maximum length-prefixed control/preamble body — guards against a malicious length prefix forcing
/// a huge allocation.
const MAX_FRAMED_BODY: usize = 64 * 1024;

/// Serialize `value` as a `u32` big-endian length prefix + JSON body — the uniform framing for every
/// small control message on a stream (availability + range preambles).
fn encode_framed<T: Serialize>(value: &T) -> Vec<u8> {
    let body = serde_json::to_vec(value).expect("control message serializes");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Read + decode a length-prefixed JSON control message from `r`, bounded by [`MAX_FRAMED_BODY`].
async fn decode_framed<T: for<'de> Deserialize<'de>, R: AsyncRead + Unpin>(
    r: &mut R,
) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAMED_BODY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control message too large",
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Like [`decode_framed`] but returns `Ok(None)` on a CLEAN end-of-stream at a frame boundary (the
/// length prefix read hits immediate EOF), so a streaming consumer can loop until the stream ends.
async fn decode_framed_opt<T: for<'de> Deserialize<'de>, R: AsyncRead + Unpin>(
    r: &mut R,
) -> io::Result<Option<T>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAMED_BODY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control message too large",
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// One command to the yamux driver task. yamux 0.13 has no `Control` handle, so we drive the
/// [`yamux::Connection`] in a task and talk to it over this channel.
enum MuxCommand {
    /// Open a new outbound stream; the resulting [`yamux::Stream`] (or error) comes back on the sender.
    OpenOutbound(tokio::sync::oneshot::Sender<Result<yamux::Stream, String>>),
}

/// A multiplexed session over one peer connection: open many concurrent logical [`PeerStream`]s.
///
/// yamux 0.13 exposes a poll-based [`yamux::Connection`] (no `Control` handle), so a background
/// driver task owns the connection and serves open-stream requests over a command channel; inbound
/// streams are surfaced on [`Self::inbound_rx`] for a serving node. Dropping the session closes the
/// command channel, which ends the driver and tears down the underlying byte stream.
pub struct PeerSession {
    cmd_tx: tokio::sync::mpsc::Sender<MuxCommand>,
    /// Inbound streams opened BY the peer (server role / bidirectional use). A pure client can
    /// ignore this; a serving node reads accepted range-request streams from here.
    inbound_rx: tokio::sync::mpsc::Receiver<PeerStream>,
}

impl std::fmt::Debug for PeerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerSession").finish_non_exhaustive()
    }
}

impl PeerSession {
    /// Wrap an established mTLS byte stream in yamux as the **client** (outbound-stream opener) and
    /// spawn the driver. `io` is any tokio duplex stream (the mTLS [`tokio_rustls::client::TlsStream`]
    /// or, in tests, a loopback stream). Returns the session; open streams with
    /// [`Self::open_stream`] / [`Self::open_range_stream`].
    pub fn client<S>(io: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self::new(io, yamux::Mode::Client)
    }

    /// Wrap an established byte stream in yamux as the **server** (accepts inbound streams). Inbound
    /// streams the peer opens are delivered via [`Self::accept_stream`]. Provided for symmetry + the
    /// serving side of tests.
    pub fn server<S>(io: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self::new(io, yamux::Mode::Server)
    }

    fn new<S>(io: S, mode: yamux::Mode) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<MuxCommand>(64);
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel::<PeerStream>(64);
        let conn = yamux::Connection::new(io.compat(), yamux::Config::default(), mode);
        tokio::spawn(drive_connection(conn, cmd_rx, inbound_tx));
        PeerSession { cmd_tx, inbound_rx }
    }

    /// Open a new outbound logical stream to the peer. Cheap — open as many as you need to run
    /// concurrent transfers without head-of-line blocking.
    pub async fn open_stream(&mut self) -> io::Result<PeerStream> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(MuxCommand::OpenOutbound(tx))
            .await
            .map_err(|_| io::Error::other("mux driver closed"))?;
        let stream = rx
            .await
            .map_err(|_| io::Error::other("mux driver dropped request"))?
            .map_err(io::Error::other)?;
        Ok(stream.compat())
    }

    /// Accept the next inbound logical stream the peer opened (server side). Returns `None` when the
    /// connection has closed. A pure client never calls this.
    pub async fn accept_stream(&mut self) -> Option<PeerStream> {
        self.inbound_rx.recv().await
    }

    /// Open a `dig.fetchRange` stream for `req`: opens a fresh logical stream, writes the
    /// [`RangeRequest`] preamble, and returns the stream for the caller to read [`RangeFrame`]s from
    /// (via [`RangeFrame::decode`]) as they arrive. The building block for multi-source parallel
    /// range downloads — open one of these per (peer, range) and read them concurrently.
    pub async fn open_range_stream(&mut self, req: &RangeRequest) -> io::Result<PeerStream> {
        let mut stream = self.open_stream().await?;
        stream.write_all(&req.encode()).await?;
        stream.flush().await?;
        Ok(stream)
    }

    /// **Availability pre-check** (`dig.getAvailability`) — ask the peer which of `items` it holds,
    /// BEFORE opening any range streams. Opens a short-lived control stream, writes the batched
    /// [`AvailabilityRequest`], reads the [`AvailabilityResponse`]. A multi-source downloader runs
    /// this against candidate peers and only range-fetches from holders — the normative flow is:
    /// discover peers → `query_availability` (batch) → fan byte-ranges across holders → verify each
    /// vs the chain-anchored root → retry a bad range from another holder → reassemble.
    pub async fn query_availability(
        &mut self,
        items: Vec<AvailabilityItem>,
    ) -> io::Result<AvailabilityResponse> {
        let req = AvailabilityRequest { items };
        let mut stream = self.open_stream().await?;
        stream.write_all(&req.encode()).await?;
        stream.flush().await?;
        AvailabilityResponse::decode(&mut stream).await
    }
}

/// Drive one yamux [`Connection`](yamux::Connection): concurrently service open-outbound commands
/// and surface inbound streams, until the command channel closes (session dropped) or the connection
/// errors. This is the task that replaces yamux 0.12's `Control`.
///
/// `T` is the futures-io view of the byte stream (a `tokio-util` [`Compat`] of the tokio mTLS
/// stream), since yamux operates on `futures::AsyncRead + AsyncWrite`.
async fn drive_connection<T>(
    mut conn: yamux::Connection<T>,
    mut cmd_rx: tokio::sync::mpsc::Receiver<MuxCommand>,
    inbound_tx: tokio::sync::mpsc::Sender<PeerStream>,
) where
    T: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
{
    use std::future::poll_fn;

    loop {
        tokio::select! {
            // An open-outbound request from the session.
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(MuxCommand::OpenOutbound(reply)) => {
                        let res = poll_fn(|cx| conn.poll_new_outbound(cx)).await;
                        let _ = reply.send(res.map_err(|e| e.to_string()));
                    }
                    None => {
                        // Session dropped — close the connection and end the driver.
                        let _ = poll_fn(|cx| conn.poll_close(cx)).await;
                        return;
                    }
                }
            }
            // An inbound stream opened by the peer.
            inbound = poll_fn(|cx| conn.poll_next_inbound(cx)) => {
                match inbound {
                    Some(Ok(stream)) => {
                        // Deliver to a serving node; if no one is accepting, the stream is dropped.
                        let _ = inbound_tx.try_send(stream.compat());
                    }
                    Some(Err(_)) | None => {
                        // Connection closed / errored — end the driver.
                        return;
                    }
                }
            }
        }
    }
}
