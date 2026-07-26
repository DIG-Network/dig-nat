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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
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
    /// The raw ciphertext bytes. On the wire they are **base64** (`base64_bytes`) — the canonical
    /// `dig.fetchRange` frame encoding every producer emits.
    #[serde(with = "base64_bytes")]
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

/// Serde for [`RangeFrame::bytes`]: **base64** on the wire, raw `Vec<u8>` in Rust.
///
/// The `dig.fetchRange` frame is JSON, and the canonical wire type
/// (`dig_rpc_protocol::types::RangeFrame`, "this window's ciphertext, base64") — and every real
/// producer, including the dig-node peer serve path — encodes the window as a base64 STRING. Reading
/// it with `serde_bytes` instead yielded the string's literal characters, so a served window arrived
/// as its own base64 text and the reassembler rejected the frame (#1586, the read-leg blocker).
///
/// Deserialization is tolerant: a base64 string (canonical) OR a byte array (what an older dig-nat
/// emitted) both decode, so a mixed-version peer is never dropped.
mod base64_bytes {
    use base64::Engine as _;
    use serde::de::{SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        d.deserialize_any(Base64OrArray)
    }

    struct Base64OrArray;

    impl<'de> Visitor<'de> for Base64OrArray {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("base64-encoded ciphertext (or a legacy byte array)")
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
            base64::engine::general_purpose::STANDARD
                .decode(v)
                .map_err(|e| E::custom(format!("range frame bytes are not valid base64: {e}")))
        }

        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            Ok(v.to_vec())
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or_default());
            while let Some(b) = seq.next_element::<u8>()? {
                out.push(b);
            }
            Ok(out)
        }
    }
}

impl AvailabilityRequest {
    /// Serialize as a `u32` big-endian length prefix + JSON body (the uniform control framing).
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        encode_framed(self)
    }
    /// Read + decode an [`AvailabilityRequest`] from `r` (the peer/serving side).
    pub async fn decode<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Self> {
        decode_framed(r).await
    }
}

impl AvailabilityResponse {
    /// Serialize as a `u32` big-endian length prefix + JSON body.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
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
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        encode_framed(self)
    }
    /// Read + decode a [`RangeRequest`] preamble from `r` (the serving side of a range stream).
    pub async fn decode<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Self> {
        decode_framed(r).await
    }
}

impl RangeFrame {
    /// Serialize as a `u32` big-endian length prefix + JSON body (one framed frame on the stream).
    ///
    /// Fails with [`io::ErrorKind::InvalidData`] if [`bytes`](Self::bytes) exceeds
    /// [`MAX_RANGE_FRAME_PAYLOAD`], or if the serialized body exceeds [`MAX_FRAMED_BODY`] for any
    /// other reason (an unusually large `chunk_lens` table or proof). A serving peer therefore cannot
    /// emit a frame [`decode`](Self::decode) is required to reject: it splits its resource on
    /// [`MAX_RANGE_FRAME_PAYLOAD`] or it learns about it here, at the send site, with the ceiling
    /// named in the error.
    ///
    /// The payload is checked separately from the body because the body check alone is too weak: a
    /// payload well over the ceiling still fits in [`MAX_FRAMED_BODY`] once base64'd when the frame
    /// carries no metadata, so it would encode here and then overflow the moment the same span rode a
    /// FIRST frame with a chunk table attached — a size-dependent, intermittent failure. One explicit
    /// ceiling on `bytes` makes the limit the same for every frame.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        if self.bytes.len() > MAX_RANGE_FRAME_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "RangeFrame payload {} exceeds MAX_RANGE_FRAME_PAYLOAD {MAX_RANGE_FRAME_PAYLOAD}; \
                     split the range into ceiling-sized frames",
                    self.bytes.len()
                ),
            ));
        }
        encode_framed(self)
    }
    /// Read + decode one [`RangeFrame`] from `r`. Returns `Ok(None)` at clean end-of-stream (the
    /// reader hit EOF on a frame boundary), so a consumer loops until `None` or `complete`.
    pub async fn decode<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Self>> {
        decode_framed_opt(r).await
    }
}

/// Maximum length-prefixed frame BODY, in bytes — the one number both sides of the framing contract
/// obey. A decoder rejects a longer body (guarding against a malicious length prefix forcing a huge
/// allocation) and, since #1640, an encoder refuses to produce one, so a sender can never emit a
/// frame a conforming receiver is required to reject.
///
/// This is a **shared byte-identical wire constant**: any second implementation of DIG peer framing
/// — including `dig-node`'s own `write_framed`/`read_framed` — MUST use this exact value.
pub const MAX_FRAMED_BODY: usize = 64 * 1024;

/// Maximum raw [`RangeFrame::bytes`] length, in bytes, that a single frame may carry — the number a
/// serving peer splits a resource on. **32 KiB.**
///
/// ## Why it is not ~48 KiB
///
/// `bytes` travels base64 (4 output bytes per 3 input bytes), so [`MAX_FRAMED_BODY`] of body would
/// hold at most ~48 KiB of raw payload *if the payload were the only thing in the frame*. It is not.
/// The frame is JSON and, per #1577, the FIRST frame of every range additionally carries `root`,
/// `total_length`, `chunk_index`, a base64 `inclusion_proof`, and **the entire `chunk_lens` array of
/// the whole resource** — whose size is driven by the RESOURCE, not by the frame.
///
/// So the ceiling is deliberately CONSERVATIVE rather than exact-fit:
///
/// | component | budget |
/// |---|---|
/// | base64 of 32 KiB of `bytes` | 43,692 B |
/// | remaining allowance for JSON keys + `chunk_lens` + proof + root | 21,844 B |
/// | **total** | **65,536 B** = [`MAX_FRAMED_BODY`] |
///
/// **Resist tightening it.** An exact-fit constant satisfies a naive round-trip test and then
/// overflows in production on the first resource with a large chunk table — which is precisely the
/// class of defect #1640 was.
///
/// ## The allowance does NOT cover every permitted resource
///
/// It is bounded, and the bound is [`MAX_FIRST_FRAME_CHUNK_LENS`] — read that before assuming this
/// ceiling makes any legal range answerable. It does not.
pub const MAX_RANGE_FRAME_PAYLOAD: usize = 32 * 1024;

/// The largest `chunk_lens` array, in entries, that is GUARANTEED to fit on a first frame alongside a
/// [`MAX_RANGE_FRAME_PAYLOAD`]-sized payload, whatever the chunk lengths are: **2,891**.
///
/// Published as a number rather than a formula because a wrong premise hid inside the derivation
/// twice: first a 256 KiB chunk-size assumption (the canonical Digstore chunker is FastCDC with a
/// **64 KiB target**, min 16 KiB, max 256 KiB — `digs crates/digstore-chunker/src/config.rs:26`), then
/// the entries' DECIMAL WIDTH, which the array's JSON size depends on just as much as its length.
///
/// Measured against the real serializer, with a ceiling-sized payload, a 1,400-byte base64
/// `inclusion_proof` and a 64-hex `root` — the shape of a real first frame:
///
/// | `chunk_lens` entries | body, 5-digit lengths | body, 6-digit lengths |
/// |---|---|---|
/// | 2,048 | 57,586 B | 59,634 B |
/// | **2,891** | 62,913 B | **65,535 B — the guaranteed bound** |
/// | 2,892 | — | 65,542 B (over by 6) |
/// | 3,373 | 65,536 B (exact fit at 5 digits) | 68,909 B (over by 3,373) |
/// | 4,096 | 69,874 B (over by 4,338) | 73,970 B (over by 8,434) |
/// | 8,192 | 94,450 B | 102,642 B |
///
/// This constant is the **6-digit** column, because a chunk may legally be up to the 256 KiB maximum
/// and six digits is therefore the worst case per entry. A caller whose chunk lengths all happen to be
/// under 100,000 — which is the case at both the 64 KiB target and the 16 KiB minimum — gets 3,373
/// instead, but **do not rely on that**: it is a property of the data, not of the protocol.
///
/// In resource terms, 2,891 entries is about **180 MiB** at the 64 KiB target chunk size and about
/// **45 MiB** at the 16 KiB minimum.
///
/// ## Known limitation — a permitted resource can have NO conforming first frame (#1640)
///
/// The ecosystem already permits resources past this bound: `digstore-host` sets
/// `MAX_MODULE_BYTES = 256 MiB` (~4,096 chunks at the 64 KiB target — the 4,096 row above), and
/// dig-download accepts up to `MAX_MODULE_CHUNK_COUNT = 1,048,576`. For such a resource a holder that
/// splits on [`MAX_RANGE_FRAME_PAYLOAD`] produces a first frame [`RangeFrame::encode`] must refuse —
/// and **surrendering the payload entirely stops helping at 9,133 entries**, where the metadata ALONE
/// fills the body.
///
/// So this is NOT a constant to re-tune: no value of [`MAX_RANGE_FRAME_PAYLOAD`] fixes it, because
/// past ~9,133 chunks the metadata alone exceeds [`MAX_FRAMED_BODY`] regardless of payload. The
/// resolution is a wire-shape change — the resource-scaling metadata (`chunk_lens`, `inclusion_proof`)
/// moves off every frame and onto the first frame or a paged prologue sent once per range stream — and
/// **that shape lands in 0.13.0**. Until then a range past this bound hard-fails at the SENDER rather
/// than corrupting a read at the receiver, which is the correct half of the trade.
///
/// Do NOT work around it locally: raising [`MAX_FRAMED_BODY`] is a RECEIVER bound (no sender may exceed
/// it until every receiver is deployed, and no finite cap holds `MAX_MODULE_CHUNK_COUNT` = 1,048,576
/// entries without abandoning the bounded-allocation property the cap exists for), and truncating
/// `chunk_lens` is not an option either — it is a DECRYPT input, since per-chunk AES-256-GCM-SIV needs
/// the whole array and a reader rejects any array whose sum differs from `total_length`.
pub const MAX_FIRST_FRAME_CHUNK_LENS: usize = 2_891;

/// Serialize `value` as a `u32` big-endian length prefix + JSON body — the uniform framing for every
/// control message on a stream (availability + range preambles, and the range frames themselves).
///
/// Fails with [`io::ErrorKind::InvalidData`] if the body would exceed [`MAX_FRAMED_BODY`]. That check
/// is the whole point: the decoders below MUST reject such a body, so producing one is a bug at the
/// SENDER and belongs at the sender's call site — not as an opaque `InvalidData` surfacing on some
/// remote peer's read.
fn encode_framed<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    let body =
        serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if body.len() > MAX_FRAMED_BODY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "framed body {} exceeds MAX_FRAMED_BODY {MAX_FRAMED_BODY}; split the payload on \
                 MAX_RANGE_FRAME_PAYLOAD ({MAX_RANGE_FRAME_PAYLOAD})",
                body.len()
            ),
        ));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
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
    /// Set + notified when the driver task ends (the underlying byte stream closed — a clean close or
    /// a transport error). Observed via [`Self::closed_handle`] so fast-connect can detect a transport
    /// dying and fall back without holding the session lock.
    closed_flag: Arc<AtomicBool>,
    closed_notify: Arc<Notify>,
}

/// A cheap, cloneable observer of a [`PeerSession`]'s underlying byte stream closing (the mux driver
/// task ending — a clean close OR a transport error). Fast-connect's promotion guard holds one to
/// detect the active transport dying and fall back to another tier, without locking the session.
#[derive(Clone)]
pub struct ClosedHandle {
    flag: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl ClosedHandle {
    /// Whether the session's transport has already closed.
    pub fn is_closed(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }

    /// Resolve once the session's transport has closed (returns immediately if already closed).
    pub async fn closed(&self) {
        loop {
            if self.flag.load(Ordering::Acquire) {
                return;
            }
            // Arm the wait, then re-check the flag: the driver sets the flag BEFORE
            // `notify_waiters`, so a close that races this arming is caught by the recheck (no lost
            // wakeup).
            let notified = self.notify.notified();
            if self.flag.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
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
        let closed_flag = Arc::new(AtomicBool::new(false));
        let closed_notify = Arc::new(Notify::new());
        tokio::spawn(drive_connection(
            conn,
            cmd_rx,
            inbound_tx,
            Arc::clone(&closed_flag),
            Arc::clone(&closed_notify),
        ));
        PeerSession {
            cmd_tx,
            inbound_rx,
            closed_flag,
            closed_notify,
        }
    }

    /// A cloneable observer of this session's transport closing — see [`ClosedHandle`].
    pub fn closed_handle(&self) -> ClosedHandle {
        ClosedHandle {
            flag: Arc::clone(&self.closed_flag),
            notify: Arc::clone(&self.closed_notify),
        }
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
        stream.write_all(&req.encode()?).await?;
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
        stream.write_all(&req.encode()?).await?;
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
    closed_flag: Arc<AtomicBool>,
    closed_notify: Arc<Notify>,
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
                        break;
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
                        break;
                    }
                }
            }
        }
    }

    // The transport is gone: publish closure (flag BEFORE notify, so `ClosedHandle::closed`'s
    // arm-then-recheck can never miss the wakeup).
    closed_flag.store(true, Ordering::Release);
    closed_notify.notify_waiters();
}
