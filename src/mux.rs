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
//! (`{offset, length, bytes, complete}`, plus the fixed-size identity set `root` + `total_length` +
//! `chunk_count` on every frame and the resource-scaling `chunk_lens` + `inclusion_proof` once per
//! stream, paged by `chunk_lens_offset`). Per-chunk integrity (split by `chunk_lens`, verify
//! the whole-resource inclusion proof vs the chain-anchored `root`, AES-256-GCM-SIV-open) is done by
//! the CONTENT layer above dig-nat; dig-nat carries these frames faithfully over the mux transport.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use crate::safe_text::SafeText;

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
#[non_exhaustive]
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
#[non_exhaustive]
pub struct AvailabilityRequest {
    /// The items to check, batched.
    pub items: Vec<AvailabilityItem>,
}

/// One answer in an [`AvailabilityResponse`], positionally aligned with the request `items`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct AvailabilityResponse {
    /// One answer per queried item, in request order.
    pub items: Vec<AvailabilityAnswer>,
}

/// A byte-range request (`dig.fetchRange`, L7 spec §9) written at the start of a range-scoped stream.
/// Identifies a resource (`store_id` + `retrieval_key` [+ `root`]) or a whole capsule
/// (`capsule: true`, identified by `store_id` [+ `root`]) and the `[offset, offset+length)` range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
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
    /// Suppress the resource-scaling layout metadata (`chunk_lens` + `inclusion_proof`) on this
    /// stream's frames, because the client already holds the commitment for this `root`.
    ///
    /// A client that has already read the layout once — a resumed download, a second range of the same
    /// resource, a parallel fetch from another holder — does not need it again, and for a large
    /// resource re-sending it costs a paged prologue per stream. Absent or `false` preserves the
    /// pre-0.13.0 behaviour, so an older holder that ignores this field is never broken by it: it
    /// simply sends metadata the client discards. The fixed-size identity fields (`root`,
    /// `total_length`, `chunk_count`, `chunk_index`) are NOT suppressed — they are what detects a
    /// wrong-generation holder on arrival.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_layout: Option<bool>,
}

/// One streamed `dig.fetchRange` frame (L7 spec §8 framing). Frames arrive in ascending `offset`
/// order and tile the requested range exactly; the caller reassembles by `offset` and stops on
/// `complete`.
///
/// ## The metadata splits into two sets, and which frames carry them differs
///
/// Read this before implementing either side — the two halves have different rules, and conforming to
/// the wrong half produces a verification miss on a multi-frame read rather than a clean failure.
///
/// - **Identity — fixed-size, on EVERY frame:** `root`, `total_length`, `chunk_count`, plus
///   `chunk_index` where the window is chunk-aligned. These are what let a reader reject a
///   wrong-generation or wrong-layout holder the moment a frame arrives, which is a property the
///   once-per-stream set can never have. They cost a bounded number of bytes, so carrying them
///   everywhere is cheap. Set them with [`with_identity`](Self::with_identity) +
///   [`with_chunk_index`](Self::with_chunk_index).
/// - **Prologue — resource-scaling, ONCE per range stream:** `chunk_lens` (paged, located by
///   `chunk_lens_offset`) and `inclusion_proof`. Their size is a function of the RESOURCE rather than of
///   the frame, so they ride the first frame or a paged prologue and **MUST NOT** be repeated on later
///   frames. Set them with [`with_chunk_lens_page`](Self::with_chunk_lens_page) +
///   [`with_inclusion_proof`](Self::with_inclusion_proof), or omit them entirely when the request set
///   [`RangeRequest::skip_layout`].
///
/// Before 0.13.0 every one of these was "first frame only", because the whole layout had to fit one
/// frame or the range was unservable (#1640). `SPEC.md` §5.1.1 is normative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
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
    /// **(identity — every frame)** the full resource ciphertext length.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_length: Option<u64>,
    /// **(prologue — once per stream)** per-chunk ciphertext lengths of the whole resource, in order,
    /// or ONE PAGE of them beginning at `chunk_lens_offset`.
    ///
    /// Resource-scaling, so it MUST NOT be repeated on later frames: on a later frame it was only a
    /// redundant equality check on an array the client already held. Omitted entirely when the request
    /// set [`RangeRequest::skip_layout`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_lens: Option<Vec<u64>>,
    /// **(identity — every frame, where the window is chunk-aligned)** index into the resource's
    /// `chunk_lens` array of the first chunk in THIS frame.
    ///
    /// Fixed-size, and about this frame rather than about the resource, so a chunk-aligned continuation
    /// frame states it too — see [`with_chunk_index`](Self::with_chunk_index), which is deliberately
    /// separate from the proof setter so stating alignment never costs a repeated proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_index: Option<u64>,
    /// **(prologue — once per stream)** merkle inclusion proof of the whole resource vs the generation
    /// `root` (base64, relayed verbatim); `null`/absent for `capsule: true` (self-verifying on install).
    ///
    /// Resource-scaling and capped at [`MAX_INCLUSION_PROOF_B64`]. At 4,096 B it would consume the
    /// entire remaining frame budget if repeated, which is the concrete reason "once per stream" is a
    /// MUST NOT rather than a preference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inclusion_proof: Option<String>,
    /// **(identity — every frame)** the generation root (64-hex) this range is served from, and which
    /// the inclusion proof is against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// **(identity — every frame)** the resource's TOTAL chunk count — how many entries the
    /// reassembled `chunk_lens` array has.
    ///
    /// Together with `root` and `total_length` it is what lets a reader detect a wrong-generation or
    /// wrong-layout holder the moment a frame arrives. It is also how a reader sizes the array it is
    /// paging in, and how it knows the prologue is complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_count: Option<u64>,
    /// **(prologue — once per page)** the index into the resource's `chunk_lens` array at which THIS
    /// frame's `chunk_lens` page begins — how a **paged prologue** is located and reassembled.
    ///
    /// A resource whose layout exceeds [`MAX_CHUNK_LENS_PER_FRAME`] cannot state it on one frame, so
    /// the sender pages it: successive frames each carry up to that many entries, stamped with the
    /// offset they start at. A reader places each page at its offset and has the whole array once it
    /// holds `chunk_count` entries. Absent means "this frame's `chunk_lens`, if any, begins at 0" — the
    /// single-frame layout, which is the pre-0.13.0 shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_lens_offset: Option<u64>,
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

impl AvailabilityItem {
    /// A *has_store* query — does the peer hold anything for this store?
    pub fn store(store_id: impl Into<String>) -> Self {
        AvailabilityItem {
            store_id: store_id.into(),
            root: None,
            retrieval_key: None,
        }
    }

    /// Narrow the query to one generation `root` — a *has_root* query for the capsule `store_id:root`.
    pub fn with_root(mut self, root: impl Into<String>) -> Self {
        self.root = Some(root.into());
        self
    }

    /// Narrow the query to one resource — a *has_resource* query.
    pub fn with_retrieval_key(mut self, retrieval_key: impl Into<String>) -> Self {
        self.retrieval_key = Some(retrieval_key.into());
        self
    }
}

impl AvailabilityRequest {
    /// A batched availability pre-check over `items`.
    pub fn new(items: Vec<AvailabilityItem>) -> Self {
        AvailabilityRequest { items }
    }

    /// Serialize as a `u32` big-endian length prefix + JSON body (the uniform control framing).
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        encode_framed(self)
    }
    /// Read + decode an [`AvailabilityRequest`] from `r` (the peer/serving side).
    pub async fn decode<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Self> {
        decode_framed(r).await
    }
}

impl AvailabilityAnswer {
    /// The peer holds the queried item. Describe WHAT it holds with the `with_*` setters.
    pub fn available() -> Self {
        AvailabilityAnswer::with_availability(true)
    }

    /// The peer does not hold the queried item — the whole answer, since no other field is meaningful.
    pub fn unavailable() -> Self {
        AvailabilityAnswer::with_availability(false)
    }

    fn with_availability(available: bool) -> Self {
        AvailabilityAnswer {
            available,
            roots: None,
            total_length: None,
            chunk_count: None,
            complete: None,
        }
    }

    /// (store granularity) the generation roots held for the store, newest-first.
    pub fn with_roots(mut self, roots: Vec<String>) -> Self {
        self.roots = Some(roots);
        self
    }

    /// (root/resource granularity) the resource's ciphertext length, so the caller can plan its ranges.
    pub fn with_total_length(mut self, total_length: u64) -> Self {
        self.total_length = Some(total_length);
        self
    }

    /// (root/resource granularity) the resource's chunk count.
    pub fn with_chunk_count(mut self, chunk_count: u64) -> Self {
        self.chunk_count = Some(chunk_count);
        self
    }

    /// Whether the peer holds the FULL resource/capsule rather than only part of it.
    pub fn with_complete(mut self, complete: bool) -> Self {
        self.complete = Some(complete);
        self
    }
}

impl AvailabilityResponse {
    /// The answers to an [`AvailabilityRequest`], positionally aligned with its `items`.
    pub fn new(items: Vec<AvailabilityAnswer>) -> Self {
        AvailabilityResponse { items }
    }

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
        RangeRequest::resource_or_capsule(
            store_id,
            Some(retrieval_key.into()),
            false,
            offset,
            length,
        )
    }

    /// A range request for a whole capsule / `.dig`, identified by `store_id` (plus a `root` if the
    /// caller pins a generation).
    pub fn capsule(store_id: impl Into<String>, offset: u64, length: u64) -> Self {
        RangeRequest::resource_or_capsule(store_id, None, true, offset, length)
    }

    fn resource_or_capsule(
        store_id: impl Into<String>,
        retrieval_key: Option<String>,
        capsule: bool,
        offset: u64,
        length: u64,
    ) -> Self {
        RangeRequest {
            store_id: store_id.into(),
            retrieval_key,
            root: None,
            capsule,
            offset,
            length,
            skip_layout: None,
        }
    }

    /// Pin the request to one generation `root` (64-hex) rather than the chain-anchored tip.
    pub fn with_root(mut self, root: impl Into<String>) -> Self {
        self.root = Some(root.into());
        self
    }

    /// Ask the holder to omit the resource-scaling layout metadata, because this client already holds
    /// the commitment for this `root`. See [`RangeRequest::skip_layout`].
    pub fn with_skip_layout(mut self, skip_layout: bool) -> Self {
        self.skip_layout = Some(skip_layout);
        self
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
    /// A **data frame**: `bytes` at `offset`, with no metadata — the shape of every continuation frame.
    ///
    /// `length` is derived from `bytes`, since a frame that misdeclares its own payload length is never
    /// what a serve path wants. The metadata a FIRST frame or a prologue page carries is layered on with
    /// the `with_*` setters, so a continuation frame cannot accidentally claim a layout it is not
    /// stating — the two shapes are different call chains, not one call with a pile of `None`s.
    pub fn data(offset: u64, bytes: Vec<u8>) -> Self {
        RangeFrame {
            offset,
            length: bytes.len() as u64,
            bytes,
            complete: false,
            total_length: None,
            chunk_lens: None,
            chunk_index: None,
            inclusion_proof: None,
            root: None,
            chunk_count: None,
            chunk_lens_offset: None,
        }
    }

    /// Mark this as the final frame of the range.
    pub fn with_complete(mut self, complete: bool) -> Self {
        self.complete = complete;
        self
    }

    /// The fixed-size identity metadata EVERY frame of a range should carry: the generation `root`
    /// (64-hex) the range is served from, the resource's ciphertext `total_length`, and its
    /// `chunk_count`.
    ///
    /// These three are what let a reader reject a wrong-generation or wrong-layout holder the moment a
    /// frame arrives — which the resource-scaling metadata never could, since it arrives once. They are
    /// fixed-size, so carrying them everywhere costs a bounded number of bytes.
    pub fn with_identity(
        mut self,
        root: impl Into<String>,
        total_length: u64,
        chunk_count: u64,
    ) -> Self {
        self.root = Some(root.into());
        self.total_length = Some(total_length);
        self.chunk_count = Some(chunk_count);
        self
    }

    /// A page of the resource's `chunk_lens` array, beginning at entry `chunk_lens_offset`.
    ///
    /// Call it once with offset `0` for a layout that fits one frame (at most
    /// [`MAX_CHUNK_LENS_PER_FRAME`] entries), or once per page of a **paged prologue**. `chunk_lens` is
    /// a DECRYPT input — per-chunk AES-GCM-SIV needs the WHOLE array, and a reader rejects an array
    /// whose sum differs from `total_length` — so a page is only ever useful as part of a complete set.
    pub fn with_chunk_lens_page(mut self, chunk_lens_offset: u64, chunk_lens: Vec<u64>) -> Self {
        self.chunk_lens_offset = Some(chunk_lens_offset);
        self.chunk_lens = Some(chunk_lens);
        self
    }

    /// Split a whole resource's `chunk_lens` into the pages of a **paged prologue**: `(offset, page)`
    /// pairs, in order, each ready for [`with_chunk_lens_page`](Self::with_chunk_lens_page).
    ///
    /// This is the encoder half of the paging rule, and it exists so that no serve path re-derives that
    /// rule by hand. #1640 was an encode/decode asymmetry, so the split and its mirror
    /// [`ChunkLensAssembler`] are published together from one module: the pages this returns are exactly
    /// the pages the assembler requires — aligned offsets, [`MAX_CHUNK_LENS_PER_FRAME`] entries each
    /// except a shorter tail, tiling the array with no gap and no overlap.
    ///
    /// A layout at or under the threshold yields a single page at offset 0, which is the single-frame
    /// pre-0.13.0 shape; an empty layout yields no pages at all.
    pub fn split_chunk_lens_pages(chunk_lens: &[u64]) -> Vec<(u64, Vec<u64>)> {
        chunk_lens
            .chunks(MAX_CHUNK_LENS_PER_FRAME)
            .enumerate()
            .map(|(page, entries)| ((page * MAX_CHUNK_LENS_PER_FRAME) as u64, entries.to_vec()))
            .collect()
    }

    /// Where this frame starts in the resource's chunk sequence — the index into `chunk_lens` of its
    /// first chunk, for a chunk-aligned window.
    ///
    /// Fixed-size **identity**, so a chunk-aligned CONTINUATION frame states it too, not only the first
    /// frame. It has its own setter for exactly that reason: it used to be a parameter of
    /// [`with_inclusion_proof`](Self::with_inclusion_proof), which meant the one field every reader wants
    /// on every frame could not be stated without repeating a once-per-stream proof — a `SPEC.md` §5.1.1
    /// MUST NOT, and 4,096 B per frame against a budget with zero slack.
    pub fn with_chunk_index(mut self, chunk_index: u64) -> Self {
        self.chunk_index = Some(chunk_index);
        self
    }

    /// The merkle inclusion proof of the whole resource against the generation `root` (base64, relayed
    /// verbatim).
    ///
    /// Resource-scaling, so it rides the first frame or the prologue — once per range stream, never
    /// repeated. Base64 longer than [`MAX_INCLUSION_PROOF_B64`] is refused by
    /// [`encode`](Self::encode): such a resource has no conforming range stream at all, and the holder
    /// must say so rather than stream frames a reader cannot verify.
    pub fn with_inclusion_proof(mut self, inclusion_proof: impl Into<String>) -> Self {
        self.inclusion_proof = Some(inclusion_proof.into());
        self
    }

    /// Override the declared `length`, which [`data`](Self::data) otherwise derives from `bytes`.
    ///
    /// For budget fixtures that hold every scalar at its widest legal value. A serve path has no reason
    /// to call this: a frame whose `length` disagrees with its payload is a frame the reader distrusts.
    pub fn with_declared_length(mut self, length: u64) -> Self {
        self.length = length;
        self
    }

    /// Serialize as a `u32` big-endian length prefix + JSON body (one framed frame on the stream).
    ///
    /// Fails with [`io::ErrorKind::InvalidData`] if [`bytes`](Self::bytes) exceeds
    /// [`MAX_RANGE_FRAME_PAYLOAD`], if [`inclusion_proof`](Self::inclusion_proof) exceeds
    /// [`MAX_INCLUSION_PROOF_B64`], or if the serialized body exceeds [`MAX_FRAMED_BODY`] for any
    /// other reason (an unusually large `chunk_lens` page). A serving peer therefore cannot
    /// emit a frame [`decode`](Self::decode) is required to reject: it splits its resource on
    /// [`MAX_RANGE_FRAME_PAYLOAD`] or it learns about it here, at the send site, with the ceiling
    /// named in the error.
    ///
    /// The payload is checked separately from the body because the body check alone is too weak: a
    /// payload well over the ceiling still fits in [`MAX_FRAMED_BODY`] once base64'd when the frame
    /// carries no metadata, so it would encode here and then overflow the moment the same span rode a
    /// FIRST frame with a chunk table attached — a size-dependent, intermittent failure. One explicit
    /// ceiling on `bytes` makes the limit the same for every frame. The proof is checked for the same
    /// reason: it is **premise 2** of [`MAX_FIRST_FRAME_CHUNK_LENS`], and a premise only a test believes
    /// is not a bound (#1655).
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
        if let Some(proof) = &self.inclusion_proof {
            if proof.len() > MAX_INCLUSION_PROOF_B64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "RangeFrame inclusion_proof {} exceeds MAX_INCLUSION_PROOF_B64 \
                         {MAX_INCLUSION_PROOF_B64}; the resource has no conforming range stream, so \
                         answer RANGE_METADATA_UNREPRESENTABLE rather than streaming frames",
                        proof.len()
                    ),
                ));
            }
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

/// Maximum length of a base64 [`RangeFrame::inclusion_proof`], in bytes: **4,096** — enough for a
/// 96-level merkle path, and **premise 2 of [`MAX_FIRST_FRAME_CHUNK_LENS`]**.
///
/// Published and enforced from 0.13.0. Before that it lived only in a test-local `const` and in prose,
/// so the word GUARANTEED on the entry bound rested on a cap nothing checked: an 8 KiB proof made a
/// *sub*-bound resource unsendable, which the published bound says cannot happen (#1655).
/// [`RangeFrame::encode`] now refuses an over-cap proof at the SENDER, naming this constant.
///
/// Widening it is not a local decision: every byte added here comes out of
/// [`MAX_FIRST_FRAME_CHUNK_LENS`], which must then be re-derived and re-published. A proof that does
/// not fit is a resource with NO conforming range stream — the holder answers a structured
/// `RANGE_METADATA_UNREPRESENTABLE` error rather than streaming an unverifiable frame.
///
/// This is a **shared byte-identical wire constant**: every implementation of DIG peer framing MUST
/// use this exact value.
pub const MAX_INCLUSION_PROOF_B64: usize = 4096;

/// The `chunk_lens` entries a serving peer puts on ONE frame before it starts **paging the prologue**:
/// **2,048**.
///
/// This is the SENDER's threshold, deliberately below the hard arithmetic ceiling
/// [`MAX_FIRST_FRAME_CHUNK_LENS`]; the gap between the two is margin, and collapsing one into the other
/// removes the only slack the budget has. A resource whose layout exceeds this is described by a
/// **paged prologue**: successive frames each carry up to this many entries, and every page states the
/// [`RangeFrame::chunk_lens_offset`] it begins at, so the reader reassembles one array of
/// [`RangeFrame::chunk_count`] entries before it decrypts.
///
/// This is a **shared byte-identical wire constant**: every implementation of DIG peer framing MUST
/// use this exact value.
pub const MAX_CHUNK_LENS_PER_FRAME: usize = 2048;

/// The largest `chunk_lens` array, in entries, that is GUARANTEED to fit on a first frame: **2,486**.
///
/// ## The four maxima this is derived against — all of them, simultaneously
///
/// Read these before using or changing the number. The same budget has been derived wrong three times,
/// each time because ONE of these stayed implicit, and each time in the UNSAFE direction — too
/// generous, which lets a conforming sender emit a frame the receiver must reject, i.e. exactly the
/// defect #1640 exists to close.
///
/// 1. **Payload at its cap** — [`MAX_RANGE_FRAME_PAYLOAD`] (32,768 B raw → 43,692 B base64).
/// 2. **Inclusion proof at its cap** — `MAX_INCLUSION_PROOF_B64` = 4,096 B. *(The 2,891 figure this
///    constant replaces held the proof at ~1,400 B, so it only fit a small-proof frame: at 2,891
///    entries the body is 64,199 B with no proof, 65,223 B at a 1,024 B proof, and 68,295 B at the
///    real cap.)*
/// 3. **Entries at their maximum decimal WIDTH** — a chunk may legally be 256 KiB, and `chunk_lens` is
///    JSON decimal, so a worst-case entry is SIX digits. *(The 3,373 figure assumed five, from a wrong
///    premise that the chunker targets 256 KiB; it is FastCDC target **64 KiB**, min 16 KiB, max
///    256 KiB — `digs crates/digstore-chunker/src/config.rs`.)*
/// 4. **Every `u64` scalar at max width, including the 0.13.0 ones** — `offset`, `length`,
///    `total_length`, `chunk_index`,
///    `chunk_count`, `chunk_lens_offset`, each at 20 digits. Deliberately stricter than the
///    protocol-tight widths (`length` ≤ 32,768 is 5 digits, `chunk_index` and `chunk_count`
///    ≤ 1,048,576 are 7). That slack is given up on purpose: a bound that depends on a scalar
///    happening to be small is a bound with a fifth implicit premise. Holding `chunk_count` at 7
///    digits rather than 20 is worth 13 B — very nearly two entries — which is exactly the size of
///    mistake this rule exists to prevent.
///
/// Measured on the **real 0.13.0 struct**, `chunk_count` and `chunk_lens_offset` included. It was
/// pre-derived against those fields before they existed — via a mirror struct, which reserved a measured
/// 76 B — and the reservation proved exact: the number did NOT move when the fields landed. That is the
/// technique worth reusing, because this bound has **zero** slack (65,536 B, the cap exactly), so any
/// further field WILL move it, and only the both-sides pin in `tests/framing_ceiling.rs` will say so.
///
/// ## Measured, never argued
///
/// Every figure here comes from serializing the real struct. Bodies at the four maxima, by entry
/// width, on the 0.13.0 field set:
///
/// | `chunk_lens` entries | 5-digit entries | 6-digit entries |
/// |---|---|---|
/// | 2,048 | 60,422 B | 62,470 B |
/// | **2,486** | 63,050 B | **65,536 B — the bound, exactly at the cap** |
/// | 2,487 | 63,056 B | 65,543 B (over by 7) |
/// | 2,495 | 63,104 B | 65,599 B (over by 63) |
/// | 2,891 | 65,480 B | 68,371 B (over by 2,835) |
/// | 4,096 | 72,710 B | 76,806 B |
///
/// At five-digit entries 2,900 would fit, but that is a property of the DATA, not of the protocol —
/// never rely on it.
///
/// In resource terms 2,486 entries is about **155 MiB** at the 64 KiB target chunk size and about
/// **38 MiB** at the 16 KiB minimum.
///
/// ## Not the same number as the sender's paging threshold
///
/// `MAX_CHUNK_LENS_PER_FRAME` = 2,048 is the 0.13.0 SENDER threshold — where a serve path starts
/// paging the prologue (62,470 B at these same maxima). This constant is the hard ARITHMETIC ceiling.
/// Two numbers doing two different jobs, and **the gap between them is deliberate margin**; do not
/// collapse one into the other.
///
/// ## This is a CEILING, not the largest servable resource (#1640, resolved in 0.13.0)
///
/// The ecosystem permits resources far past this bound — `digstore-host` sets
/// `MAX_MODULE_BYTES = 256 MiB` (~4,096 chunks at the 64 KiB target, the last row above) and
/// dig-download accepts `MAX_MODULE_CHUNK_COUNT = 1,048,576` — and they are all servable, because the
/// resource-scaling metadata no longer has to fit one frame: it rides a **paged prologue**
/// ([`MAX_CHUNK_LENS_PER_FRAME`] entries per page, each located by
/// [`RangeFrame::chunk_lens_offset`]). A 1,048,576-chunk layout costs roughly 7.3 MB across about 512
/// pages, once per range stream — and nothing at all when the client sets
/// [`RangeRequest::skip_layout`] because it already holds the layout.
///
/// So this constant governs how much layout ONE frame may state, which is why it is still the number a
/// sender must respect and never the number a resource must fit under. Before 0.13.0 the two were the
/// same thing, and a resource past the bound simply had no conforming first frame: [`RangeFrame::encode`]
/// refused it, hard-failing LOUDLY at the sender rather than corrupting a read at the receiver — the
/// correct half of the trade, but only half. Surrendering the payload entirely bought only so much room:
/// past **8,727 entries** the metadata ALONE fills the body, which is why no value of
/// [`MAX_RANGE_FRAME_PAYLOAD`] was ever the fix and the wire shape had to change.
///
/// Two workarounds remain forbidden, for reasons that did not go away: raising [`MAX_FRAMED_BODY`] is a
/// RECEIVER bound (no sender may exceed it until every receiver is deployed, and no finite cap holds a
/// million entries without abandoning the bounded-allocation property the cap exists for), and
/// truncating `chunk_lens` is not an option either — it is a DECRYPT input, since per-chunk
/// AES-256-GCM-SIV needs the whole array and a reader rejects any array whose sum differs from
/// `total_length`. The ONE remaining unrepresentable input is an `inclusion_proof` over
/// [`MAX_INCLUSION_PROOF_B64`]; such a resource has no conforming range stream at all, and the holder
/// says so with a structured `RANGE_METADATA_UNREPRESENTABLE` error instead of streaming frames.
pub const MAX_FIRST_FRAME_CHUNK_LENS: usize = 2_486;

/// The largest `chunk_count` a reader will reassemble a layout for: **1,048,576 entries**.
///
/// It bounds the ONE allocation a paged prologue makes from a peer-declared number. At the ceiling the
/// array is 1,048,576 × 8 B = **8 MB** of `u64`, which is the whole derivation: a bounded, affordable
/// worst case per in-flight stream. Above it a reader refuses rather than sizes itself to a stranger's
/// claim — a ~64-byte frame declaring a vast count is otherwise a memory-exhaustion primitive, and one
/// such frame has already aborted a node.
///
/// It mirrors dig-download's `MAX_MODULE_CHUNK_COUNT`, deliberately: the two are the same bound seen
/// from the transport and from the content layer, so they must not drift apart. At the ~64 KiB FastCDC
/// target this ceiling is about 64 GiB of resource, far past any size the ecosystem permits
/// (`digstore-host`'s `MAX_MODULE_BYTES` is 256 MiB), so it constrains a liar and never an honest holder.
///
/// This is a **shared byte-identical wire constant**: every implementation of DIG paged-prologue
/// reassembly MUST use this exact value.
pub const MAX_RESOURCE_CHUNK_COUNT: usize = 1_048_576;

/// Why a [`ChunkLensAssembler`] refused a page, or refused to yield an array.
///
/// Each variant is ONE rejection with its own name. That is deliberate: a guard justified by a single
/// attacker behaviour ("a liar sends a short page") is bypassed by the next variant of it — a *middle*
/// page rather than a last one, a repeated page rather than a missing one, an offset off by one rather
/// than wildly wrong. Naming each member of the class separately is what lets a consumer report, and a
/// test pin, the specific rule that was broken instead of a generic "bad prologue".
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChunkLensError {
    /// The declared `chunk_count` exceeds [`MAX_RESOURCE_CHUNK_COUNT`]. Refused BEFORE allocating.
    #[error(
        "declared chunk_count {chunk_count} exceeds MAX_RESOURCE_CHUNK_COUNT {MAX_RESOURCE_CHUNK_COUNT}"
    )]
    ChunkCountTooLarge {
        /// The count the sender declared.
        chunk_count: usize,
    },

    /// The array for a legal `chunk_count` could not be allocated on this host. A resource ceiling is
    /// not a memory guarantee, so the reservation is fallible and its failure is an error rather than an
    /// abort.
    #[error("cannot reserve a {chunk_count}-entry chunk_lens array ({bytes} bytes)")]
    AllocationFailed {
        /// The count that could not be reserved.
        chunk_count: usize,
        /// The reservation size in bytes.
        bytes: usize,
    },

    /// A page carrying no entries. It fills nothing, so accepting it would let a sender stream frames
    /// indefinitely without ever completing the prologue.
    #[error("chunk_lens page at offset {offset} is empty")]
    EmptyPage {
        /// The offset the empty page claimed.
        offset: u64,
    },

    /// A page carrying more than [`MAX_CHUNK_LENS_PER_FRAME`] entries — a wire-constant violation,
    /// independent of where the page claims to sit.
    #[error(
        "chunk_lens page of {entries} entries exceeds MAX_CHUNK_LENS_PER_FRAME {MAX_CHUNK_LENS_PER_FRAME}"
    )]
    PageTooLarge {
        /// The page's entry count.
        entries: usize,
    },

    /// A `chunk_lens_offset` that is not a multiple of [`MAX_CHUNK_LENS_PER_FRAME`]. Pages are placed by
    /// page index, so a misaligned page would straddle two slots and make occupancy unanswerable.
    #[error(
        "chunk_lens_offset {offset} is not a multiple of MAX_CHUNK_LENS_PER_FRAME {MAX_CHUNK_LENS_PER_FRAME}"
    )]
    MisalignedOffset {
        /// The offset the page claimed.
        offset: u64,
    },

    /// A `chunk_lens_offset` at or beyond the declared `chunk_count` — there is no such entry to fill.
    #[error("chunk_lens_offset {offset} is beyond the declared chunk_count {chunk_count}")]
    OffsetOutOfRange {
        /// The offset the page claimed.
        offset: u64,
        /// The declared total entry count.
        chunk_count: usize,
    },

    /// A page whose extent runs past the end of the array — an aligned offset is not sufficient, since a
    /// full page at the LAST page's offset covers entries that do not exist.
    #[error(
        "chunk_lens page of {entries} entries at offset {offset} extends past the declared chunk_count \
         {chunk_count}"
    )]
    PageExtendsPastEnd {
        /// The offset the page claimed.
        offset: u64,
        /// The page's entry count.
        entries: usize,
        /// The declared total entry count.
        chunk_count: usize,
    },

    /// A page that is neither full nor the tail. Pages must tile the array exactly, so a short
    /// non-final page leaves a gap that no page-aligned page can ever fill; it is refused on arrival
    /// rather than surfacing later as an unexplained incompleteness.
    #[error(
        "chunk_lens page at offset {offset} has {entries} entries; this page must have exactly {expected}"
    )]
    UnexpectedPageLength {
        /// The offset the page claimed.
        offset: u64,
        /// The page's entry count.
        entries: usize,
        /// The entry count this page slot requires.
        expected: usize,
    },

    /// A page for a slot that is already filled. A duplicate or overlapping page is a REJECT, never an
    /// overwrite — otherwise the LAST sender of a page decides its contents.
    #[error("a chunk_lens page at offset {offset} was already accepted")]
    DuplicatePage {
        /// The offset of the already-filled slot.
        offset: u64,
    },

    /// The prologue ended short of `chunk_count`, so there is no array to yield.
    #[error("incomplete chunk_lens prologue: {have} of {want} entries")]
    Incomplete {
        /// Entries actually accumulated.
        have: usize,
        /// Entries the declared `chunk_count` requires.
        want: usize,
    },
}

/// Reassembles one resource's `chunk_lens` array from the pages of a **paged prologue** — the
/// decode-side mirror of [`RangeFrame::split_chunk_lens_pages`] (`SPEC.md` §5.1.1 is normative).
///
/// ## Why it lives here, beside the encoder
///
/// #1640 was an encode/decode asymmetry across a crate boundary: dig-nat capped DECODE and capped
/// ENCODE at nothing, so every read past ~48 KiB failed. Both halves of the paging rule therefore live
/// in this one module, next to the constants they are derived from. A second implementation of these
/// placement, duplicate and completeness rules would be that same defect class waiting to recur.
///
/// ## Fail-closed, with no partial results
///
/// `chunk_lens` is a **DECRYPT** input: per-chunk AES-256-GCM-SIV needs the WHOLE array, and its
/// entries must sum to the resource's `total_length`. A partial layout is therefore unusable rather
/// than partially useful, which is why [`into_chunk_lens`](Self::into_chunk_lens) yields NOTHING until
/// every page has landed, and why every irregular page is refused on arrival instead of adopted and
/// checked later. The array is reserved fallibly and bounded by [`MAX_RESOURCE_CHUNK_COUNT`], so a
/// declared count is never allowed to become an allocation this host cannot survive.
///
/// ```no_run
/// use dig_nat::mux::{ChunkLensAssembler, RangeFrame};
///
/// # fn f(frames: Vec<RangeFrame>) -> Result<(), Box<dyn std::error::Error>> {
/// let mut assembler = ChunkLensAssembler::new(5_000)?;
/// for frame in frames {
///     if let Some(page) = &frame.chunk_lens {
///         assembler.accept_page(frame.chunk_lens_offset.unwrap_or(0), page)?;
///     }
/// }
/// let chunk_lens = assembler.into_chunk_lens()?; // errors unless the prologue is complete
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ChunkLensAssembler {
    /// The array under construction, pre-sized to `chunk_count`. Unfilled entries are zero, which is
    /// never mistaken for data because occupancy is tracked separately in `filled`.
    lens: Vec<u64>,
    /// One flag per page slot — the authoritative occupancy record, so a repeated page is detectable
    /// even when it carries the same bytes as the page already accepted.
    filled: Vec<bool>,
    /// How many page slots are filled, so completeness is answered without rescanning `filled`.
    filled_pages: usize,
}

impl ChunkLensAssembler {
    /// Start reassembling the layout of a resource whose frames declare `chunk_count` entries.
    ///
    /// Refuses a `chunk_count` above [`MAX_RESOURCE_CHUNK_COUNT`] BEFORE it allocates anything, and
    /// reserves the array with `try_reserve_exact` so even a legal count cannot abort the process on a
    /// host that cannot spare it.
    pub fn new(chunk_count: usize) -> Result<Self, ChunkLensError> {
        if chunk_count > MAX_RESOURCE_CHUNK_COUNT {
            return Err(ChunkLensError::ChunkCountTooLarge { chunk_count });
        }

        let mut lens = Vec::new();
        lens.try_reserve_exact(chunk_count)
            .map_err(|_| ChunkLensError::AllocationFailed {
                chunk_count,
                bytes: chunk_count * std::mem::size_of::<u64>(),
            })?;
        lens.resize(chunk_count, 0);

        let page_count = chunk_count.div_ceil(MAX_CHUNK_LENS_PER_FRAME);
        let mut filled = Vec::new();
        filled
            .try_reserve_exact(page_count)
            .map_err(|_| ChunkLensError::AllocationFailed {
                chunk_count,
                bytes: page_count,
            })?;
        filled.resize(page_count, false);

        Ok(ChunkLensAssembler {
            lens,
            filled,
            filled_pages: 0,
        })
    }

    /// Place one `chunk_lens` page, which begins at entry `offset` of the resource's array.
    ///
    /// A page is accepted only if it satisfies EVERY rule of the paged prologue; each violation has its
    /// own [`ChunkLensError`] variant, and a rejected page leaves the assembler exactly as it was.
    ///
    /// - non-empty, and at most [`MAX_CHUNK_LENS_PER_FRAME`] entries
    /// - `offset` a multiple of [`MAX_CHUNK_LENS_PER_FRAME`], and inside the declared count
    /// - an extent that stays within the array, and a length that exactly fills its page slot
    /// - a slot not already filled — a duplicate or overlapping page is REJECTED, never an overwrite
    pub fn accept_page(&mut self, offset: u64, page: &[u64]) -> Result<(), ChunkLensError> {
        let chunk_count = self.lens.len();
        let page_size = MAX_CHUNK_LENS_PER_FRAME as u64;

        if page.is_empty() {
            return Err(ChunkLensError::EmptyPage { offset });
        }
        if page.len() > MAX_CHUNK_LENS_PER_FRAME {
            return Err(ChunkLensError::PageTooLarge {
                entries: page.len(),
            });
        }
        // `%` rather than `u64::is_multiple_of`, which is not stable at this crate's MSRV (1.75).
        if offset % page_size != 0 {
            return Err(ChunkLensError::MisalignedOffset { offset });
        }
        // Compared as u64 so an offset near `u64::MAX` cannot wrap into a valid index on a 64-bit host.
        if offset >= chunk_count as u64 {
            return Err(ChunkLensError::OffsetOutOfRange {
                offset,
                chunk_count,
            });
        }

        let start = offset as usize;
        let end = start + page.len();
        if end > chunk_count {
            return Err(ChunkLensError::PageExtendsPastEnd {
                offset,
                entries: page.len(),
                chunk_count,
            });
        }
        // Every page but the tail must be exactly full, or it leaves a gap no aligned page can fill.
        let expected = MAX_CHUNK_LENS_PER_FRAME.min(chunk_count - start);
        if page.len() != expected {
            return Err(ChunkLensError::UnexpectedPageLength {
                offset,
                entries: page.len(),
                expected,
            });
        }

        let slot = start / MAX_CHUNK_LENS_PER_FRAME;
        if self.filled[slot] {
            return Err(ChunkLensError::DuplicatePage { offset });
        }

        self.lens[start..end].copy_from_slice(page);
        self.filled[slot] = true;
        self.filled_pages += 1;
        Ok(())
    }

    /// Whether every page slot has been filled, i.e. the layout is whole and decryptable.
    ///
    /// A zero-chunk resource is complete immediately: there is no layout to reassemble, and reporting it
    /// forever-incomplete would stall a stream over a resource already fully described.
    pub fn is_complete(&self) -> bool {
        self.filled_pages == self.filled.len()
    }

    /// The reassembled `chunk_lens` array, or [`ChunkLensError::Incomplete`] if any page is missing.
    ///
    /// There is no partial variant of this call, by design: a layout short even one entry cannot decrypt
    /// the resource, and handing back what arrived so far would invite a caller to treat a hostile or
    /// truncated prologue as usable.
    pub fn into_chunk_lens(self) -> Result<Vec<u64>, ChunkLensError> {
        if !self.is_complete() {
            let have = self
                .filled
                .iter()
                .enumerate()
                .filter(|(_, filled)| **filled)
                .map(|(slot, _)| {
                    let start = slot * MAX_CHUNK_LENS_PER_FRAME;
                    MAX_CHUNK_LENS_PER_FRAME.min(self.lens.len() - start)
                })
                .sum();
            return Err(ChunkLensError::Incomplete {
                have,
                want: self.lens.len(),
            });
        }
        Ok(self.lens)
    }
}

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
    serde_json::from_slice(&body).map_err(malformed_frame)
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
        .map_err(malformed_frame)
}

/// Turn a `serde_json` decode failure on a PEER-SUPPLIED frame into an `io::Error` that says what
/// went wrong without repeating what the peer sent (#1674).
///
/// The naive `io::Error::new(InvalidData, e)` keeps serde's own message, and serde's message quotes
/// the offending input back — so every node that logged a malformed frame logged text of the
/// sender's choosing. Routing through [`SafeText::describing_json_error`] keeps the diagnosis
/// (category, line, column) and drops the quotation.
fn malformed_frame(error: serde_json::Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "malformed frame: {}",
            SafeText::describing_json_error(&error)
        ),
    )
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
