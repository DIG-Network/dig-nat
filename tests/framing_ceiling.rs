//! The two sides of the length-prefixed framing contract must agree (#1640).
//!
//! `decode_framed` has always rejected a body over [`MAX_FRAMED_BODY`]; `encode` never checked, so a
//! sender could emit a frame no conforming receiver may accept — and the failure surfaced at the
//! RECEIVER as an opaque `InvalidData("control message too large")`, kilometres from its cause.
//!
//! Every test here drives the REAL encoder against the REAL decoder over a REAL byte stream. A
//! symmetric struct round-trip, an in-process mock transport, or a small fixture all pass against the
//! broken behaviour — which is exactly how this defect survived to production.

use dig_nat::mux::{
    RangeFrame, MAX_FIRST_FRAME_CHUNK_LENS, MAX_FRAMED_BODY, MAX_RANGE_FRAME_PAYLOAD,
};
use tokio::io::AsyncWriteExt;

/// A `RangeFrame` carrying `payload` and nothing optional — the shape of every non-first data frame.
fn data_frame(offset: u64, payload: Vec<u8>) -> RangeFrame {
    RangeFrame {
        offset,
        length: payload.len() as u64,
        bytes: payload,
        complete: false,
        total_length: None,
        chunk_lens: None,
        chunk_index: None,
        inclusion_proof: None,
        root: None,
    }
}

/// A FIRST frame carrying the #1577 verification metadata for a resource of `chunk_count` chunks.
///
/// The entry COUNT is the parameter on purpose. The metadata's size is driven by the resource, not by
/// the frame, so the only meaningful fixture size is the one derived from the protocol's own bound —
/// [`MAX_FIRST_FRAME_CHUNK_LENS`]. An earlier version of this file used a convenient 2,048 entries —
/// comfortably inside the bound, and therefore incapable of showing that the allowance did not in fact
/// cover every permitted resource. That is what let a wrong premise about chunk size survive review.
/// Same lesson as the sub-48 KiB e2e fixture that hid #1640 itself: choose the fixture from the
/// protocol's limit, never from what is convenient.
fn first_frame(payload: Vec<u8>, chunk_count: usize) -> RangeFrame {
    RangeFrame {
        // Every entry at the 256 KiB FastCDC maximum: six decimal digits, the widest a chunk length
        // can legally be. The array's JSON size depends on entry WIDTH as much as on entry count, and
        // deriving the bound at a narrower width is the second wrong premise this test guards against.
        chunk_lens: Some(vec![262_144; chunk_count]),
        chunk_index: Some(0),
        total_length: Some(256 * 1024 * 1024),
        inclusion_proof: Some("A".repeat(1400)),
        root: Some("ab".repeat(32)),
        ..data_frame(0, payload)
    }
}

/// Assert `encoded` was refused, without dumping tens of kilobytes of frame into the panic message
/// on failure.
fn expect_refusal(encoded: std::io::Result<Vec<u8>>, what: &str) -> std::io::Error {
    match encoded {
        Ok(wire) => panic!(
            "{what} must be refused at the sender, but encoded {} bytes",
            wire.len()
        ),
        Err(e) => e,
    }
}

/// Read every frame off `wire` with the real decoder until clean EOF.
async fn decode_all(wire: Vec<u8>) -> std::io::Result<Vec<RangeFrame>> {
    let mut cursor = std::io::Cursor::new(wire);
    let mut frames = Vec::new();
    while let Some(frame) = RangeFrame::decode(&mut cursor).await? {
        frames.push(frame);
    }
    Ok(frames)
}

/// A sender must never be able to emit a payload the receiver is required to reject: `encode` fails
/// LOUDLY, at the sender, naming the ceiling.
#[tokio::test]
async fn encode_refuses_a_payload_above_the_published_ceiling() {
    let over = data_frame(0, vec![7u8; MAX_RANGE_FRAME_PAYLOAD + 1]);

    let err = expect_refusal(over.encode(), "a payload over the ceiling");

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    let msg = err.to_string();
    assert!(
        msg.contains(&MAX_RANGE_FRAME_PAYLOAD.to_string()),
        "the error must name the ceiling so the sender knows what to split on, got: {msg}"
    );
}

/// The ceiling must hold for the WORST-CASE frame, not the empty one: a full-size payload PLUS the
/// largest `chunk_lens` table the published bound claims fits, PLUS an inclusion proof, still encodes
/// and still decodes. An exact-fit payload ceiling derived from base64 expansion alone passes the
/// previous test and fails this one.
#[tokio::test]
async fn a_ceiling_payload_at_the_published_chunk_bound_still_decodes() {
    let frame = first_frame(
        vec![9u8; MAX_RANGE_FRAME_PAYLOAD],
        MAX_FIRST_FRAME_CHUNK_LENS,
    );

    let wire = frame
        .encode()
        .expect("a payload at the ceiling must encode");
    assert!(
        wire.len() - 4 <= MAX_FRAMED_BODY,
        "worst-case body {} exceeds the decode cap {MAX_FRAMED_BODY} — the ceiling is fitted too \
         tightly to leave room for per-frame metadata",
        wire.len() - 4
    );

    let decoded = decode_all(wire).await.expect("the receiver must accept it");
    assert_eq!(decoded, vec![frame]);
}

/// [`MAX_FIRST_FRAME_CHUNK_LENS`] is published as an EXACT bound, so one entry past it must refuse.
/// Together with the test above this pins the number from both sides — a published bound that is only
/// checked from below can drift upward unnoticed, which is how the previous 2,048-entry fixture let a
/// too-generous claim stand.
#[tokio::test]
async fn one_chunk_entry_past_the_published_bound_is_refused() {
    let frame = first_frame(
        vec![9u8; MAX_RANGE_FRAME_PAYLOAD],
        MAX_FIRST_FRAME_CHUNK_LENS + 1,
    );

    let err = expect_refusal(frame.encode(), "one entry past the published chunk bound");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

/// The KNOWN LIMITATION, asserted rather than left implicit (#1640): a resource the ecosystem already
/// permits — `digstore-host`'s `MAX_MODULE_BYTES` of 256 MiB, about 4,096 chunks at the canonical
/// 64 KiB FastCDC target — has NO conforming first frame. Splitting on [`MAX_RANGE_FRAME_PAYLOAD`] is
/// refused, and shrinking the payload to nothing does not rescue it once the metadata alone fills the
/// body.
///
/// This test documents the gap and will need updating when the #1640 wire-shape decision lands; that
/// is the point. Encoding this failure makes the limitation impossible to forget, and asserts the
/// valuable half of the invariant meanwhile: the sender refuses LOUDLY and locally instead of emitting
/// bytes that would fail on a remote peer.
#[tokio::test]
async fn a_permitted_256_mebibyte_module_has_no_conforming_first_frame_yet() {
    let chunks_in_256_mib = 256 * 1024 / 64; // 4,096 chunks at the 64 KiB FastCDC target.
    assert!(chunks_in_256_mib > MAX_FIRST_FRAME_CHUNK_LENS);

    expect_refusal(
        first_frame(vec![9u8; MAX_RANGE_FRAME_PAYLOAD], chunks_in_256_mib).encode(),
        "a 256 MiB module's first frame at the payload ceiling",
    );
    // Nor does surrendering the entire payload help beyond 9,133 entries.
    expect_refusal(
        first_frame(Vec::new(), 9_500).encode(),
        "a first frame whose metadata alone exceeds the body cap",
    );
}

/// The end-to-end property: a multi-megabyte resource crosses the real wire when the sender splits on
/// the published ceiling. Before #1640 a serve path split on a 3 MiB window instead, so the first
/// frame of any resource over ~48 KiB died at the reader.
#[tokio::test]
async fn a_one_mebibyte_resource_rides_ceiling_sized_frames_over_a_real_stream() {
    let resource: Vec<u8> = (0..1024u32 * 1024).map(|i| (i % 251) as u8).collect();

    let (mut writer, reader) = tokio::io::duplex(4 * 1024 * 1024);
    let mut offset = 0usize;
    let mut frames_written = 0usize;
    while offset < resource.len() {
        let end = (offset + MAX_RANGE_FRAME_PAYLOAD).min(resource.len());
        let mut frame = data_frame(offset as u64, resource[offset..end].to_vec());
        frame.complete = end == resource.len();
        writer
            .write_all(&frame.encode().expect("a ceiling-sized frame encodes"))
            .await
            .unwrap();
        frames_written += 1;
        offset = end;
    }
    writer.shutdown().await.unwrap();
    assert!(frames_written > 1, "1 MiB must need more than one frame");

    let mut reader = reader;
    let mut reassembled = Vec::new();
    while let Some(frame) = RangeFrame::decode(&mut reader).await.unwrap() {
        assert_eq!(frame.offset as usize, reassembled.len());
        reassembled.extend_from_slice(&frame.bytes);
    }
    assert_eq!(reassembled, resource);
}

/// The metadata is not exempt: a `chunk_lens` table so large that the BODY exceeds the cap is refused
/// even when the payload itself is legal, so the receiver never meets an undecodable frame.
#[tokio::test]
async fn encode_refuses_a_legal_payload_whose_metadata_overflows_the_body() {
    let mut frame = data_frame(0, vec![1u8; MAX_RANGE_FRAME_PAYLOAD]);
    frame.chunk_lens = Some((0..MAX_FRAMED_BODY as u64).map(|i| 1_000_000 + i).collect());

    let err = expect_refusal(frame.encode(), "a body over the decode cap");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}
