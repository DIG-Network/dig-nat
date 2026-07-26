//! The two sides of the length-prefixed framing contract must agree (#1640).
//!
//! `decode_framed` has always rejected a body over [`MAX_FRAMED_BODY`]; `encode` never checked, so a
//! sender could emit a frame no conforming receiver may accept — and the failure surfaced at the
//! RECEIVER as an opaque `InvalidData("control message too large")`, kilometres from its cause.
//!
//! Every test here drives the REAL encoder against the REAL decoder over a REAL byte stream. A
//! symmetric struct round-trip, an in-process mock transport, or a small fixture all pass against the
//! broken behaviour — which is exactly how this defect survived to production.

use dig_nat::mux::{RangeFrame, MAX_FRAMED_BODY, MAX_RANGE_FRAME_PAYLOAD};
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

/// The worst-case FIRST frame: the #1577 verification metadata is on every first frame and its size
/// is driven by the resource, not the frame — a 512 MiB resource at 256 KiB chunks carries 2048
/// `chunk_lens` entries. This is what an exact-fit payload ceiling would overflow.
fn first_frame_with_large_metadata(payload: Vec<u8>) -> RangeFrame {
    RangeFrame {
        chunk_lens: Some((0..2048u64).map(|i| 262_144 + i).collect()),
        chunk_index: Some(0),
        total_length: Some(512 * 1024 * 1024),
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

/// The ceiling must hold for the WORST-CASE frame, not the empty one: a full-size payload PLUS a
/// large `chunk_lens` table and an inclusion proof still encodes and still decodes. An exact-fit
/// constant derived from base64 expansion alone passes the previous test and fails this one.
#[tokio::test]
async fn a_ceiling_payload_with_large_metadata_still_decodes() {
    let frame = first_frame_with_large_metadata(vec![9u8; MAX_RANGE_FRAME_PAYLOAD]);

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
