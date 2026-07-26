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

/// The published cap on a base64 `inclusion_proof`. Every fixture below holds it HERE, at its cap.
///
/// The 2,891-entry figure this file used to assert was derived with a ~1,400-byte proof, so it was the
/// bound for a *small-proof* frame while the protocol permits four times that. A fixture that quietly
/// shrinks one co-occurring field turns a real worst case into a narrow one.
const MAX_INCLUSION_PROOF_B64: usize = 4096;

/// A FIRST frame carrying the #1577 verification metadata for a resource of `chunk_count` chunks, with
/// a `proof_len`-byte inclusion proof.
///
/// Both sizes are parameters ON PURPOSE, and callers pass the published caps. The metadata's size is
/// driven by the resource rather than the frame, so the only meaningful fixture is the one derived from
/// the protocol's own limits. Earlier versions of this file used a convenient 2,048 entries and then a
/// convenient 1,400-byte proof; each sat comfortably inside the real bound and so could only ever
/// confirm the allowance was adequate *for that fixture*. Same lesson as the sub-48 KiB e2e fixture
/// that hid #1640 itself: choose fixtures from the protocol's limits, never from what is convenient.
fn first_frame(payload: Vec<u8>, chunk_count: usize, proof_len: usize) -> RangeFrame {
    RangeFrame {
        // Every entry at the 256 KiB FastCDC maximum: six decimal digits, the widest a chunk length can
        // legally be. The array's JSON size depends on entry WIDTH as much as on entry count.
        chunk_lens: Some(vec![262_144; chunk_count]),
        // Every u64 scalar at max width, matching how the constant was derived — a bound that relies on
        // a scalar happening to be small carries a hidden premise.
        chunk_index: Some(u64::MAX),
        total_length: Some(u64::MAX),
        inclusion_proof: Some("A".repeat(proof_len)),
        root: Some("ab".repeat(32)),
        offset: u64::MAX,
        length: u64::MAX,
        ..data_frame(0, payload)
    }
}

/// Mirrors `RangeFrame`'s serialized shape plus the two 0.13.0 prologue fields, used ONLY to measure
/// how many bytes those fields will cost.
///
/// [`MAX_FIRST_FRAME_CHUNK_LENS`] is derived on the 0.13.0 field set so it never has to move when the
/// prologue lands, which means a test on today's fields must reserve that difference or it would accept
/// a constant that is correct today and wrong in one release. Measured by serializing, not asserted as
/// a byte count in a comment — an arithmetic claim in prose is how this number went wrong three times.
#[derive(serde::Serialize)]
struct V013Fields {
    chunk_count: u64,
    chunk_lens_offset: u64,
}

/// The bytes the 0.13.0 prologue fields add to a frame body, measured.
fn v013_reservation() -> usize {
    let fields = V013Fields {
        chunk_count: u64::MAX,
        chunk_lens_offset: u64::MAX,
    };
    // `{"a":1,"b":2}` -> the two `"key":value` pairs plus the two commas joining them into a frame.
    serde_json::to_vec(&fields).unwrap().len() - "{}".len() + ",".len()
}

/// The body `frame` serializes to, plus the 0.13.0 reservation — the number the published bound is
/// derived against.
fn body_with_v013_reservation(frame: &RangeFrame) -> usize {
    serde_json::to_vec(frame).unwrap().len() + v013_reservation()
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

/// UPPER PIN on [`MAX_FIRST_FRAME_CHUNK_LENS`]: at the published bound, with ALL FOUR maxima held
/// simultaneously — full payload, full proof, six-digit entries, max-width `u64` scalars — the frame
/// fits inside [`MAX_FRAMED_BODY`] *and* still fits once the 0.13.0 prologue fields are added.
///
/// Raising the constant fails here. Every too-generous figure in this number's history is caught by
/// this one test: 2,495 lands at 65,586 B, 2,891 at 68,358 B, 3,373 further still.
#[tokio::test]
async fn the_published_chunk_bound_fits_with_every_field_at_its_maximum() {
    let frame = first_frame(
        vec![9u8; MAX_RANGE_FRAME_PAYLOAD],
        MAX_FIRST_FRAME_CHUNK_LENS,
        MAX_INCLUSION_PROOF_B64,
    );

    let budget = body_with_v013_reservation(&frame);
    assert!(
        budget <= MAX_FRAMED_BODY,
        "at the published bound of {MAX_FIRST_FRAME_CHUNK_LENS} entries the worst-case body is          {budget} B, over the {MAX_FRAMED_BODY} B cap — the constant is too generous, which is the          UNSAFE direction: a conforming sender would emit a frame the receiver must reject"
    );

    // And it is not merely arithmetic — the real encoder accepts it and the real decoder returns it.
    let wire = frame.encode().expect("the bound must be encodable today");
    let decoded = decode_all(wire).await.expect("the receiver must accept it");
    assert_eq!(decoded, vec![frame]);
}

/// LOWER PIN on [`MAX_FIRST_FRAME_CHUNK_LENS`]: one entry past the bound does NOT fit.
///
/// Together with the test above this pins the constant from both sides, so exactly one value passes and
/// it cannot drift. Lowering it fails here — the old convenient 2,048 fixture lands at 62,457 B, well
/// inside the cap. A bound checked only from below can only ever confirm itself.
#[tokio::test]
async fn one_chunk_entry_past_the_published_bound_does_not_fit() {
    let frame = first_frame(
        vec![9u8; MAX_RANGE_FRAME_PAYLOAD],
        MAX_FIRST_FRAME_CHUNK_LENS + 1,
        MAX_INCLUSION_PROOF_B64,
    );

    let budget = body_with_v013_reservation(&frame);
    assert!(
        budget > MAX_FRAMED_BODY,
        "one entry past the published bound still fits at {budget} B — the constant is lower than the          real ceiling, so it is not the bound it claims to be"
    );
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
        first_frame(
            vec![9u8; MAX_RANGE_FRAME_PAYLOAD],
            chunks_in_256_mib,
            MAX_INCLUSION_PROOF_B64,
        )
        .encode(),
        "a 256 MiB module's first frame at the payload ceiling",
    );
    // Nor does surrendering the entire payload help beyond 9,133 entries.
    expect_refusal(
        first_frame(Vec::new(), 9_500, MAX_INCLUSION_PROOF_B64).encode(),
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
