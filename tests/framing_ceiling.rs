//! The two sides of the length-prefixed framing contract must agree (#1640).
//!
//! `decode_framed` has always rejected a body over [`MAX_FRAMED_BODY`]; `encode` never checked, so a
//! sender could emit a frame no conforming receiver may accept — and the failure surfaced at the
//! RECEIVER as an opaque `InvalidData("control message too large")`, kilometres from its cause.
//!
//! Every test here drives the REAL encoder against the REAL decoder over a REAL byte stream. A
//! symmetric struct round-trip, an in-process mock transport, or a small fixture all pass against the
//! broken behaviour — which is exactly how this defect survived to production.

use dig_nat::{
    RangeFrame, MAX_CHUNK_LENS_PER_FRAME, MAX_FIRST_FRAME_CHUNK_LENS, MAX_FRAMED_BODY,
    MAX_INCLUSION_PROOF_B64, MAX_RANGE_FRAME_PAYLOAD,
};
use tokio::io::AsyncWriteExt;

/// A `RangeFrame` carrying `payload` and nothing optional — the shape of every non-first data frame.
fn data_frame(offset: u64, payload: Vec<u8>) -> RangeFrame {
    RangeFrame::data(offset, payload)
}

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
    // Every u64 scalar at max width, matching how the constant was derived — a bound that relies on a
    // scalar happening to be small carries a hidden premise. `chunk_lens` entries sit at the 256 KiB
    // FastCDC maximum: six decimal digits, the widest a chunk length can legally be, since the array's
    // JSON size depends on entry WIDTH as much as on entry count.
    RangeFrame::data(u64::MAX, payload)
        .with_declared_length(u64::MAX)
        .with_identity("ab".repeat(32), u64::MAX, u64::MAX)
        .with_chunk_lens_page(u64::MAX, vec![262_144; chunk_count])
        .with_chunk_index(u64::MAX)
        .with_inclusion_proof("A".repeat(proof_len))
}

/// The serialized body `frame` occupies — the number the published bound is derived against.
///
/// MEASURED by serializing the real struct, never argued in prose: three of the four historical wrong
/// values of this bound were byte counts reasoned about in a comment. Until 0.13.0 this had to add a
/// reservation for the then-future prologue fields; those fields are real now, so the fixture carries
/// them and the measurement is direct.
fn body_len(frame: &RangeFrame) -> usize {
    serde_json::to_vec(frame)
        .expect("a range frame serializes")
        .len()
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
/// this one test: 2,495 lands at 65,599 B, 2,891 at 68,371 B, 3,373 further still.
#[tokio::test]
async fn the_published_chunk_bound_fits_with_every_field_at_its_maximum() {
    let frame = first_frame(
        vec![9u8; MAX_RANGE_FRAME_PAYLOAD],
        MAX_FIRST_FRAME_CHUNK_LENS,
        MAX_INCLUSION_PROOF_B64,
    );

    let budget = body_len(&frame);
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
/// it cannot drift. Lowering it fails here — the old convenient 2,048 fixture lands at 62,470 B, well
/// inside the cap. A bound checked only from below can only ever confirm itself.
#[tokio::test]
async fn one_chunk_entry_past_the_published_bound_does_not_fit() {
    let frame = first_frame(
        vec![9u8; MAX_RANGE_FRAME_PAYLOAD],
        MAX_FIRST_FRAME_CHUNK_LENS + 1,
        MAX_INCLUSION_PROOF_B64,
    );

    let budget = body_len(&frame);
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
    // Nor does surrendering the entire payload help beyond 8,727 entries — where the metadata ALONE
    // fills the body, which is why no value of MAX_RANGE_FRAME_PAYLOAD rescues this class of resource.
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

/// `MAX_INCLUSION_PROOF_B64` is **premise 2** of [`MAX_FIRST_FRAME_CHUNK_LENS`], so the encoder must
/// ENFORCE it, not merely be tested against fixtures that respect it (#1655).
///
/// Until 0.13.0 the cap lived only in this file's own `const` and in prose, which means the word
/// GUARANTEED in `SPEC.md` rested on a premise nothing checked: an 8 KiB proof made a resource with
/// FEWER than 2,486 chunks unsendable — precisely what the published bound says cannot happen. The
/// fixture below is that resource: a comfortably sub-bound entry count, refused solely because of the
/// proof. A test that only ever built proofs at or under the cap could not see this.
#[tokio::test]
async fn encode_refuses_an_inclusion_proof_above_the_published_cap() {
    let entries = MAX_FIRST_FRAME_CHUNK_LENS / 2;
    let over = first_frame(
        vec![9u8; MAX_RANGE_FRAME_PAYLOAD],
        entries,
        MAX_INCLUSION_PROOF_B64 + 1,
    );

    let err = expect_refusal(over.encode(), "an inclusion proof over the published cap");

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    let msg = err.to_string();
    assert!(
        msg.contains("MAX_INCLUSION_PROOF_B64"),
        "the error must name the cap it enforces so the premise is traceable, got: {msg}"
    );
}

/// The other side of that cap: a proof at EXACTLY the published length is legal, and the frame carrying
/// it still fits at the published entry bound. Pinning both sides is what makes the cap a boundary
/// rather than a direction — and it is the assertion that fails if a future field addition silently eats
/// the proof's allowance.
#[tokio::test]
async fn a_proof_at_exactly_the_published_cap_still_fits_at_the_entry_bound() {
    let at_cap = first_frame(
        vec![9u8; MAX_RANGE_FRAME_PAYLOAD],
        MAX_FIRST_FRAME_CHUNK_LENS,
        MAX_INCLUSION_PROOF_B64,
    );

    assert_eq!(
        at_cap.inclusion_proof.as_ref().map(String::len),
        Some(MAX_INCLUSION_PROOF_B64),
        "the fixture must hold the proof AT its cap — a helper that silently shrinks a co-occurring          field measures a narrower frame than the protocol permits"
    );
    at_cap
        .encode()
        .expect("a proof of exactly MAX_INCLUSION_PROOF_B64 is legal — the cap is inclusive");
}

/// The sender's paging threshold must keep real margin below the arithmetic ceiling, MEASURED at the
/// same maxima. If a future field addition consumes that margin, this fails here — at the number that
/// governs what senders actually emit — rather than in production on the first large resource.
#[tokio::test]
async fn the_paging_threshold_leaves_measured_margin_below_the_body_cap() {
    let paged = first_frame(
        vec![9u8; MAX_RANGE_FRAME_PAYLOAD],
        MAX_CHUNK_LENS_PER_FRAME,
        MAX_INCLUSION_PROOF_B64,
    );

    let body = body_len(&paged);
    assert!(
        body <= MAX_FRAMED_BODY,
        "a full prologue page at every maximum is {body} B, over the {MAX_FRAMED_BODY} B cap — the          paging threshold a serve path splits on does not itself fit"
    );
    assert_eq!(
        body, 62_470,
        "the published margin figure moved; re-derive it and re-publish it in SPEC.md rather than          updating this number to match"
    );
}
