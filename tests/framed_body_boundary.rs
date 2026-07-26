//! The `MAX_FRAMED_BODY` boundary, pinned from BOTH sides (#1655).
//!
//! It was the one cap in the framing contract not pinned at ±1: changing the encoder's `>` to `>=`
//! kept the whole suite green, which means nothing was actually asserting where the boundary IS. A
//! bound checked only from one side can only confirm itself.
//!
//! The fixture is an `AvailabilityResponse` rather than a `RangeFrame` on purpose: its `roots` field is
//! a JSON string, so the body length is tunable to the BYTE. `RangeFrame`'s size levers are base64
//! (3 bytes at a time) and `chunk_lens` entries (7 bytes at a time), neither of which can land on an
//! exact body length — and a boundary test that cannot hit the boundary is not a boundary test.

use dig_nat::{AvailabilityAnswer, AvailabilityResponse, MAX_FRAMED_BODY};

/// An `AvailabilityResponse` whose serialized body is exactly `target` bytes, or `None` if `target` is
/// below the shape's own overhead.
fn response_with_body_of(target: usize) -> Option<AvailabilityResponse> {
    let overhead = body_len(&build(0));
    let pad = target.checked_sub(overhead)?;
    let padded = build(pad);
    assert_eq!(
        body_len(&padded),
        target,
        "the padding must move the body one byte at a time, or the boundary cannot be hit exactly"
    );
    Some(padded)
}

fn build(pad: usize) -> AvailabilityResponse {
    AvailabilityResponse::new(vec![
        AvailabilityAnswer::available().with_roots(vec!["r".repeat(pad)])
    ])
}

fn body_len(response: &AvailabilityResponse) -> usize {
    serde_json::to_vec(response)
        .expect("the wire types serialize")
        .len()
}

/// A body of exactly `MAX_FRAMED_BODY` is the largest LEGAL one: the encoder accepts it and the frame
/// on the wire is the `u32`-BE prefix plus those bytes.
#[tokio::test]
async fn a_body_of_exactly_the_cap_encodes() {
    let at_cap =
        response_with_body_of(MAX_FRAMED_BODY).expect("the cap exceeds the shape overhead");

    let wire = at_cap
        .encode()
        .expect("a body of exactly MAX_FRAMED_BODY is legal — the cap is inclusive");

    assert_eq!(wire.len(), 4 + MAX_FRAMED_BODY);
    assert_eq!(
        u32::from_be_bytes(wire[..4].try_into().unwrap()) as usize,
        MAX_FRAMED_BODY
    );
}

/// One byte past the cap is refused at the SENDER, naming the cap — the governing invariant is that a
/// conforming sender never emits a body a conforming receiver is required to reject.
#[tokio::test]
async fn a_body_one_byte_past_the_cap_is_refused() {
    let one_over =
        response_with_body_of(MAX_FRAMED_BODY + 1).expect("the cap exceeds the shape overhead");

    let err = one_over
        .encode()
        .expect_err("one byte past MAX_FRAMED_BODY must be refused");

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        err.to_string().contains(&MAX_FRAMED_BODY.to_string()),
        "the error must name the cap so the sender knows what it overran, got: {err}"
    );
}
