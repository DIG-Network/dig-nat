//! A peer's own bytes must never reach the text of an error we produce about that peer (#1674).
//!
//! `serde_json` is helpful to a developer and generous to a stranger: when a value has the wrong
//! type, or an enum tag is unrecognised, its message QUOTES THE OFFENDING INPUT BACK. Every decode
//! on this crate's peer wire ran that message straight into an `io::Error`, so any node that logged
//! a malformed frame logged whatever the sender chose to put in it.
//!
//! Two distinct harms, and the fix must close both:
//!
//! * **Log injection** — the quoted text can carry control characters and forge whole log lines.
//! * **Information disclosure** — even perfectly inert text is attacker-chosen content echoed to an
//!   operator's console, or into a structured field something downstream parses.
//!
//! Every test here drives the REAL public decoder (`RangeFrame::decode`) over a REAL byte stream,
//! because that is the crate's actual construction idiom. A direct call to the sanitizer would
//! prove only that the sanitizer works — which is the failure mode that let this class survive in
//! three separate crates already.

use dig_nat::{RangeFrame, RangeRequest};

/// The stranger's payload. Deliberately plain ASCII with no JSON-escapable character, so it is
/// **byte-identical** whether an error renders it raw or through `{:?}`. A marker containing a
/// newline would let a passing test mean merely "serde re-escaped it", which is not the property
/// under test; this one can only be absent if the text genuinely never got in.
const STRANGER_MARKER: &str = "PEER-CHOSEN-TEXT-0f9a1c";

/// A frame body whose `offset` is a string rather than a number, carrying `text`.
///
/// This is the cheapest way a stranger reaches serde's echo: a type mismatch on the very first
/// field. No handshake, no valid frame, one packet.
fn hostile_frame_wire(text: &str) -> Vec<u8> {
    let body = format!(r#"{{"offset":"{text}","length":0,"bytes":"","complete":true}}"#);
    let mut wire = Vec::with_capacity(4 + body.len());
    wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
    wire.extend_from_slice(body.as_bytes());
    wire
}

/// Decode `wire` with the real decoder and return the error it produced.
async fn decode_error(wire: Vec<u8>) -> std::io::Error {
    let mut cursor = std::io::Cursor::new(wire);
    match RangeFrame::decode(&mut cursor).await {
        Ok(frame) => panic!("a malformed frame must not decode, got {frame:?}"),
        Err(e) => e,
    }
}

/// PRECONDITION — serde really does echo, so the test below is testing something.
///
/// Without this, `peer_bytes_never_reach_the_decode_error` would pass just as happily against a
/// serde message that never contained the marker in the first place, and would defend nothing.
#[test]
fn serde_json_quotes_the_peer_input_back_verbatim() {
    let body = format!(r#"{{"offset":"{STRANGER_MARKER}","length":0,"bytes":"","complete":true}}"#);

    let raw = serde_json::from_slice::<RangeFrame>(body.as_bytes())
        .expect_err("a string offset is not a u64")
        .to_string();

    assert!(
        raw.contains(STRANGER_MARKER),
        "this test's premise is gone: serde no longer echoes the input, so the fix it guards is \
         no longer proven by the test below. Got: {raw}"
    );
}

/// THE PROPERTY — a stranger's bytes do not reach the error text of the real decoder.
#[tokio::test]
async fn peer_bytes_never_reach_the_decode_error() {
    let err = decode_error(hostile_frame_wire(STRANGER_MARKER)).await;

    let msg = err.to_string();
    assert!(
        !msg.contains(STRANGER_MARKER),
        "the decode error echoed the peer's own bytes back: {msg}"
    );
    // `Debug` is logged at least as often as `Display` (`{:?}` on a `Result`, a `.unwrap()` panic,
    // a `tracing` field). A careful `Display` over a leaky inner value closes only half the surface.
    let debug = format!("{err:?}");
    assert!(
        !debug.contains(STRANGER_MARKER),
        "the decode error's Debug echoed the peer's own bytes back: {debug}"
    );
}

/// THE CONTROL — the fix must not be "say less".
///
/// Deleting the detail satisfies the assertion above perfectly and is the nearest wrong
/// implementation, so it gets its own test: the error still has to tell a developer what happened
/// and where, it just may not quote the stranger.
#[tokio::test]
async fn the_decode_error_still_diagnoses_the_failure() {
    let err = decode_error(hostile_frame_wire(STRANGER_MARKER)).await;

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    let msg = err.to_string();
    assert!(
        msg.contains("line 1") && msg.contains("column"),
        "a developer must still be able to locate the failure, got: {msg}"
    );
    assert!(
        msg.contains("data"),
        "a developer must still be able to tell a syntax error from a schema error, got: {msg}"
    );
}

/// A control character in the stranger's text must not reach the error either — the log-injection
/// half of the class, kept separate from the disclosure half so a fix that handles only one is not
/// mistaken for a fix that handles both.
#[tokio::test]
async fn a_forged_log_line_cannot_be_smuggled_through_a_decode_error() {
    // `\n` inside the JSON string literal, so serde decodes it to a REAL newline before it ever
    // reaches the error message.
    let forged = format!("{STRANGER_MARKER}\\n2026-07-31T00:00:00Z ERROR forged");

    let err = decode_error(hostile_frame_wire(&forged)).await;

    let msg = err.to_string();
    assert!(
        !msg.contains('\n') && !msg.contains('\r'),
        "the decode error carried a line break, so a peer can forge log lines: {msg:?}"
    );
    assert!(
        !msg.contains("forged"),
        "the decode error echoed the peer's forged line: {msg:?}"
    );
}

/// The SERVING side, which is the more exposed of the two.
///
/// `RangeFrame::decode` above is a client reading a reply from a holder it chose to talk to.
/// `RangeRequest::decode` is a node reading a request from ANY stranger who can open a stream — no
/// selection, no prior relationship. The two use different decoders internally (`decode_framed_opt`
/// vs `decode_framed`), so covering only the client half leaves the more hostile half unproven; that
/// asymmetry was found by reverting the fix and watching these tests stay green.
#[tokio::test]
async fn a_strangers_request_preamble_cannot_echo_its_own_bytes_back() {
    let body = format!(r#"{{"store_id":"{STRANGER_MARKER}","length":"{STRANGER_MARKER}"}}"#);
    let mut wire = Vec::new();
    wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
    wire.extend_from_slice(body.as_bytes());

    let mut cursor = std::io::Cursor::new(wire);
    let err = RangeRequest::decode(&mut cursor)
        .await
        .expect_err("a string length is not a u64");

    assert!(
        !err.to_string().contains(STRANGER_MARKER),
        "the serving side echoed the stranger's bytes: {err}"
    );
    assert!(
        !format!("{err:?}").contains(STRANGER_MARKER),
        "the serving side's Debug echoed the stranger's bytes: {err:?}"
    );
    // CONTROL: still diagnosable.
    assert!(err.to_string().contains("column"), "got: {err}");
}

// ---------------------------------------------------------------------------------------------
// The same class through a second door: a traversal failure's `reason`.
// ---------------------------------------------------------------------------------------------

use dig_nat::{MethodError, NatError, TraversalKind};

/// A failed mTLS handshake's reason is built from a rustls error, and a rustls error can carry text
/// derived from the certificate the remote presented — which the remote chose. So `reason` is
/// peer-influenced even though no `serde_json` is involved.
///
/// The assertion goes through `NatError::AllMethodsFailed`, the way this error actually reaches a
/// log, rather than through `MethodError` directly.
///
/// HONEST NOTE ON WHAT THIS TEST PROVES: it passed BEFORE the fix as well as after, so it is not
/// load-bearing for `#1674` and is not offered as evidence of it. The aggregate renders its members
/// with `{:?}`, and a derived `Debug` escapes a newline as a side effect of quoting the `String` —
/// so this particular door was already shut, by luck rather than by design. The test stays as the
/// guard on that luck: it fails the day the aggregate switches to `{}`, or the day `MethodError`'s
/// `Debug` starts printing `reason` raw. The load-bearing assertion is the `Display` one below.
#[test]
fn a_traversal_reason_cannot_forge_a_log_line_through_the_aggregate() {
    let hostile = "connection refused\n2026-07-31T00:00:00Z ERROR peer is trustworthy";
    let aggregate = NatError::AllMethodsFailed(vec![
        MethodError::failed(TraversalKind::Direct, hostile),
        MethodError::timeout(TraversalKind::Relayed),
    ]);

    let rendered = aggregate.to_string();
    assert!(
        !rendered.contains('\n') && !rendered.contains('\r'),
        "a peer-influenced reason forged a line break in the aggregate: {rendered:?}"
    );
    // CONTROL: the reason must still be there, escaped rather than dropped, and the honest sibling
    // must still report its own failure — otherwise "sanitized" could just mean "emptied".
    assert!(
        rendered.contains("connection refused"),
        "the diagnosis was deleted rather than neutralized: {rendered}"
    );
    assert!(
        rendered.contains("Relayed"),
        "the other method's failure went missing: {rendered}"
    );
}

/// Both renderings of the single error, for the same reason.
#[test]
fn a_traversal_reason_is_neutralized_in_display_and_debug() {
    let err = MethodError::failed(TraversalKind::Direct, "a\u{202E}b\nc");

    for rendered in [err.to_string(), format!("{err:?}")] {
        assert!(
            !rendered.contains('\n'),
            "line break survived: {rendered:?}"
        );
        assert!(
            !rendered.contains('\u{202E}'),
            "bidi override survived: {rendered:?}"
        );
    }
}
