//! Reassembly of a **paged prologue** — the decode-side mirror of the 0.13.0 encoder (`SPEC.md`
//! §5.1.1), exercised over the REAL fallible [`RangeFrame::encode`] / [`RangeFrame::decode`] wire.
//!
//! ## Why every fixture crosses the real wire
//!
//! #1640 was an encode/decode asymmetry that survived because every fixture sat comfortably under the
//! ceiling it was supposed to measure — 8-byte mock frames, 20 KB and 27 KB e2e content. All of them
//! passed while the defect was live. So no page here is handed to the assembler as a bare `Vec`: each
//! is attached to a `RangeFrame`, put through `encode` (which refuses an over-budget body), read back
//! through `decode`, and only then accepted. A fixture that trips a published ceiling therefore fails
//! LOUDLY instead of quietly certifying a shape the protocol forbids.
//!
//! ## Why the round trip is sized at 5,000 chunks
//!
//! `MAX_CHUNK_LENS_PER_FRAME` is 2,048, so 5,000 entries is **three pages** — two full and one short
//! tail. A fixture at or below 2,048 is one page, which is the single-frame pre-0.13.0 shape and cannot
//! exhibit paging at all: it would pass against an assembler that ignored `chunk_lens_offset` entirely.
//!
//! ## Why each rejection has its own test
//!
//! A guard justified by ONE attacker behaviour is bypassed by the next variant of it — a *middle* page
//! instead of a last one, a repeated page instead of a missing one, an offset off by one instead of
//! wildly wrong. That pattern has cost this ecosystem three separate findings. Each rejection below is
//! therefore stated and tested as its own class member, with the fixture varying exactly one thing away
//! from the honest round trip above it.

use dig_nat::mux::{ChunkLensAssembler, ChunkLensError, RangeFrame};
use dig_nat::{MAX_CHUNK_LENS_PER_FRAME, MAX_RESOURCE_CHUNK_COUNT};

/// A resource layout of `chunk_count` plausible per-chunk ciphertext lengths.
///
/// Entries vary so that a page placed at the wrong offset produces a DIFFERENT array rather than an
/// accidentally equal one — a uniform layout makes misplacement invisible.
fn layout(chunk_count: usize) -> Vec<u64> {
    (0..chunk_count)
        .map(|i| 16_384 + (i as u64 % 977) * 241)
        .collect()
}

/// Put one page through the real wire: attach it to a frame with the full identity set, `encode`
/// (fallible — an over-budget page fails the test here), then `decode` and hand the decoded page to
/// `accept`.
///
/// The frame also carries a payload at `MAX_RANGE_FRAME_PAYLOAD`, because a prologue page never travels
/// alone: it rides a data frame. Measuring the page against an EMPTY frame would measure a narrower
/// frame than the protocol permits.
async fn accept_over_the_wire(
    assembler: &mut ChunkLensAssembler,
    offset: u64,
    page: &[u64],
    chunk_count: u64,
    total_length: u64,
) -> Result<(), ChunkLensError> {
    let frame = RangeFrame::data(offset, vec![0xA5; dig_nat::MAX_RANGE_FRAME_PAYLOAD])
        .with_identity("aa".repeat(32), total_length, chunk_count)
        .with_chunk_lens_page(offset, page.to_vec());

    let encoded = frame
        .encode()
        .expect("fixture frame must be encodable — an over-budget fixture is a broken fixture");

    // A guard against this fixture quietly shrinking back under the ceiling it is supposed to measure.
    // A full page riding a cap-sized payload must be a NEAR-ceiling frame; if a future edit makes these
    // frames small, this suite would go on passing while measuring nothing (#1640's exact failure mode).
    if page.len() == MAX_CHUNK_LENS_PER_FRAME {
        assert!(
            encoded.len() > 55_000 && encoded.len() <= dig_nat::MAX_FRAMED_BODY + 4,
            "a full-page fixture frame must sit just inside MAX_FRAMED_BODY, not far below it; got {} B",
            encoded.len()
        );
    }
    let decoded = RangeFrame::decode(&mut encoded.as_slice())
        .await
        .expect("decode must not fail on a frame we just encoded")
        .expect("a whole frame was written, so decode must yield one");

    let page = decoded
        .chunk_lens
        .expect("the page survives the round trip");
    let offset = decoded.chunk_lens_offset.expect("the offset survives too");
    assembler.accept_page(offset, &page)
}

/// The honest case, and the control every rejection test varies ONE thing away from: three pages of a
/// 5,000-entry layout, each crossing the real wire, reassemble byte-identically.
#[tokio::test]
async fn pages_of_a_multi_page_layout_reassemble_byte_identically() {
    let chunk_lens = layout(5_000);
    let total_length: u64 = chunk_lens.iter().sum();
    let pages = RangeFrame::split_chunk_lens_pages(&chunk_lens);

    assert_eq!(
        pages.len(),
        3,
        "5,000 entries at {MAX_CHUNK_LENS_PER_FRAME} per page is three pages — the fixture must be \
         genuinely above the paging threshold, not below it"
    );
    assert_eq!(
        pages.iter().map(|(_, p)| p.len()).collect::<Vec<_>>(),
        vec![2_048, 2_048, 904]
    );

    let mut assembler = ChunkLensAssembler::new(5_000).expect("5,000 is well inside the cap");
    for (offset, page) in &pages {
        assert!(
            !assembler.is_complete(),
            "not complete until every page lands"
        );
        accept_over_the_wire(&mut assembler, *offset, page, 5_000, total_length)
            .await
            .expect("an honest page is accepted");
    }

    assert!(assembler.is_complete());
    assert_eq!(
        assembler.into_chunk_lens().expect("complete, so it yields"),
        chunk_lens,
        "the reassembled array must be byte-identical to the one that was split"
    );
}

/// A single-frame layout — the pre-0.13.0 shape, one page at offset 0 — still reassembles, so an older
/// holder that sends one unpaged array keeps working (§5.1, additive).
#[tokio::test]
async fn a_single_unpaged_page_is_still_a_complete_prologue() {
    let chunk_lens = layout(1_000);
    let total_length: u64 = chunk_lens.iter().sum();
    let pages = RangeFrame::split_chunk_lens_pages(&chunk_lens);
    assert_eq!(pages.len(), 1, "1,000 entries fit one page");

    let mut assembler = ChunkLensAssembler::new(1_000).unwrap();
    accept_over_the_wire(&mut assembler, 0, &pages[0].1, 1_000, total_length)
        .await
        .unwrap();

    assert_eq!(assembler.into_chunk_lens().unwrap(), chunk_lens);
}

/// **Rejection: a repeated page.** Re-sending an already-filled page is refused, never silently
/// overwritten — otherwise the LAST sender of a page decides its contents, and a hostile page arriving
/// after an honest one wins.
#[tokio::test]
async fn a_duplicate_page_is_rejected_and_never_overwrites() {
    let chunk_lens = layout(5_000);
    let total_length: u64 = chunk_lens.iter().sum();
    let pages = RangeFrame::split_chunk_lens_pages(&chunk_lens);

    let mut assembler = ChunkLensAssembler::new(5_000).unwrap();
    accept_over_the_wire(&mut assembler, 0, &pages[0].1, 5_000, total_length)
        .await
        .unwrap();

    let lie: Vec<u64> = pages[0].1.iter().map(|_| 99_999).collect();
    let err = accept_over_the_wire(&mut assembler, 0, &lie, 5_000, total_length)
        .await
        .expect_err("the slot is filled, so the second page is refused");
    assert_eq!(err, ChunkLensError::DuplicatePage { offset: 0 });

    // The refusal must be a refusal, not a late detection: finish the array honestly and prove the
    // ORIGINAL bytes are what survived.
    for (offset, page) in &pages[1..] {
        accept_over_the_wire(&mut assembler, *offset, page, 5_000, total_length)
            .await
            .unwrap();
    }
    assert_eq!(assembler.into_chunk_lens().unwrap(), chunk_lens);
}

/// **Rejection: a page that overlaps the end of the array.** An aligned offset is not enough — a full
/// 2,048-entry page at the last page's offset extends past `chunk_count`, so it covers entries that do
/// not exist. Distinct from a duplicate: nothing is filled yet.
#[tokio::test]
async fn a_page_extending_past_the_end_is_rejected() {
    let chunk_lens = layout(5_000);
    let total_length: u64 = chunk_lens.iter().sum();

    let mut assembler = ChunkLensAssembler::new(5_000).unwrap();
    let oversized = vec![16_384_u64; MAX_CHUNK_LENS_PER_FRAME];
    let err = accept_over_the_wire(&mut assembler, 4_096, &oversized, 5_000, total_length)
        .await
        .expect_err("4,096 + 2,048 = 6,144 entries in a 5,000-entry array");

    assert_eq!(
        err,
        ChunkLensError::PageExtendsPastEnd {
            offset: 4_096,
            entries: 2_048,
            chunk_count: 5_000,
        }
    );
    assert!(!assembler.is_complete());
}

/// **Rejection: a short MIDDLE page.** The variant that bypasses a guard aimed only at a short LAST
/// page. Pages must tile exactly, so a non-final page carrying fewer than `MAX_CHUNK_LENS_PER_FRAME`
/// entries leaves a gap no page-aligned page can ever fill — refused on arrival rather than surfacing
/// as a mysterious incompleteness at EOF.
#[tokio::test]
async fn a_short_middle_page_is_rejected_on_arrival() {
    let chunk_lens = layout(5_000);
    let total_length: u64 = chunk_lens.iter().sum();

    let mut assembler = ChunkLensAssembler::new(5_000).unwrap();
    let short = &chunk_lens[0..2_047];
    let err = accept_over_the_wire(&mut assembler, 0, short, 5_000, total_length)
        .await
        .expect_err("a non-final page must be exactly full");

    assert_eq!(
        err,
        ChunkLensError::UnexpectedPageLength {
            offset: 0,
            entries: 2_047,
            expected: 2_048,
        }
    );
}

/// **Rejection: a misaligned offset.** Off by ONE, not wildly wrong — the cheap variant that a
/// range-only check waves through, and which would place entries across two page slots.
#[test]
fn a_misaligned_offset_is_rejected() {
    let mut assembler = ChunkLensAssembler::new(5_000).unwrap();
    let page = vec![16_384_u64; MAX_CHUNK_LENS_PER_FRAME];

    let err = assembler
        .accept_page(2_047, &page)
        .expect_err("2,047 is not a multiple of the page size");
    assert_eq!(err, ChunkLensError::MisalignedOffset { offset: 2_047 });

    // ...and one past the aligned boundary is refused for the same reason.
    assert_eq!(
        assembler.accept_page(2_049, &page).unwrap_err(),
        ChunkLensError::MisalignedOffset { offset: 2_049 }
    );
}

/// **Rejection: an over-cap page.** `MAX_CHUNK_LENS_PER_FRAME` is a shared wire constant, so a page of
/// 2,049 entries is refused as a protocol violation — pinned from BOTH sides, since a cap tested only
/// from above can be satisfied by a cap set anywhere below it.
#[test]
fn a_page_over_the_per_frame_cap_is_rejected_and_the_cap_itself_is_accepted() {
    let chunk_count = 3 * MAX_CHUNK_LENS_PER_FRAME;

    let mut assembler = ChunkLensAssembler::new(chunk_count).unwrap();
    let over = vec![16_384_u64; MAX_CHUNK_LENS_PER_FRAME + 1];
    assert_eq!(
        assembler.accept_page(0, &over).unwrap_err(),
        ChunkLensError::PageTooLarge {
            entries: MAX_CHUNK_LENS_PER_FRAME + 1,
        }
    );

    let at_cap = vec![16_384_u64; MAX_CHUNK_LENS_PER_FRAME];
    assembler
        .accept_page(0, &at_cap)
        .expect("exactly at the cap is legal — the bound is inclusive");
}

/// **Rejection: an empty page.** It fills nothing, so accepting it lets a sender stream frames forever
/// without ever completing the prologue.
#[test]
fn an_empty_page_is_rejected() {
    let mut assembler = ChunkLensAssembler::new(5_000).unwrap();
    assert_eq!(
        assembler.accept_page(0, &[]).unwrap_err(),
        ChunkLensError::EmptyPage { offset: 0 }
    );
}

/// **Rejection: an offset beyond the array.** The declared-offset variant of the allocation abort this
/// type exists to prevent — refused before any placement, not sized against.
#[test]
fn an_offset_past_the_declared_count_is_rejected() {
    let mut assembler = ChunkLensAssembler::new(5_000).unwrap();
    let page = vec![16_384_u64; 16];

    assert_eq!(
        assembler.accept_page(6_144, &page).unwrap_err(),
        ChunkLensError::OffsetOutOfRange {
            offset: 6_144,
            chunk_count: 5_000,
        }
    );
    // `u64::MAX - 2_047` is 2^64 - 2_048, which IS page-aligned, so alignment cannot be what saves us
    // here: the range check must compare in `u64` and reject, rather than truncate to a `usize` index.
    assert_eq!(
        assembler.accept_page(u64::MAX - 2_047, &page).unwrap_err(),
        ChunkLensError::OffsetOutOfRange {
            offset: u64::MAX - 2_047,
            chunk_count: 5_000,
        },
        "a huge aligned offset must not wrap into an accepted placement"
    );
}

/// **Rejection: a declared `chunk_count` over `MAX_RESOURCE_CHUNK_COUNT`.** Refused BEFORE the array is
/// allocated, which is the point: a ~64-byte frame declaring a vast count once aborted a node, and the
/// cap plus fallible reservation is what makes that a clean error instead.
#[test]
fn a_chunk_count_over_the_resource_cap_is_refused_before_allocating() {
    assert_eq!(
        ChunkLensAssembler::new(MAX_RESOURCE_CHUNK_COUNT + 1).unwrap_err(),
        ChunkLensError::ChunkCountTooLarge {
            chunk_count: MAX_RESOURCE_CHUNK_COUNT + 1,
        }
    );

    // Pinned from both sides: exactly at the ceiling must be constructible, or the published maximum
    // is not the maximum.
    ChunkLensAssembler::new(MAX_RESOURCE_CHUNK_COUNT)
        .expect("exactly at the cap is legal — the bound is inclusive");
}

/// A zero-chunk resource has no layout to reassemble, and an assembler that reported it "incomplete
/// forever" would stall a stream over a resource that is already fully described.
#[test]
fn a_zero_chunk_layout_is_complete_immediately_and_yields_an_empty_array() {
    let assembler = ChunkLensAssembler::new(0).unwrap();
    assert!(assembler.is_complete());
    assert!(assembler.into_chunk_lens().unwrap().is_empty());
}

/// **Rejection: incomplete at EOF.** The missing page is a MIDDLE one, so the failure cannot be
/// mistaken for "the stream stopped early" — and the assembler yields NO array rather than a partial
/// one. `chunk_lens` is a DECRYPT input; a partial array is unusable, never partially useful.
#[tokio::test]
async fn an_incomplete_prologue_yields_no_array_at_all() {
    let chunk_lens = layout(5_000);
    let total_length: u64 = chunk_lens.iter().sum();
    let pages = RangeFrame::split_chunk_lens_pages(&chunk_lens);

    let mut assembler = ChunkLensAssembler::new(5_000).unwrap();
    for (offset, page) in [&pages[0], &pages[2]] {
        accept_over_the_wire(&mut assembler, *offset, page, 5_000, total_length)
            .await
            .unwrap();
    }

    assert!(!assembler.is_complete(), "the middle page never arrived");
    assert_eq!(
        assembler.into_chunk_lens().unwrap_err(),
        ChunkLensError::Incomplete {
            have: 2_952,
            want: 5_000,
        }
    );
}

/// Splitting is the encoder mirror of accepting, so no serve path ever re-derives the paging rule. The
/// shape it produces must be exactly what the assembler requires: aligned offsets, full pages except
/// the tail, tiling the array without gap or overlap.
#[test]
fn splitting_produces_aligned_full_pages_that_tile_the_array() {
    for chunk_count in [0, 1, 2_047, 2_048, 2_049, 5_000, 4_096] {
        let chunk_lens = layout(chunk_count);
        let pages = RangeFrame::split_chunk_lens_pages(&chunk_lens);

        assert_eq!(
            pages.len(),
            chunk_count.div_ceil(MAX_CHUNK_LENS_PER_FRAME),
            "page count for {chunk_count} entries"
        );

        let mut next = 0_usize;
        for (offset, page) in &pages {
            assert_eq!(*offset as usize, next, "pages tile without gap or overlap");
            assert_eq!(offset % MAX_CHUNK_LENS_PER_FRAME as u64, 0, "aligned");
            assert!(!page.is_empty() && page.len() <= MAX_CHUNK_LENS_PER_FRAME);
            next += page.len();
        }
        assert_eq!(
            next, chunk_count,
            "the pages cover every entry, exactly once"
        );
        assert_eq!(
            pages
                .iter()
                .flat_map(|(_, p)| p)
                .copied()
                .collect::<Vec<_>>(),
            chunk_lens
        );
    }
}
