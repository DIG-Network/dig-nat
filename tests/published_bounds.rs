//! `SPEC.md` §5.1 tells consumers to read the framing bounds as `dig_nat::<NAME>`. This file uses
//! exactly those paths, so the SPEC's claim is compiled rather than merely asserted in prose.
//!
//! Before 0.13.0 two of them did not resolve: `MAX_FIRST_FRAME_CHUNK_LENS` was `pub` on `mux` but
//! never re-exported at the crate root, and `MAX_INCLUSION_PROOF_B64` existed only as a test-local
//! `const` — so the word GUARANTEED in the spec rested on a premise no consumer could read and no
//! encoder enforced (#1655).

use dig_nat::{
    MAX_CHUNK_LENS_PER_FRAME, MAX_FIRST_FRAME_CHUNK_LENS, MAX_FRAMED_BODY, MAX_INCLUSION_PROOF_B64,
    MAX_RANGE_FRAME_PAYLOAD, MAX_RESOURCE_CHUNK_COUNT,
};

/// The published values, read through the public paths `SPEC.md` documents. Pinning them here means a
/// change to any shared byte-identical wire constant cannot land as a silent edit — it has to come with
/// a deliberate change to the number a second implementation is required to match.
#[test]
fn the_framing_bounds_are_readable_at_the_crate_root_with_their_published_values() {
    assert_eq!(MAX_FRAMED_BODY, 65_536);
    assert_eq!(MAX_RANGE_FRAME_PAYLOAD, 32_768);
    assert_eq!(MAX_INCLUSION_PROOF_B64, 4_096);
    assert_eq!(MAX_CHUNK_LENS_PER_FRAME, 2_048);
    assert_eq!(MAX_FIRST_FRAME_CHUNK_LENS, 2_486);
    assert_eq!(MAX_RESOURCE_CHUNK_COUNT, 1_048_576);
}

/// The resource ceiling is a bound on ONE allocation made from a peer-declared number, so the byte cost
/// at the ceiling is part of the published contract, not an implementation detail: 8 MB of `u64`.
///
/// Pinned rather than recomputed, because every raise of this number raises that allocation with it.
#[test]
fn the_resource_chunk_count_ceiling_costs_eight_megabytes_of_u64() {
    assert_eq!(
        MAX_RESOURCE_CHUNK_COUNT * std::mem::size_of::<u64>(),
        8 * 1024 * 1024
    );
}

/// The sender's paging threshold must stay strictly inside the hard arithmetic ceiling: the gap is the
/// deliberate margin that keeps a paged prologue representable even as fixed fields are added.
///
/// Checked at COMPILE time, since both sides are constants — a run-time assertion over two `const`s
/// only fires for whoever runs the suite, while this one fails the build for whoever edits the number.
const _: () = assert!(MAX_CHUNK_LENS_PER_FRAME < MAX_FIRST_FRAME_CHUNK_LENS);
