//! `PeerTarget` candidate-list semantics after the dig-ip migration.
//!
//! Family selection + the IPv6-first preference now live in the canonical `dig-ip` crate and are
//! applied at DIAL time (see `tests/dial_family.rs` for that conformance matrix). `PeerTarget` itself
//! therefore just carries the peer's candidates in DISCOVERY order — it no longer sorts them. These
//! tests pin that storage contract; the direct method passes the list through unchanged.

use std::net::SocketAddr;

use dig_nat::method::direct::DirectMethod;
use dig_nat::method::{TraversalKind, TraversalMethod};
use dig_nat::{PeerId, PeerTarget};

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn id() -> PeerId {
    PeerId::from_bytes([1u8; 32])
}

// ---- PeerTarget candidate list: preserved in discovery order ----

/// A multi-candidate target keeps the candidates in the order supplied (dig-ip orders them at dial
/// time, so PeerTarget must NOT reorder — a caller's discovery order is preserved).
#[test]
fn peer_target_preserves_candidate_order() {
    let peer = PeerTarget::with_addrs(
        id(),
        vec![sa("203.0.113.5:4444"), sa("[2001:db8::1]:4444")],
        "DIG_MAINNET",
    );
    assert_eq!(
        peer.direct_addrs(),
        &[sa("203.0.113.5:4444"), sa("[2001:db8::1]:4444")],
        "candidates are kept in discovery order, not sorted",
    );
    // The single-addr accessor returns the first candidate in discovery order.
    assert_eq!(peer.direct_addr(), Some(sa("203.0.113.5:4444")));
}

/// The single-addr constructor is a one-element candidate list.
#[test]
fn peer_target_with_addr_is_single_candidate() {
    let peer = PeerTarget::with_addr(id(), sa("203.0.113.5:4444"), "DIG_MAINNET");
    assert_eq!(peer.direct_addrs(), &[sa("203.0.113.5:4444")]);
    assert_eq!(peer.direct_addr(), Some(sa("203.0.113.5:4444")));
}

/// Replacing the candidate list keeps the supplied order.
#[test]
fn set_direct_addrs_preserves_order() {
    let mut peer = PeerTarget::relay_only(id(), "DIG_MAINNET");
    peer.set_direct_addrs(vec![sa("10.0.0.1:1"), sa("[2001:db8::1]:1")]);
    assert_eq!(
        peer.direct_addrs(),
        &[sa("10.0.0.1:1"), sa("[2001:db8::1]:1")]
    );
}

/// A relay-only target has no candidates.
#[test]
fn peer_target_relay_only_has_no_candidates() {
    let peer = PeerTarget::relay_only(id(), "DIG_MAINNET");
    assert!(peer.direct_addrs().is_empty());
    assert_eq!(peer.direct_addr(), None);
}

// ---- Direct method carries the whole candidate list through unchanged ----

/// The direct method yields ALL of the peer's candidates, in discovery order (dig-ip orders them at
/// dial time).
#[tokio::test]
async fn direct_method_yields_full_candidate_list() {
    let peer = PeerTarget::with_addrs(
        id(),
        vec![sa("203.0.113.5:4444"), sa("[2001:db8::1]:4444")],
        "DIG_MAINNET",
    );
    let out = DirectMethod.attempt(&peer).await.unwrap();
    assert_eq!(out.kind, TraversalKind::Direct);
    assert_eq!(
        out.dial_addrs,
        vec![sa("203.0.113.5:4444"), sa("[2001:db8::1]:4444")],
        "the outcome carries the peer's candidate list in discovery order",
    );
}
