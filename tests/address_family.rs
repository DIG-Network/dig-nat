//! IPv6-first candidate-ordering + happy-eyeballs dial tests (the ecosystem IPv6-first rule).
//!
//! These assert the ADDRESS-FAMILY POLICY of dig-nat: a peer's candidate addresses are carried as an
//! ordered list with IPv6 first (IPv4 fallback), the ordering is by `IpAddr` family (never a string
//! heuristic), and the dialer tries the candidates IPv6-first, falling back to IPv4 only when the
//! IPv6 attempt fails. No real network — the dial timeout/stagger seams are injected.

use std::net::SocketAddr;

use dig_nat::method::direct::DirectMethod;
use dig_nat::method::{TraversalKind, TraversalMethod};
use dig_nat::peer::is_ipv6_first;
use dig_nat::{PeerId, PeerTarget};

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn id() -> PeerId {
    PeerId::from_bytes([1u8; 32])
}

// ---- PeerTarget candidate list: IPv6-first ordering ----

/// A multi-candidate target orders IPv6 candidates BEFORE IPv4 regardless of input order.
#[test]
fn peer_target_orders_ipv6_before_ipv4() {
    // Deliberately pass IPv4 first, then IPv6.
    let peer = PeerTarget::with_addrs(
        id(),
        vec![sa("203.0.113.5:4444"), sa("[2001:db8::1]:4444")],
        "DIG_MAINNET",
    );
    let addrs = peer.direct_addrs();
    assert_eq!(addrs.len(), 2);
    assert!(addrs[0].is_ipv6(), "IPv6 candidate must come first");
    assert!(
        addrs[1].is_ipv4(),
        "IPv4 candidate is the fallback (second)"
    );
    // The single-addr accessor returns the IPv6-preferred first candidate.
    assert_eq!(peer.direct_addr(), Some(sa("[2001:db8::1]:4444")));
}

/// Ordering uses the IP family, NOT a `contains(':')` string heuristic — a bracketed IPv6 with a
/// port has a ':' in it and an IPv4:port also has a ':'; only `IpAddr::is_ipv6` gets this right.
#[test]
fn peer_target_ordering_is_by_family_not_string() {
    let peer = PeerTarget::with_addrs(
        id(),
        vec![
            sa("198.51.100.7:9"),          // IPv4 (has a ':')
            sa("[2001:db8::dead:beef]:9"), // IPv6 (has many ':')
        ],
        "DIG_MAINNET",
    );
    let addrs = peer.direct_addrs();
    assert!(addrs[0].is_ipv6());
    assert!(addrs[1].is_ipv4());
}

/// A stable, order-preserving sort: two IPv6 candidates keep their relative input order (so a caller
/// can express a preference among same-family candidates), and likewise for two IPv4.
#[test]
fn peer_target_ordering_is_stable_within_family() {
    let peer = PeerTarget::with_addrs(
        id(),
        vec![
            sa("[2001:db8::2]:1"),
            sa("10.0.0.1:1"),
            sa("[2001:db8::1]:1"),
            sa("10.0.0.2:1"),
        ],
        "DIG_MAINNET",
    );
    assert_eq!(
        peer.direct_addrs(),
        &[
            sa("[2001:db8::2]:1"),
            sa("[2001:db8::1]:1"),
            sa("10.0.0.1:1"),
            sa("10.0.0.2:1"),
        ]
    );
}

/// The single-addr constructor still works and is a one-element candidate list.
#[test]
fn peer_target_with_addr_is_single_candidate() {
    let peer = PeerTarget::with_addr(id(), sa("203.0.113.5:4444"), "DIG_MAINNET");
    assert_eq!(peer.direct_addrs(), &[sa("203.0.113.5:4444")]);
    assert_eq!(peer.direct_addr(), Some(sa("203.0.113.5:4444")));
}

/// A relay-only target has no candidates.
#[test]
fn peer_target_relay_only_has_no_candidates() {
    let peer = PeerTarget::relay_only(id(), "DIG_MAINNET");
    assert!(peer.direct_addrs().is_empty());
    assert_eq!(peer.direct_addr(), None);
}

// ---- #179 LOW/optimization: cheap "already IPv6-first?" check for the dial hot path ----
//
// `happy_eyeballs_connect` (dialer.rs) clones + re-sorts the WHOLE candidate slice on every connect
// attempt even though callers (PeerTarget::direct_addrs, MethodOutcome::candidates) already hand it
// an IPv6-first list. `is_ipv6_first` is the cheap `O(n)` check that lets the hot path skip the
// clone+sort when it would be a no-op, while still catching genuinely unsorted input so the
// defensive re-order guarantee is never dropped.

#[test]
fn is_ipv6_first_true_for_already_ordered_lists() {
    assert!(is_ipv6_first(&[]), "empty list is trivially ordered");
    assert!(is_ipv6_first(&[sa("[2001:db8::1]:1")]));
    assert!(is_ipv6_first(&[sa("10.0.0.1:1")]));
    assert!(is_ipv6_first(&[
        sa("[2001:db8::1]:1"),
        sa("[2001:db8::2]:1"),
        sa("10.0.0.1:1"),
        sa("10.0.0.2:1"),
    ]));
}

#[test]
fn is_ipv6_first_false_for_ipv4_before_ipv6() {
    assert!(!is_ipv6_first(&[sa("10.0.0.1:1"), sa("[2001:db8::1]:1")]));
    // A single IPv4 candidate ahead of a mixed tail is still unsorted.
    assert!(!is_ipv6_first(&[
        sa("10.0.0.1:1"),
        sa("[2001:db8::1]:1"),
        sa("10.0.0.2:1"),
    ]));
}

// `happy_eyeballs_connect` must still defensively re-order genuinely-unsorted input (the
// optimization must never drop the IPv6-first ordering guarantee) — covered end-to-end by
// `attempts_ipv6_before_ipv4_on_all_fail` in `tests/happy_eyeballs.rs`, which passes an
// intentionally IPv4-first candidate list straight into the public dial function.

// ---- Direct method carries the whole ordered candidate list ----

/// The direct method yields ALL of the peer's candidates (IPv6-first), not just one.
#[tokio::test]
async fn direct_method_yields_full_ordered_candidate_list() {
    let peer = PeerTarget::with_addrs(
        id(),
        vec![sa("203.0.113.5:4444"), sa("[2001:db8::1]:4444")],
        "DIG_MAINNET",
    );
    let out = DirectMethod.attempt(&peer).await.unwrap();
    assert_eq!(out.kind, TraversalKind::Direct);
    assert_eq!(
        out.dial_addrs,
        vec![sa("[2001:db8::1]:4444"), sa("203.0.113.5:4444")],
        "the outcome carries the IPv6-first ordered candidate list"
    );
    // First candidate is IPv6.
    assert!(out.dial_addr().unwrap().is_ipv6());
}
