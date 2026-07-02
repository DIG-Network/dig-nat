//! The peer the caller wants to reach ([`PeerTarget`]) and the connection they get back
//! ([`PeerConnection`]).
//!
//! To the caller, [`crate::connect`] "just connects to a peer" — they describe the peer once and
//! receive an mTLS-authenticated [`PeerConnection`] whose remote `peer_id` has been verified. Which
//! traversal method got there is reported (observability) but never something the caller must
//! choose or handle.

use std::net::SocketAddr;

use crate::identity::PeerId;
use crate::method::TraversalKind;
use crate::mux::{PeerSession, PeerStream};

/// A description of the peer to connect to.
///
/// The caller supplies the peer's stable [`PeerId`] (for mTLS verification) and any candidate
/// addresses it knows (from discovery / the address manager / the relay peer list). At least one
/// direct candidate OR `peer_id`+relay reachability is needed; the strategy uses the candidate list
/// for the direct/mapping methods and `peer_id` for the relay-coordinated + relayed methods.
///
/// ## Address-family policy — IPv6-first, IPv4-fallback
///
/// The candidate list is stored **IPv6-first**: every IPv6 candidate precedes every IPv4 candidate,
/// with the relative order WITHIN each family preserved (a stable sort). This is the foundation of
/// the ecosystem's IPv6-first / IPv4-fallback rule — the dialer walks the candidates in order
/// (happy-eyeballs, [`crate::dialer`]) so a peer reachable over IPv6 is dialed over IPv6, and IPv4 is
/// used only when the IPv6 candidate(s) fail. Ordering is decided by the address FAMILY
/// ([`SocketAddr::is_ipv6`]), never by a string heuristic. Use [`PeerTarget::with_addrs`] to supply
/// several candidates (they are sorted for you); [`PeerTarget::with_addr`] for a single one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerTarget {
    /// The peer's network identity — SHA-256 of its TLS SPKI DER. Used to VERIFY the mTLS peer and
    /// to address it over the relay. Required.
    pub peer_id: PeerId,

    /// The peer's directly-dialable candidate `ip:port`s, ordered **IPv6-first** (see the
    /// type-level address-family policy). Empty when the peer is only reachable via the relay.
    /// Prefer the [`PeerTarget::with_addrs`]/[`PeerTarget::with_addr`] constructors (which enforce
    /// the ordering) or [`PeerTarget::set_direct_addrs`] over mutating this directly; read it via
    /// [`PeerTarget::direct_addrs`] (all, ordered) or [`PeerTarget::direct_addr`] (the
    /// IPv6-preferred first candidate).
    direct_addrs: Vec<SocketAddr>,

    /// The network id the peer registered under (relay `network_id`, e.g. `DIG_MAINNET`). Used to
    /// scope relay peer lookups + hole-punch coordination.
    pub network_id: String,
}

impl PeerTarget {
    /// A peer known by a single direct address (public / port-forwarded / discovered).
    pub fn with_addr(
        peer_id: PeerId,
        direct_addr: SocketAddr,
        network_id: impl Into<String>,
    ) -> Self {
        PeerTarget::with_addrs(peer_id, vec![direct_addr], network_id)
    }

    /// A peer known by one OR MORE direct candidate addresses. The candidates are stored
    /// **IPv6-first** (IPv6 candidates before IPv4, order-preserving within each family) so the
    /// dialer prefers IPv6 and falls back to IPv4 — pass them in any order.
    pub fn with_addrs(
        peer_id: PeerId,
        direct_addrs: Vec<SocketAddr>,
        network_id: impl Into<String>,
    ) -> Self {
        let mut t = PeerTarget {
            peer_id,
            direct_addrs,
            network_id: network_id.into(),
        };
        sort_ipv6_first(&mut t.direct_addrs);
        t
    }

    /// A peer known only by identity — reachable via relay-coordinated methods.
    pub fn relay_only(peer_id: PeerId, network_id: impl Into<String>) -> Self {
        PeerTarget {
            peer_id,
            direct_addrs: Vec::new(),
            network_id: network_id.into(),
        }
    }

    /// The peer's candidate addresses, ordered IPv6-first (the dial order). Empty for a relay-only
    /// target.
    pub fn direct_addrs(&self) -> &[SocketAddr] {
        &self.direct_addrs
    }

    /// The single best (IPv6-preferred) candidate address, or `None` for a relay-only target.
    ///
    /// This is the backwards-compatible accessor for callers that want ONE address: it returns the
    /// first candidate, which — because the list is IPv6-first — is the IPv6 candidate when one is
    /// known, otherwise the IPv4 fallback. Prefer [`PeerTarget::direct_addrs`] to honour the full
    /// happy-eyeballs fallback.
    pub fn direct_addr(&self) -> Option<SocketAddr> {
        self.direct_addrs.first().copied()
    }

    /// Replace the candidate list, re-establishing the IPv6-first ordering.
    pub fn set_direct_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.direct_addrs = addrs;
        sort_ipv6_first(&mut self.direct_addrs);
    }
}

/// Sort a candidate list **IPv6-first**: every IPv6 address precedes every IPv4 address, preserving
/// the relative order within each family (a stable sort). This is the single place the IPv6-first
/// ordering rule is applied. Ordering is decided by the address FAMILY ([`SocketAddr::is_ipv6`]),
/// never by inspecting the string form (a bracketed `[v6]:port` and an `v4:port` both contain ':').
pub fn sort_ipv6_first(addrs: &mut [SocketAddr]) {
    // Stable sort with IPv6 (key 0) before IPv4 (key 1); ties keep input order.
    addrs.sort_by_key(|a| if a.is_ipv6() { 0u8 } else { 1u8 });
}

/// An established, mutually-authenticated, **multiplexed** connection to a peer.
///
/// The connection is one mTLS byte stream whose remote presented a certificate whose `peer_id`
/// equals [`Self::peer_id`] (verified during the handshake by [`crate::mtls::PeerIdPinningVerifier`]),
/// wrapped in a [`PeerSession`] so the caller can open **many concurrent logical streams**
/// ([`open_stream`](Self::open_stream)) or **byte-range streams**
/// ([`open_range_stream`](Self::open_range_stream)) — streaming-first, no head-of-line blocking.
/// [`Self::method`] reports which traversal technique established it — observability only; the caller
/// opens streams identically regardless of the tier.
pub struct PeerConnection {
    /// The verified remote identity (== the [`PeerTarget::peer_id`] the caller asked for).
    pub peer_id: PeerId,
    /// The traversal technique that established this connection (Direct, Upnp, …, Relayed).
    pub method: TraversalKind,
    /// The remote address the mTLS session runs over (the peer's endpoint, or the relay for a
    /// relayed transport).
    pub remote_addr: SocketAddr,
    /// The multiplexed session over the authenticated, encrypted byte stream to the peer.
    pub session: PeerSession,
}

impl PeerConnection {
    /// Open a new concurrent logical stream to the peer (cheap; open as many as you need for
    /// simultaneous transfers without head-of-line blocking).
    pub async fn open_stream(&mut self) -> std::io::Result<PeerStream> {
        self.session.open_stream().await
    }

    /// Open a `dig.fetchRange` stream for `req` (writes the range-request preamble, then streams
    /// [`crate::mux::RangeFrame`]s). The primitive for multi-source parallel range downloads.
    pub async fn open_range_stream(
        &mut self,
        req: &crate::mux::RangeRequest,
    ) -> std::io::Result<PeerStream> {
        self.session.open_range_stream(req).await
    }

    /// Availability pre-check (`dig.getAvailability`) — ask whether this peer holds `items` BEFORE
    /// opening range streams (see [`crate::mux::PeerSession::query_availability`]).
    pub async fn query_availability(
        &mut self,
        items: Vec<crate::mux::AvailabilityItem>,
    ) -> std::io::Result<crate::mux::AvailabilityResponse> {
        self.session.query_availability(items).await
    }
}

impl std::fmt::Debug for PeerConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConnection")
            .field("peer_id", &self.peer_id)
            .field("method", &self.method)
            .field("remote_addr", &self.remote_addr)
            .field("session", &"<multiplexed mTLS session>")
            .finish()
    }
}
