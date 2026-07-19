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
/// ## Address-family policy — IPv6-first, IPv4-fallback (via `dig-ip`)
///
/// The candidate list is stored in DISCOVERY order — the IPv6-first preference + the local∩peer
/// family intersection are applied at DIAL time by the canonical `dig-ip` crate ([`crate::dialer`]),
/// not by this type. So a peer reachable over IPv6 is dialed over IPv6 and IPv4 is used only as a
/// fallback, but a caller supplies candidates in whatever order it discovered them. Use
/// [`PeerTarget::with_addrs`] to supply several candidates; [`PeerTarget::with_addr`] for a single
/// one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerTarget {
    /// The peer's network identity — SHA-256 of its TLS SPKI DER. Used to VERIFY the mTLS peer and
    /// to address it over the relay. Required.
    pub peer_id: PeerId,

    /// The peer's directly-dialable candidate `ip:port`s, in discovery order (family selection +
    /// IPv6-first preference are applied at dial time by `dig-ip`; see the type-level address-family
    /// policy). Empty when the peer is only reachable via the relay. Prefer the
    /// [`PeerTarget::with_addrs`]/[`PeerTarget::with_addr`] constructors or
    /// [`PeerTarget::set_direct_addrs`] over mutating this directly; read it via
    /// [`PeerTarget::direct_addrs`] (all) or [`PeerTarget::direct_addr`] (the first candidate).
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

    /// A peer known by one OR MORE direct candidate addresses, kept in the order supplied. The
    /// dialer (`dig-ip`) applies the IPv6-first preference + local∩peer family intersection at dial
    /// time, so the caller need not pre-order the candidates.
    pub fn with_addrs(
        peer_id: PeerId,
        direct_addrs: Vec<SocketAddr>,
        network_id: impl Into<String>,
    ) -> Self {
        PeerTarget {
            peer_id,
            direct_addrs,
            network_id: network_id.into(),
        }
    }

    /// A peer known only by identity — reachable via relay-coordinated methods.
    pub fn relay_only(peer_id: PeerId, network_id: impl Into<String>) -> Self {
        PeerTarget {
            peer_id,
            direct_addrs: Vec::new(),
            network_id: network_id.into(),
        }
    }

    /// The peer's candidate addresses, in discovery order. Empty for a relay-only target. The dial
    /// order (IPv6-first, intersected with the local host's families) is computed by `dig-ip` at
    /// dial time.
    pub fn direct_addrs(&self) -> &[SocketAddr] {
        &self.direct_addrs
    }

    /// The first candidate address, or `None` for a relay-only target.
    ///
    /// A convenience accessor for callers that want ONE address; it returns the first candidate in
    /// discovery order. Prefer [`PeerTarget::direct_addrs`] so the dialer honours the full
    /// family-aware happy-eyeballs fallback (`dig-ip`).
    pub fn direct_addr(&self) -> Option<SocketAddr> {
        self.direct_addrs.first().copied()
    }

    /// Replace the candidate list (kept in the order supplied).
    pub fn set_direct_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.direct_addrs = addrs;
    }
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
    /// The peer's verified BLS G1 identity pubkey (#1204), captured from the cert binding when the
    /// handshake carried a valid one. `None` for a legacy peer with no binding (or when binding
    /// verification was off). The sealing layer (S2) seals directed payloads to this key so a
    /// misdelivery cannot be opened by the wrong node.
    pub peer_bls_pub: Option<[u8; 48]>,
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
            .field(
                "peer_bls_pub",
                &self.peer_bls_pub.map(|_| "<48-byte G1 pubkey>"),
            )
            .field("session", &"<multiplexed mTLS session>")
            .finish()
    }
}
