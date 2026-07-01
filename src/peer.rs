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
/// The caller supplies the peer's stable [`PeerId`] (for mTLS verification) and any hint addresses
/// it knows (from discovery / the address manager / the relay peer list). At least one of
/// `direct_addr` or `peer_id`+relay reachability is needed; the strategy uses `direct_addr` for the
/// direct/mapping methods and `peer_id` for the relay-coordinated + relayed methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerTarget {
    /// The peer's network identity — SHA-256 of its TLS SPKI DER. Used to VERIFY the mTLS peer and
    /// to address it over the relay. Required.
    pub peer_id: PeerId,

    /// A directly-dialable `ip:port` for the peer, if known (e.g. a publicly reachable node, a
    /// port-forwarded node, or an address learned from discovery). Drives the direct + mapping
    /// methods. `None` when the peer is only reachable via the relay.
    pub direct_addr: Option<SocketAddr>,

    /// The network id the peer registered under (relay `network_id`, e.g. `DIG_MAINNET`). Used to
    /// scope relay peer lookups + hole-punch coordination.
    pub network_id: String,
}

impl PeerTarget {
    /// A peer known by a direct address (public / port-forwarded / discovered).
    pub fn with_addr(
        peer_id: PeerId,
        direct_addr: SocketAddr,
        network_id: impl Into<String>,
    ) -> Self {
        PeerTarget {
            peer_id,
            direct_addr: Some(direct_addr),
            network_id: network_id.into(),
        }
    }

    /// A peer known only by identity — reachable via relay-coordinated methods.
    pub fn relay_only(peer_id: PeerId, network_id: impl Into<String>) -> Self {
        PeerTarget {
            peer_id,
            direct_addr: None,
            network_id: network_id.into(),
        }
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
