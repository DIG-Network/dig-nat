//! Relayed-transport method (TURN-like) — the **last resort**, tier 6.
//!
//! This tier is **sharply distinct** from the tier-5 hole-punch ([`super::hole_punch`]):
//!
//! | Tier | Method | Relay's role | Relay bandwidth |
//! |------|--------|--------------|-----------------|
//! | 5 | [`HolePunchMethod`](super::hole_punch::HolePunchMethod) | **signaling only** — brokers a candidate exchange, then the DATA path is peer-to-peer direct | minimal (a few coordination messages) |
//! | 6 | [`RelayedTransportMethod`] (this) | **carries ALL data** — every byte of the peer connection is proxied through the relay (RLY-002 `relay_message`) | highest — the relay proxies the whole stream |
//!
//! Because tier 6 costs the relay the most bandwidth, it is tried **only after** the tier-5 hole
//! punch fails: prefer brokering an introduction (hole punch) over proxying the stream (TURN). The
//! [`crate::strategy`] enforces this via [`super::TraversalKind::rank`] (HolePunch=4 < Relayed=5).
//!
//! After the relay opens the tunnel, the resulting byte stream is still wrapped in the same mTLS
//! (peer_id = SHA-256(SPKI)) as every other tier — the relay proxies ciphertext it cannot read.
//!
//! The relay data-plane is abstracted behind [`RelayedTransport`] so the method is unit-tested with
//! a mock (no real relay). The production impl — [`ReservationRelayedTransport`] — opens an RLY-002
//! forwarding channel to the target peer THROUGH the node's persistent relay reservation socket
//! (never a second connection), and hands the caller a [`RelayTunnel`] for the byte stream.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;

use crate::error::MethodError;
use crate::method::{MethodOutcome, TraversalKind, TraversalMethod};
use crate::peer::PeerTarget;
use crate::relay::{RelayStatus, RelayTunnel};

/// A relayed transport that opens the DUPLEX BYTE TUNNEL an mTLS session runs over — the transport
/// half of the tier-6 relayed dial. Distinct from [`RelayedTransport`] (which only reports a probe
/// endpoint): this yields the actual byte channel, so a relayed connection carries the SAME dig-tls
/// mTLS + `peer_id` pin + BLS binding as a direct one (the relay forwards ciphertext it cannot read).
///
/// [`crate::connect`] composes the relayed tier only when a `RelayedDialer` is supplied via the
/// runtime carrier; the [`crate::dialer::MtlsDialer`] uses it to open the tunnel for a
/// [`TraversalKind::Relayed`] outcome, then runs the identical handshake over it.
#[async_trait]
pub trait RelayedDialer: Send + Sync {
    /// The relay endpoint the tunnel forwards through (observability + the relayed dial address).
    fn relay_endpoint(&self) -> SocketAddr;

    /// Whether a relayed tunnel can currently be opened (a reservation is held). The relayed method's
    /// [`attempt`](TraversalMethod::attempt) gates on this so an unavailable relay falls through
    /// cleanly rather than producing a doomed dial.
    fn is_ready(&self) -> bool;

    /// Open a live duplex tunnel to `target_peer` (hex `peer_id`) on `network_id`. `Err` if the
    /// reservation is not held. The returned [`RelayTunnel`] is wrapped in a byte-stream adapter and
    /// the mTLS handshake runs over it.
    async fn open_dial_tunnel(
        &self,
        target_peer: &str,
        network_id: &str,
    ) -> Result<RelayTunnel, String>;
}

#[async_trait]
impl RelayedDialer for ReservationRelayedTransport {
    fn relay_endpoint(&self) -> SocketAddr {
        self.relay_endpoint
    }

    fn is_ready(&self) -> bool {
        self.status.relay_transport_ready()
    }

    async fn open_dial_tunnel(
        &self,
        target_peer: &str,
        network_id: &str,
    ) -> Result<RelayTunnel, String> {
        self.status.open_tunnel(target_peer, network_id)
    }
}

/// The relayed (tier-6, TURN-last) traversal method built over a [`RelayedDialer`]. Its
/// [`attempt`](TraversalMethod::attempt) confirms the relay reservation is ready and yields the relay
/// endpoint as the dial address; the actual byte tunnel + mTLS is opened by the dialer. This is the
/// method [`crate::connect`] auto-composes for the relayed tier (given a runtime `RelayedDialer`).
pub struct RelayedDialMethod {
    dialer: Arc<dyn RelayedDialer>,
}

impl RelayedDialMethod {
    /// Build the relayed method over a live [`RelayedDialer`] (the relay data-plane).
    pub fn new(dialer: Arc<dyn RelayedDialer>) -> Self {
        RelayedDialMethod { dialer }
    }
}

#[async_trait]
impl TraversalMethod for RelayedDialMethod {
    fn kind(&self) -> TraversalKind {
        TraversalKind::Relayed
    }

    async fn attempt(&self, _peer: &PeerTarget) -> Result<MethodOutcome, MethodError> {
        if !self.dialer.is_ready() {
            return Err(MethodError::failed(
                TraversalKind::Relayed,
                "relay reservation not connected — relayed transport unavailable",
            ));
        }
        // The dial address is the relay endpoint (observability); the dialer opens the real tunnel to
        // the peer over the held reservation.
        Ok(MethodOutcome::single(
            TraversalKind::Relayed,
            self.dialer.relay_endpoint(),
        ))
    }
}

/// Abstraction over the relay **data plane**: open a stream to `target_peer` whose bytes are
/// proxied THROUGH the relay (RLY-002). This is the tier-6 TURN-like fallback — distinct from the
/// tier-5 [`HolePunchCoordinator`](super::hole_punch::HolePunchCoordinator), which only signals.
///
/// Returns the relay endpoint the data flows over (for observability — the mTLS session then runs
/// over that tunnel). `Err` = the relay could not open the forwarding channel (peer offline / relay
/// down / disabled).
#[async_trait]
pub trait RelayedTransport: Send + Sync {
    /// Open a relay-proxied data channel to `target_peer` on `network_id`. Returns the relay's
    /// endpoint address (the data path). `Err` = could not establish the tunnel.
    async fn open_relayed(&self, target_peer: &str, network_id: &str)
        -> Result<SocketAddr, String>;
}

/// The tier-6 relayed-transport (TURN-like) method — proxies ALL peer data through the relay. Only
/// reached when every more-direct method (including the tier-5 hole punch) has failed.
pub struct RelayedTransportMethod<T: RelayedTransport> {
    transport: T,
}

impl<T: RelayedTransport> RelayedTransportMethod<T> {
    /// Build a relayed-transport method over `transport` (the relay data-plane).
    pub fn new(transport: T) -> Self {
        RelayedTransportMethod { transport }
    }
}

#[async_trait]
impl<T: RelayedTransport> TraversalMethod for RelayedTransportMethod<T> {
    fn kind(&self) -> TraversalKind {
        TraversalKind::Relayed
    }

    async fn attempt(&self, peer: &PeerTarget) -> Result<MethodOutcome, MethodError> {
        let relay_addr = self
            .transport
            .open_relayed(&peer.peer_id.to_hex(), &peer.network_id)
            .await
            .map_err(|e| MethodError::failed(TraversalKind::Relayed, e))?;
        // The "dial address" for the relayed tier is the RELAY — all data flows through it (a single
        // endpoint, not a candidate list).
        Ok(MethodOutcome::single(TraversalKind::Relayed, relay_addr))
    }
}

/// The PRODUCTION [`RelayedTransport`]: opens the RLY-002 forwarding channel over the node's LIVE
/// persistent relay reservation (never a second socket), reusing the same [`RelayStatus`] handle the
/// reservation loop publishes its outbound sink through. This is the tier-6 TURN fallback made real.
///
/// `open_relayed` (the ladder seam) confirms the reservation is held and the target is reachable via
/// the relay, returning the relay endpoint for observability. The actual byte stream is obtained with
/// [`open_tunnel`](Self::open_tunnel), which yields a [`RelayTunnel`] that forwards A→relay→B; per
/// NC-1 the caller seals every payload to the recipient, so the relay forwards ciphertext only.
pub struct ReservationRelayedTransport {
    /// Shared handle to the persistent reservation — its live outbound sink + tunnel registry.
    status: Arc<RelayStatus>,
    /// The relay endpoint the data is forwarded through (observability; the byte path is the WS).
    relay_endpoint: SocketAddr,
}

impl ReservationRelayedTransport {
    /// Build the production transport over a live relay reservation (`status`) that forwards through
    /// `relay_endpoint`.
    pub fn new(status: Arc<RelayStatus>, relay_endpoint: SocketAddr) -> Self {
        ReservationRelayedTransport {
            status,
            relay_endpoint,
        }
    }

    /// Open a live RLY-002 relayed tunnel to `target_peer` (hex `peer_id`) over the held reservation.
    /// The returned [`RelayTunnel`] sends/receives payloads forwarded A→relay→B. `Err` if no
    /// reservation is currently held.
    pub fn open_tunnel(&self, target_peer: &str, network_id: &str) -> Result<RelayTunnel, String> {
        self.status.open_tunnel(target_peer, network_id)
    }
}

#[async_trait]
impl RelayedTransport for ReservationRelayedTransport {
    async fn open_relayed(
        &self,
        target_peer: &str,
        network_id: &str,
    ) -> Result<SocketAddr, String> {
        // Prove the RLY-002 forwarding channel can be established over the held reservation by opening
        // (then releasing) a tunnel to the target; the working tunnel is taken via `open_tunnel`. A
        // relay session must be live — otherwise this tier genuinely cannot carry the connection.
        let _probe = self.status.open_tunnel(target_peer, network_id)?;
        Ok(self.relay_endpoint)
    }
}
