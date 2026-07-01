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
//! a mock (no real relay). The production impl opens an RLY-002 forwarding channel to the target
//! peer through the relay WebSocket.

use std::net::SocketAddr;

use async_trait::async_trait;

use crate::error::MethodError;
use crate::method::{MethodOutcome, TraversalKind, TraversalMethod};
use crate::peer::PeerTarget;

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
        Ok(MethodOutcome {
            kind: TraversalKind::Relayed,
            // The "dial address" for the relayed tier is the RELAY — all data flows through it.
            dial_addr: relay_addr,
        })
    }
}
