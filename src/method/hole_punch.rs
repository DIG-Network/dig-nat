//! Relay-coordinated hole-punch method (RLY-007) — when both peers are behind NAT, use the relay as
//! a rendezvous to exchange server-reflexive addresses, then attempt a simultaneous open so a DIRECT
//! path forms across both NATs (no relayed traffic).
//!
//! Flow: this node learns its own reflexive address via STUN ([`crate::stun`]) and sends the relay a
//! [`RelayMessage::HolePunchRequest`](crate::wire::RelayMessage::HolePunchRequest) naming the target
//! peer + our external address. The relay forwards it and returns the peer's external address in a
//! [`RelayMessage::HolePunchCoordinate`](crate::wire::RelayMessage::HolePunchCoordinate). Both sides
//! then dial each other's external address at the same time, punching a hole through their NATs.
//!
//! This is the LAST method before the fully-relayed transport: it still yields a *direct* peer
//! address to dial, so a success avoids relaying traffic. The relay coordination is abstracted
//! behind [`HolePunchCoordinator`] so the method is unit-tested with a mock coordinator (no relay).

use std::net::SocketAddr;

use async_trait::async_trait;

use crate::error::MethodError;
use crate::method::{MethodOutcome, TraversalKind, TraversalMethod};
use crate::peer::PeerTarget;

/// Abstraction over the relay's RLY-007 hole-punch coordination: "given the target peer and my
/// external address, tell me the peer's external address so we can simultaneously open."
///
/// Real impl talks the `HolePunchRequest`/`HolePunchCoordinate` wire to the relay; tests supply a
/// mock returning a canned peer address (or an error) so the method logic is verified with no relay.
#[async_trait]
pub trait HolePunchCoordinator: Send + Sync {
    /// Exchange external addresses via the relay for `target_peer` and return the peer's external
    /// address to dial. `Err` = coordination failed (peer offline, relay down, timeout).
    async fn coordinate(
        &self,
        target_peer: &str,
        network_id: &str,
        my_external_addr: SocketAddr,
    ) -> Result<SocketAddr, String>;
}

/// The relay-coordinated hole-punch method. Needs this node's own reflexive (STUN-discovered)
/// external address to advertise, and a [`HolePunchCoordinator`] to exchange it with the peer.
pub struct HolePunchMethod<C: HolePunchCoordinator> {
    coordinator: C,
    /// This node's server-reflexive address (from [`crate::stun::query_reflexive_address`]).
    pub my_external_addr: SocketAddr,
}

impl<C: HolePunchCoordinator> HolePunchMethod<C> {
    /// Build a hole-punch method over `coordinator`, advertising `my_external_addr`.
    pub fn new(coordinator: C, my_external_addr: SocketAddr) -> Self {
        HolePunchMethod {
            coordinator,
            my_external_addr,
        }
    }
}

#[async_trait]
impl<C: HolePunchCoordinator> TraversalMethod for HolePunchMethod<C> {
    fn kind(&self) -> TraversalKind {
        TraversalKind::HolePunch
    }

    async fn attempt(&self, peer: &PeerTarget) -> Result<MethodOutcome, MethodError> {
        let peer_addr = self
            .coordinator
            .coordinate(
                &peer.peer_id.to_hex(),
                &peer.network_id,
                self.my_external_addr,
            )
            .await
            .map_err(|e| MethodError::failed(TraversalKind::HolePunch, e))?;
        // The coordinator returns the single peer address to simultaneously-open against (its family
        // is whatever the peers exchanged via STUN — IPv6 when both have it).
        Ok(MethodOutcome::single(TraversalKind::HolePunch, peer_addr))
    }
}
