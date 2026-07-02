//! Direct method — the peer is already reachable at a known `ip:port` (publicly routable, or its
//! operator port-forwarded it). No NAT work needed: just hand the strategy the address to dial.
//!
//! This is FIRST in the traversal order because when it works it is the cheapest and lowest-latency
//! path. It "succeeds" merely by having an address; whether the dial then completes is the
//! strategy's mTLS step (a refused dial there falls through to the next method).

use async_trait::async_trait;

use crate::error::MethodError;
use crate::method::{MethodOutcome, TraversalKind, TraversalMethod};
use crate::peer::PeerTarget;

/// The direct-dial method: yields the peer's whole IPv6-first candidate list
/// ([`PeerTarget::direct_addrs`]) so the dialer tries IPv6 first and falls back to IPv4, or fails if
/// the peer has no known direct address (then the strategy moves on to the mapping/relay methods).
#[derive(Debug, Default, Clone, Copy)]
pub struct DirectMethod;

#[async_trait]
impl TraversalMethod for DirectMethod {
    fn kind(&self) -> TraversalKind {
        TraversalKind::Direct
    }

    async fn attempt(&self, peer: &PeerTarget) -> Result<MethodOutcome, MethodError> {
        let addrs = peer.direct_addrs();
        if addrs.is_empty() {
            return Err(MethodError::failed(
                TraversalKind::Direct,
                "peer has no known direct address",
            ));
        }
        // The peer's candidate list is already IPv6-first; carry all of it so the dial can fall back.
        Ok(MethodOutcome::candidates(
            TraversalKind::Direct,
            addrs.to_vec(),
        ))
    }
}
