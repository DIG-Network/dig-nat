//! Traversal methods — one module per NAT-traversal technique behind a common
//! [`TraversalMethod`] trait, plus the [`TraversalKind`] tag the strategy orders them by.
//!
//! Each method answers ONE question: "given this peer, can you produce a reachable socket address I
//! can dial (and, for the relayed method, an already-open transport)?" The [`crate::strategy`]
//! module owns the ORDER + the racing/sequencing; a method never decides it is "the one". This keeps
//! every technique small, single-purpose, and independently testable with a mock socket / fake IGD /
//! loopback relay.
//!
//! Attempt order (first success wins), from the crate `DESIGN.md`:
//! 1. [`direct`] — peer publicly reachable / already port-forwarded
//! 2. [`upnp`] — UPnP/IGD port mapping
//! 3. [`natpmp`] — NAT-PMP (RFC 6886)
//! 4. [`pcp`] — PCP (RFC 6887)
//! 5. [`hole_punch`] — relay-coordinated simultaneous-open hole punch: the relay is used ONLY as a
//!    signaling/rendezvous channel to exchange candidates + coordinate timing; the DATA path is
//!    peer-to-peer DIRECT (relay carries no data → minimal relay bandwidth).
//! 6. [`relayed`] — TURN-like relayed transport: the relay carries ALL data (highest relay
//!    bandwidth). The genuine LAST resort, tried only after the hole punch (tier 5) fails.
//!
//! Tiers 5 and 6 are deliberately SEPARATE methods with separate abstractions
//! ([`hole_punch::HolePunchCoordinator`] = signaling-only vs [`relayed::RelayedTransport`] =
//! data-proxy) and separate [`TraversalKind`]s so observability reports exactly which succeeded and
//! the strategy prefers the bandwidth-cheap punch before the bandwidth-heavy TURN.

pub mod direct;
pub mod hole_punch;
pub mod natpmp;
pub mod pcp;
pub mod relayed;
pub mod upnp;

use std::net::SocketAddr;

use async_trait::async_trait;

use crate::error::MethodError;
use crate::peer::PeerTarget;

/// Which traversal technique produced a result — used to order methods, tag failures, and report
/// (observability) which method actually succeeded WITHOUT the caller caring.
///
/// Ordinal order == attempt order == relay-last: a smaller [`TraversalKind::rank`] is tried first,
/// and `Relayed` has the highest rank so it is always the last resort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraversalKind {
    /// Peer is publicly reachable (or already port-forwarded) — dial it directly.
    Direct,
    /// A UPnP/IGD port mapping was created on the local gateway.
    Upnp,
    /// A NAT-PMP (RFC 6886) mapping was created.
    NatPmp,
    /// A PCP (RFC 6887) mapping was created.
    Pcp,
    /// A relay-coordinated hole punch established a direct path across both NATs.
    HolePunch,
    /// Traffic is tunnelled THROUGH the relay (last resort).
    Relayed,
}

impl TraversalKind {
    /// Attempt-order rank (lower = tried earlier). Guarantees direct-first and relayed-last.
    pub fn rank(self) -> u8 {
        match self {
            TraversalKind::Direct => 0,
            TraversalKind::Upnp => 1,
            TraversalKind::NatPmp => 2,
            TraversalKind::Pcp => 3,
            TraversalKind::HolePunch => 4,
            TraversalKind::Relayed => 5,
        }
    }
}

/// What a traversal method yields on success: the dialable candidate addresses for the peer
/// (ordered **IPv6-first**), plus which technique produced them. The [`crate::strategy`] then
/// performs the mTLS dial, trying the candidates IPv6-first with IPv4 fallback (happy-eyeballs, see
/// [`crate::dialer`]) — except the relayed method, which returns the already-open relay tunnel.
///
/// The direct/mapping methods carry the peer's whole IPv6-first candidate list so the dial can fall
/// back across families; the hole-punch/relayed methods yield a single coordinated/relay address
/// ([`MethodOutcome::single`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodOutcome {
    /// Which technique produced these reachable addresses.
    pub kind: TraversalKind,
    /// The candidate addresses the strategy should dial, ordered **IPv6-first** (peer public
    /// endpoints, a hole-punched peer address, the relay endpoint, or — mapping methods — the peer
    /// candidates to try after opening the local pinhole). The dialer tries them IPv6-first and
    /// falls back to IPv4. Never empty on success.
    pub dial_addrs: Vec<SocketAddr>,
}

impl MethodOutcome {
    /// An outcome carrying a SINGLE dial address (hole-punch / relayed tiers, which yield one
    /// coordinated peer address or the relay endpoint).
    pub fn single(kind: TraversalKind, dial_addr: SocketAddr) -> Self {
        MethodOutcome {
            kind,
            dial_addrs: vec![dial_addr],
        }
    }

    /// An outcome carrying the peer's ordered candidate list (direct / mapping tiers). The addresses
    /// are (re-)sorted IPv6-first so the dial honours the fallback order regardless of input order.
    pub fn candidates(kind: TraversalKind, mut dial_addrs: Vec<SocketAddr>) -> Self {
        crate::peer::sort_ipv6_first(&mut dial_addrs);
        MethodOutcome { kind, dial_addrs }
    }

    /// The single best (IPv6-preferred) dial address — the first candidate — or `None` if empty.
    pub fn dial_addr(&self) -> Option<SocketAddr> {
        self.dial_addrs.first().copied()
    }
}

/// A single NAT-traversal technique. Implementors are small + single-purpose and MUST honour the
/// deadline the strategy hands them (they are additionally wrapped in a hard timeout by the
/// strategy, so a hung method can never block `connect`).
#[async_trait]
pub trait TraversalMethod: Send + Sync {
    /// Which technique this is (for ordering + observability).
    fn kind(&self) -> TraversalKind;

    /// Attempt to produce a reachable address for `peer`. `Ok(outcome)` means "try dialing this";
    /// `Err` means this technique did not work (the strategy falls through to the next one).
    async fn attempt(&self, peer: &PeerTarget) -> Result<MethodOutcome, MethodError>;
}
