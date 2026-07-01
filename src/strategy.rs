//! The traversal strategy — orders the enabled methods (direct-first, relay-last), tries each with
//! a bounded timeout, and returns the FIRST connection that establishes. This is where "the caller
//! doesn't choose the method" is realised.
//!
//! ## Order
//!
//! Methods are always attempted in [`TraversalKind::rank`] order — Direct → Upnp → NatPmp → Pcp →
//! HolePunch → Relayed — regardless of the order the caller listed them, so the cheapest/most-direct
//! path is preferred and the fully-relayed transport is genuinely the LAST resort.
//!
//! ## Two-stage attempt
//!
//! A method yields a [`MethodOutcome`] (a dial address + which technique). The strategy then asks
//! the [`Dialer`] to establish the mTLS session to that address. Both stages are bounded by the
//! per-method timeout, so a hung method OR a hung dial can never block `connect`. If both stages
//! fail for every method, the strategy returns [`NatError::AllMethodsFailed`] with the ordered
//! per-method reasons.
//!
//! ## Testability
//!
//! [`Dialer`] abstracts the mTLS dial (real impl in [`crate::dialer`]; tests inject a fake that
//! returns a canned outcome), and the methods are [`TraversalMethod`] trait objects (tests inject
//! mocks). So the ordering, first-success-wins, relay-last, and all-fail→error behaviour are all
//! tested with NO real network.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::error::{MethodError, NatError};
use crate::method::{MethodOutcome, TraversalKind, TraversalMethod};
use crate::peer::{PeerConnection, PeerTarget};

/// Establishes the actual mTLS peer connection once a method has produced a reachable address.
///
/// For the direct/mapping/hole-punch methods this is a rustls mTLS dial to `outcome.dial_addr`; for
/// the relayed method it opens the mTLS session tunnelled through the relay. Abstracted so the
/// strategy is testable and the transport detail lives in one place ([`crate::dialer`]).
#[async_trait]
pub trait Dialer: Send + Sync {
    /// Establish an mTLS connection to `peer` using the reachable address in `outcome`, verifying
    /// the remote's `peer_id` matches [`PeerTarget::peer_id`]. `Err` = the dial or verification
    /// failed (the strategy falls through to the next method).
    async fn dial(
        &self,
        peer: &PeerTarget,
        outcome: &MethodOutcome,
    ) -> Result<PeerConnection, MethodError>;
}

/// Run the traversal strategy: try each enabled method in rank order; the first that produces a
/// verified mTLS [`PeerConnection`] wins. `methods` may be listed in any order — they are sorted by
/// [`TraversalKind::rank`] here so ordering is guaranteed independent of caller input.
///
/// Returns [`NatError::NoMethodsEnabled`] if `methods` is empty, else the first success, else
/// [`NatError::AllMethodsFailed`] with every method's reason in attempt order.
pub async fn connect_with_strategy(
    peer: &PeerTarget,
    methods: Vec<Arc<dyn TraversalMethod>>,
    dialer: &dyn Dialer,
    per_method_timeout: Duration,
) -> Result<PeerConnection, NatError> {
    if methods.is_empty() {
        return Err(NatError::NoMethodsEnabled);
    }

    // Guarantee direct-first, relay-last regardless of how the caller ordered `methods`.
    let mut ordered = methods;
    ordered.sort_by_key(|m| m.kind().rank());

    let mut failures: Vec<MethodError> = Vec::with_capacity(ordered.len());

    for method in ordered {
        let kind = method.kind();
        // Stage 1: the method produces a reachable address (bounded).
        let outcome = match run_bounded(per_method_timeout, kind, method.attempt(peer)).await {
            Ok(outcome) => outcome,
            Err(e) => {
                tracing::debug!(?kind, reason = %e.reason, "traversal method did not produce an address");
                failures.push(e);
                continue;
            }
        };
        // Stage 2: dial + mTLS-verify to that address (bounded).
        match run_bounded(per_method_timeout, kind, dialer.dial(peer, &outcome)).await {
            Ok(conn) => {
                tracing::info!(?kind, remote = %conn.remote_addr, "peer connection established");
                return Ok(conn);
            }
            Err(e) => {
                tracing::debug!(?kind, reason = %e.reason, "dial failed; falling through");
                failures.push(e);
            }
        }
    }

    Err(NatError::AllMethodsFailed(failures))
}

/// Run one method/dial future under a hard timeout, mapping a timeout to [`MethodError::timeout`].
/// This is the guarantee that a stuck method can never hang `connect`.
async fn run_bounded<T, F>(timeout: Duration, kind: TraversalKind, fut: F) -> Result<T, MethodError>
where
    F: std::future::Future<Output = Result<T, MethodError>>,
{
    match tokio::time::timeout(timeout, fut).await {
        Ok(res) => res,
        Err(_) => Err(MethodError::timeout(kind)),
    }
}
