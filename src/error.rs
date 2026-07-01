//! Error + status types for NAT traversal.
//!
//! The public surface returns a single [`NatError`] so a caller never has to match on
//! transport-internal error zoo. Each traversal method's failure is captured as a
//! [`MethodError`] and, when *every* method fails, aggregated into
//! [`NatError::AllMethodsFailed`] carrying the per-method reasons — so an operator/agent can see
//! exactly why each path was rejected without scraping logs.

use crate::method::TraversalKind;

/// Peer-RPC JSON-RPC error codes from the L7 peer-network spec (§7, §9). Exposed so a node building
/// its RPC surface over dig-nat maps transport outcomes to the exact catalogued codes.
pub mod rpc_error_codes {
    /// `-32004` RESOURCE_UNAVAILABLE — the peer does not hold the resource/capsule at the requested
    /// root (try another source).
    pub const RESOURCE_UNAVAILABLE: i32 = -32004;
    /// `-32006` PEER_UNREACHABLE — no connection to the named peer could be established (every
    /// traversal strategy failed) or the peer is not registered on this network. Maps from
    /// [`super::NatError::AllMethodsFailed`].
    pub const PEER_UNREACHABLE: i32 = -32006;
    /// `-32007` RANGE_NOT_SATISFIABLE — the requested `offset`/`length` lies outside the resource, or
    /// the range is otherwise unsatisfiable.
    pub const RANGE_NOT_SATISFIABLE: i32 = -32007;
}

/// The single error type returned by the public [`crate::connect`] API.
///
/// A connection attempt degrades gracefully: each method is tried with bounded timeouts and, if
/// *all* enabled methods fail, [`NatError::AllMethodsFailed`] is returned with the ordered list of
/// per-method failures. `connect` never panics and never hangs — a stuck method is bounded by its
/// timeout and surfaces here as a [`MethodError::Timeout`].
#[derive(Debug, thiserror::Error)]
pub enum NatError {
    /// Every enabled traversal method failed. Carries the ordered per-method reasons (the order is
    /// the attempt order: direct → UPnP → NAT-PMP → PCP → hole-punch → relayed).
    #[error("all NAT traversal methods failed: {0:?}")]
    AllMethodsFailed(Vec<MethodError>),

    /// No traversal methods were enabled in the config, so there was nothing to try.
    #[error("no traversal methods enabled")]
    NoMethodsEnabled,

    /// The mTLS session was established but the peer's identity did not match the expected
    /// `peer_id` (SHA-256 of its TLS SubjectPublicKeyInfo DER). This is a hard security failure:
    /// the transport connected but to the wrong (or an unverifiable) peer.
    #[error("peer identity mismatch: expected {expected}, got {actual}")]
    PeerIdentityMismatch {
        /// The `peer_id` the caller asked to connect to (hex).
        expected: String,
        /// The `peer_id` derived from the certificate the remote actually presented (hex).
        actual: String,
    },

    /// Configuration was invalid (e.g. an unparseable relay endpoint or a bad local identity).
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}

impl NatError {
    /// The peer-RPC error code a node should surface when this connect failure bubbles up to its RPC
    /// layer. A failed traversal (all methods failed / peer identity mismatch / nothing enabled) is
    /// [`rpc_error_codes::PEER_UNREACHABLE`] (`-32006`) per the L7 spec.
    pub fn rpc_error_code(&self) -> i32 {
        rpc_error_codes::PEER_UNREACHABLE
    }
}

/// One traversal method's failure, tagged with which method produced it.
///
/// Aggregated into [`NatError::AllMethodsFailed`] in attempt order. The `kind` lets an agent see
/// *which* path failed and the `reason` is a stable human string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{kind:?}: {reason}")]
pub struct MethodError {
    /// Which traversal method produced this failure.
    pub kind: TraversalKind,
    /// A stable, human-readable reason (also machine-greppable).
    pub reason: String,
    /// Whether the failure was a timeout (vs an outright refusal / protocol error). Lets the
    /// strategy + observers distinguish "peer/gateway unreachable in time" from "actively rejected".
    pub timeout: bool,
}

impl MethodError {
    /// A non-timeout method failure.
    pub fn failed(kind: TraversalKind, reason: impl Into<String>) -> Self {
        MethodError {
            kind,
            reason: reason.into(),
            timeout: false,
        }
    }

    /// A timeout method failure (the method did not complete within its bounded deadline).
    pub fn timeout(kind: TraversalKind) -> Self {
        MethodError {
            kind,
            reason: format!("{kind:?} timed out"),
            timeout: true,
        }
    }
}
