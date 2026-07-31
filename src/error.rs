//! Error + status types for NAT traversal.
//!
//! The public surface returns a single [`NatError`] so a caller never has to match on
//! transport-internal error zoo. Each traversal method's failure is captured as a
//! [`MethodError`] and, when *every* method fails, aggregated into
//! [`NatError::AllMethodsFailed`] carrying the per-method reasons — so an operator/agent can see
//! exactly why each path was rejected without scraping logs.

use std::fmt;

use crate::method::TraversalKind;
use crate::safe_text::SafeText;

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
#[derive(Clone, PartialEq, Eq)]
pub struct MethodError {
    /// Which traversal method produced this failure.
    pub kind: TraversalKind,
    /// A stable, human-readable reason (also machine-greppable).
    ///
    /// **Peer-influenced.** A failed mTLS handshake's reason is derived from a rustls error, and a
    /// rustls error can carry text derived from the certificate the remote presented. It is stored
    /// raw (so a consumer can match on it) but NEUTRALIZED WHEN RENDERED — see the `Display` and
    /// `Debug` impls below.
    pub reason: String,
    /// Whether the failure was a timeout (vs an outright refusal / protocol error). Lets the
    /// strategy + observers distinguish "peer/gateway unreachable in time" from "actively rejected".
    pub timeout: bool,
}

/// Renders the `kind` then the `reason`, with the reason NEUTRALIZED (#1674).
///
/// Sanitizing lives here rather than at each construction site because that is what makes it hold:
/// `reason` is a `String` reachable from `MethodError::failed`, from struct literal syntax, and from
/// a consumer mutating the public field, and a guard applied at any one of those is a guard the next
/// caller skips. Applied in `Display` it is unrepresentable in a rendered error however the error
/// was built.
impl fmt::Display for MethodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?}: {}",
            self.kind,
            SafeText::from_untrusted(&self.reason)
        )
    }
}

/// Hand-written for the same reason as `Display`, and because `Debug` is the rendering that actually
/// reaches a log here: [`NatError::AllMethodsFailed`] formats its members with `{:?}`.
///
/// A DERIVED `Debug` happens to be safe today — it renders `reason` with `{:?}`, which escapes a
/// newline as a side effect of quoting. That is luck, not a guarantee: it does not neutralize bidi
/// overrides, it applies no length bound, and it would silently stop protecting anything the day the
/// aggregate switched to `{}`. So the neutralization is stated rather than inherited.
impl fmt::Debug for MethodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MethodError")
            .field("kind", &self.kind)
            .field("reason", &SafeText::from_untrusted(&self.reason))
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl std::error::Error for MethodError {}

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
