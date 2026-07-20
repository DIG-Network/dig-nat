//! # dig-nat — abstract NAT traversal for DIG Node peer connections
//!
//! One API, [`connect`], establishes a **mutually-authenticated (mTLS)** connection to a peer using
//! the best available NAT-traversal method, transparently. **The caller never chooses the method** —
//! they describe the peer once and get back a verified [`PeerConnection`]; which technique got there
//! is reported for observability but is not something the caller handles.
//!
//! ## Traversal order (first success wins, relay last)
//!
//! Internally the [`strategy`] attempts, in this order:
//! 1. **Direct** — peer publicly reachable / already port-forwarded ([`method::direct`])
//! 2. **UPnP/IGD** port mapping ([`method::upnp`])
//! 3. **NAT-PMP** (RFC 6886, [`method::natpmp`])
//! 4. **PCP** (RFC 6887, [`method::pcp`])
//! 5. **Relay-coordinated hole-punch** (RLY-007, [`method::hole_punch`])
//! 6. **Relayed transport** via `relay.dig.net` — the LAST resort ([`relay`])
//!
//! [`stun`] (RFC 5389) discovers this node's reflexive address for candidate advertisement +
//! hole-punch coordination.
//!
//! ## Streaming-first + multiplexed transport
//!
//! Whatever tier establishes the connection, the result is uniform: a [`PeerConnection`] wrapping a
//! single mTLS byte stream in [`yamux`](mux) multiplexing. The caller opens **many cheap concurrent
//! logical streams** ([`PeerConnection::open_stream`]) with no head-of-line blocking, and
//! **byte-range streams** ([`PeerConnection::open_range_stream`]) scoped to `[offset, len)` of a
//! resource — so a downloader fetches DIFFERENT ranges from DIFFERENT peers in parallel and
//! reassembles. The API is streaming (read bytes as they arrive), never buffer-the-whole-response.
//!
//! ## Identity + mTLS — delegated to `dig-tls`
//!
//! Every peer connection is mutual TLS, and the entire certificate model is owned by the canonical
//! [`dig-tls`](dig_tls) crate (L00): the shipped public DigNetwork CA, the per-peer CA-signed
//! [`NodeCert`], `peer_id = SHA-256(TLS SPKI DER)`, the #1204 BLS-G1 cert binding, and the ready
//! rustls mutual-auth configs. dig-nat presents this node's [`NodeCert`] and uses
//! [`dig_tls::client_config`] to pin the remote's `peer_id` to the [`peer::PeerTarget::peer_id`] the
//! caller asked for — so the transport is self-authenticating. dig-nat holds NO cert/binding/peer_id
//! code of its own (it was extracted to dig-tls in 0.6.0); the names below are re-exports for
//! convenience.
//!
//! ## Graceful fallback + relay resilience
//!
//! Each method is bounded by a per-method timeout; if ALL fail, [`connect`] returns a clear
//! [`NatError::AllMethodsFailed`] (never panics, never hangs). The [`relay`] client — used both as
//! the last-resort transport and as a node's persistent reachability channel — establishes and
//! maintains its session with keepalive + capped-exponential-backoff reconnect, tolerates the relay
//! being down (retries in the background, never crashes the node), logs once per state change, and
//! honours the `DIG_RELAY_URL=off` opt-out. See [`relay::RelayStatus`].
//!
//! ## Example
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use dig_nat::{connect, NatConfig, NodeCert, PeerTarget, PeerId};
//! # async fn run(node: Arc<NodeCert>, peer_id: PeerId, addr: std::net::SocketAddr) -> Result<(), dig_nat::NatError> {
//! let peer = PeerTarget::with_addr(peer_id, addr, "DIG_MAINNET");
//! let conn = connect(&peer, &node, &NatConfig::default()).await?;
//! println!("connected to {} via {:?}", conn.peer_id, conn.method);
//! # Ok(()) }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod dialer;
pub mod error;
pub mod method;
pub mod mux;
pub mod peer;
pub mod relay;
pub mod relay_descriptor;
pub mod strategy;
pub mod stun;
pub mod wire;

use std::sync::Arc;

// --- Certificate / mTLS / identity model — re-exported from the canonical `dig-tls` crate (L00).
// dig-nat CONSUMES dig-tls for ALL of these (it holds no copy of its own), so a single source of
// truth means the DIG cert shape can never byte-drift between crates. ---
pub use dig_tls::binding::{verify_binding_from_leaf_cert, BindingOutcome};
pub use dig_tls::verify::{CapturedBlsPub, CapturedPeerId};
pub use dig_tls::{
    peer_id_from_leaf_cert_der, peer_id_from_tls_spki_der, BindingPolicy, NodeCert, PeerId,
};

pub use config::{NatConfig, NatConfigBuilder};
pub use error::{MethodError, NatError};
pub use method::{TraversalKind, TraversalMethod};
pub use mux::{
    AvailabilityAnswer, AvailabilityItem, AvailabilityRequest, AvailabilityResponse, PeerSession,
    PeerStream, RangeFrame, RangeRequest,
};
pub use peer::{PeerConnection, PeerTarget};
pub use relay_descriptor::{verify_relay_descriptor, RelayDescriptor, RelayDescriptorError};

use dialer::MtlsDialer;
use method::direct::DirectMethod;

/// Establish a mutually-authenticated connection to `peer`, choosing the traversal method
/// transparently (first success wins; relay is the last resort).
///
/// `node` is this node's [`NodeCert`] — its CA-signed mTLS identity from [`dig-tls`](dig_tls),
/// presented as the client certificate; `config` selects which methods are enabled, the per-method
/// timeout, the relay/STUN endpoints, and the [`BindingPolicy`] applied to the peer's #1204 cert
/// binding. On success the returned [`PeerConnection`] carries the verified remote `peer_id`, the
/// [`TraversalKind`] that established it, the peer's bound BLS pubkey (when present), and the
/// authenticated stream.
///
/// # Errors
/// - [`NatError::NoMethodsEnabled`] — the config enabled no methods.
/// - [`NatError::AllMethodsFailed`] — every enabled method failed (with per-method reasons).
/// - [`NatError::InvalidConfig`] — the relay/STUN config could not be used.
///
/// This function never panics and never hangs: every method (and its dial) is bounded by
/// [`NatConfig::per_method_timeout`].
pub async fn connect(
    peer: &PeerTarget,
    node: &Arc<NodeCert>,
    config: &NatConfig,
) -> Result<PeerConnection, NatError> {
    let methods = build_enabled_methods(config);
    if methods.is_empty() {
        return Err(NatError::NoMethodsEnabled);
    }
    let dialer = MtlsDialer::new(Arc::clone(node)).with_binding_policy(config.binding_policy);
    strategy::connect_with_strategy(peer, methods, &dialer, config.per_method_timeout).await
}

/// Assemble the enabled [`TraversalMethod`] trait objects for a config.
///
/// NOTE: the UPnP/NAT-PMP/PCP/hole-punch methods need runtime inputs the caller has not yet supplied
/// through the current minimal config surface (gateway address, this node's local port + reflexive
/// address, a live relay coordinator). Until those are wired through the builder, `connect` composes
/// the methods it can construct from the config alone — currently the always-available **Direct**
/// method. The other methods are fully implemented + tested and are composed explicitly by callers
/// (e.g. `dig-node`) that hold that runtime context, via [`strategy::connect_with_strategy`]. This
/// keeps `connect` honest (it never claims a method it cannot actually run) while the richer
/// auto-composition lands with the discovery inputs.
fn build_enabled_methods(config: &NatConfig) -> Vec<Arc<dyn TraversalMethod>> {
    let mut methods: Vec<Arc<dyn TraversalMethod>> = Vec::new();
    let direct = DirectMethod;
    if config.is_enabled(direct.kind()) {
        methods.push(Arc::new(direct));
    }
    methods
}
