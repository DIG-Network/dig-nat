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
pub mod runtime;
pub mod strategy;
pub mod stun;
pub mod tunnel;
pub mod wire;

#[cfg(test)]
mod relayed_dial_tests;

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
pub use method::hole_punch::{HolePunchCoordinator, HolePunchMethod};
pub use method::relayed::{
    RelayedDialMethod, RelayedDialer, RelayedTransport, ReservationRelayedTransport,
};
pub use method::upnp::{IgdGateway, RealIgd, UpnpMethod};
pub use method::{TraversalKind, TraversalMethod};
pub use mux::{
    AvailabilityAnswer, AvailabilityItem, AvailabilityRequest, AvailabilityResponse, PeerSession,
    PeerStream, RangeFrame, RangeRequest,
};
pub use peer::{PeerConnection, PeerTarget};
pub use relay_descriptor::{verify_relay_descriptor, RelayDescriptor, RelayDescriptorError};
pub use runtime::{NatRuntime, NatRuntimeBuilder};

use dialer::MtlsDialer;
use method::direct::DirectMethod;
use method::natpmp::NatPmpMethod;
use method::pcp::PcpMethod;

/// Establish a mutually-authenticated connection to `peer` with an empty runtime — the convenience
/// entry point for a caller that holds NO live transport handles (a publicly-reachable node). Only
/// the **Direct** tier is composable without runtime handles; a NAT'd node that needs the full ladder
/// (UPnP/NAT-PMP/PCP/hole-punch/relayed) calls [`connect_with_runtime`] with a [`NatRuntime`] carrying
/// the gateway/port/relay handles.
///
/// `node` is this node's [`NodeCert`] — its CA-signed mTLS identity from [`dig-tls`](dig_tls),
/// presented as the client certificate; `config` selects which methods are enabled, the per-method
/// timeout, and the [`BindingPolicy`] applied to the peer's #1204 cert binding.
///
/// # Errors
/// - [`NatError::NoMethodsEnabled`] — no method could be composed (nothing enabled, or the enabled
///   tiers all lacked their runtime inputs — here, only Direct is available).
/// - [`NatError::AllMethodsFailed`] — every composed method failed (with per-method reasons).
///
/// This never panics and never hangs: every method + dial is bounded by
/// [`NatConfig::per_method_timeout`].
pub async fn connect(
    peer: &PeerTarget,
    node: &Arc<NodeCert>,
    config: &NatConfig,
) -> Result<PeerConnection, NatError> {
    connect_with_runtime(peer, node, config, &NatRuntime::default()).await
}

/// Establish a mutually-authenticated connection to `peer`, auto-composing the **FULL** NAT-traversal
/// ladder — direct → UPnP → NAT-PMP → PCP → hole-punch → relayed — trying each in rank order, first
/// success wins, relay last. The caller never chooses the method: it supplies the data [`NatConfig`]
/// and the live [`NatRuntime`] handles, and the strategy picks the first tier that establishes an
/// mTLS [`PeerConnection`] whose remote `peer_id` matches [`PeerTarget::peer_id`].
///
/// Each tier is composed ONLY when it is enabled in `config` AND its runtime inputs are present in
/// `runtime` (an absent tier is skipped — the composition is honest, never a silently-broken dial):
/// - **Direct** — always (no runtime input).
/// - **UPnP** — `runtime.local_port` (+ an optional injected IGD gateway; else the real one).
/// - **NAT-PMP** — `runtime.local_port` + `runtime.gateway_v4`.
/// - **PCP** — `runtime.local_port` + `runtime.gateway_v4` + `runtime.client_ip`.
/// - **Hole-punch** — `runtime.hole_punch` + `runtime.my_external_addr`.
/// - **Relayed** — `runtime.relayed` (carries mTLS over the relay tunnel — NOT a weaker connection).
///
/// Every tier — including the relayed one — runs the SAME dig-tls mTLS: the CA-chained [`NodeCert`],
/// the `peer_id` pin, and the #1204 BLS binding. IPv6 is preferred at every IP-dialing tier via
/// `dig-ip` (§5.2). The relayed tier tunnels the identical handshake through the relay, which forwards
/// only ciphertext it cannot read.
///
/// # Errors
/// Same as [`connect`]: [`NatError::NoMethodsEnabled`] if no tier could be composed, else
/// [`NatError::AllMethodsFailed`] with each composed tier's reason in attempt order.
pub async fn connect_with_runtime(
    peer: &PeerTarget,
    node: &Arc<NodeCert>,
    config: &NatConfig,
    runtime: &NatRuntime,
) -> Result<PeerConnection, NatError> {
    let methods = compose_ladder(config, runtime);
    if methods.is_empty() {
        return Err(NatError::NoMethodsEnabled);
    }
    let mut dialer = MtlsDialer::new(Arc::clone(node)).with_binding_policy(config.binding_policy);
    if let Some(relayed) = &runtime.relayed {
        dialer = dialer.with_relayed_dialer(Arc::clone(relayed));
    }
    strategy::connect_with_strategy(peer, methods, &dialer, config.per_method_timeout).await
}

/// Assemble the [`TraversalMethod`] trait objects for the full ladder from the enabled tiers in
/// `config` whose runtime inputs are present in `runtime`. The strategy orders them by
/// [`TraversalKind::rank`], so the order they are pushed here is irrelevant. A tier missing its
/// runtime inputs is silently omitted — `connect` only ever attempts a tier it can actually run.
fn compose_ladder(config: &NatConfig, runtime: &NatRuntime) -> Vec<Arc<dyn TraversalMethod>> {
    let mut methods: Vec<Arc<dyn TraversalMethod>> = Vec::new();

    // Direct — always composable (the peer's own candidate addresses).
    if config.is_enabled(TraversalKind::Direct) {
        methods.push(Arc::new(DirectMethod));
    }

    // UPnP — needs a local port to map; uses an injected IGD gateway or the real SSDP-discovered one.
    if config.is_enabled(TraversalKind::Upnp) {
        if let Some(port) = runtime.local_port {
            let gateway: Arc<dyn IgdGateway> = runtime
                .igd
                .clone()
                .unwrap_or_else(|| Arc::new(RealIgd::default()));
            methods.push(Arc::new(UpnpMethod::new(gateway, port)));
        }
    }

    // NAT-PMP — needs the local port + the IPv4 gateway.
    if config.is_enabled(TraversalKind::NatPmp) {
        if let (Some(port), Some(gw)) = (runtime.local_port, runtime.gateway_v4) {
            methods.push(Arc::new(NatPmpMethod::new(gw, port)));
        }
    }

    // PCP — needs the local port + the IPv4 gateway + this node's client IP.
    if config.is_enabled(TraversalKind::Pcp) {
        if let (Some(port), Some(gw), Some(client_ip)) =
            (runtime.local_port, runtime.gateway_v4, runtime.client_ip)
        {
            methods.push(Arc::new(PcpMethod::new(gw, port, client_ip)));
        }
    }

    // Hole-punch — needs a relay coordinator + this node's STUN-discovered reflexive address.
    if config.is_enabled(TraversalKind::HolePunch) {
        if let (Some(coordinator), Some(my_addr)) =
            (runtime.hole_punch.clone(), runtime.my_external_addr)
        {
            methods.push(Arc::new(HolePunchMethod::new(coordinator, my_addr)));
        }
    }

    // Relayed (TURN-last) — needs the relay data-plane; the dial carries mTLS over the relay tunnel.
    if config.is_enabled(TraversalKind::Relayed) {
        if let Some(relayed) = runtime.relayed.clone() {
            methods.push(Arc::new(RelayedDialMethod::new(relayed)));
        }
    }

    methods
}
