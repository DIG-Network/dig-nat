//! Connection configuration — the enabled methods, per-method timeout, relay/STUN endpoints, and the
//! cert-binding policy that shape a [`crate::connect`] call. Built with a fluent builder; the caller
//! never selects the traversal method (only which ones are *enabled*).
//!
//! The local mTLS identity is NOT here: it is a [`dig_tls::NodeCert`] the caller passes to
//! [`crate::connect`] directly (dig-tls owns the cert model — CA, leaf, peer_id, binding).

use std::time::Duration;

use crate::method::TraversalKind;
use dig_tls::BindingPolicy;

/// Which traversal methods are enabled + the per-method deadline, relay settings, and cert-binding
/// policy for a connect.
///
/// The DEFAULT enables every method in the canonical order with sane timeouts and the canonical
/// [`dig_constants::DIG_RELAY_URL`] relay. The caller tweaks via the builder but never picks *which*
/// method wins — the strategy does, first-success-wins, relay-last.
#[derive(Debug, Clone)]
pub struct NatConfig {
    /// The traversal techniques permitted, by kind. The strategy always tries them in
    /// [`TraversalKind::rank`] order regardless of the order here.
    pub enabled_methods: Vec<TraversalKind>,
    /// Per-method hard timeout — a method that does not complete in this window is abandoned and the
    /// strategy moves on (this is the guarantee that a hung method can never block `connect`).
    pub per_method_timeout: Duration,
    /// The relay WebSocket endpoint for the relay-coordinated + relayed methods. Defaults to the
    /// canonical relay; honour the `DIG_RELAY_URL` env override / `=off` opt-out via
    /// [`crate::relay::relay_url_from_env`] / [`crate::relay::relay_enabled`].
    pub relay_endpoint: String,
    /// A STUN server used to discover this node's reflexive address for candidate advertisement +
    /// hole-punch. `None` = derive from the relay host on the standard STUN port
    /// [`STUN_PORT`](crate::config::STUN_PORT) (the relay co-locates a STUN server, L7 spec §3):
    /// point a node at a private relay and its STUN follows.
    pub stun_server: Option<std::net::SocketAddr>,
    /// The #1204 BLS cert-binding verification stance applied to the PEER's certificate during the
    /// mTLS handshake. Defaults to [`BindingPolicy::Opportunistic`] (the rollout default: verify a
    /// binding when present, reject a present-but-invalid one, tolerate a legacy peer that has none).
    /// A node that requires payload sealing sets [`BindingPolicy::Required`] (fail-closed,
    /// anti-downgrade). Verified via `dig-tls`; the verified peer BLS pubkey lands on
    /// [`crate::PeerConnection::peer_bls_pub`].
    pub binding_policy: BindingPolicy,
    /// Fast-connect ([`crate::connect_fast`]) drain window: after a live relayed→direct promotion,
    /// how long to keep the swapped-out relayed transport alive for in-flight streams to finish
    /// before dropping it (releasing the per-peer relay tunnel). A short cap bounds the worst case
    /// (a stuck stream can't pin the tunnel forever); request-scoped streams finish well within it.
    pub fast_connect_grace: Duration,
}

/// The default [`NatConfig::fast_connect_grace`] post-promotion drain window.
pub const DEFAULT_FAST_CONNECT_GRACE: Duration = Duration::from_secs(5);

/// The standard STUN port (RFC 5389). The DIG relay serves STUN here, co-located with the relay host
/// (`relay.dig.net:3478`); a node derives its STUN host from `DIG_RELAY_URL` (L7 spec §3).
pub const STUN_PORT: u16 = 3478;

impl Default for NatConfig {
    fn default() -> Self {
        NatConfig {
            enabled_methods: vec![
                TraversalKind::Direct,
                TraversalKind::Upnp,
                TraversalKind::NatPmp,
                TraversalKind::Pcp,
                TraversalKind::HolePunch,
                TraversalKind::Relayed,
            ],
            per_method_timeout: Duration::from_secs(5),
            relay_endpoint: dig_constants::DIG_RELAY_URL.to_string(),
            stun_server: None,
            binding_policy: BindingPolicy::Opportunistic,
            fast_connect_grace: DEFAULT_FAST_CONNECT_GRACE,
        }
    }
}

impl NatConfig {
    /// Start from the default config.
    pub fn builder() -> NatConfigBuilder {
        NatConfigBuilder {
            cfg: NatConfig::default(),
        }
    }

    /// Whether `kind` is enabled in this config.
    pub fn is_enabled(&self, kind: TraversalKind) -> bool {
        self.enabled_methods.contains(&kind)
    }
}

/// Fluent builder for [`NatConfig`].
#[derive(Debug, Clone)]
pub struct NatConfigBuilder {
    cfg: NatConfig,
}

impl NatConfigBuilder {
    /// Restrict the enabled methods (they are still tried in canonical rank order).
    pub fn enabled_methods(mut self, methods: Vec<TraversalKind>) -> Self {
        self.cfg.enabled_methods = methods;
        self
    }

    /// Disable a single method (e.g. turn off the relay fallback for an air-gapped node).
    pub fn disable(mut self, kind: TraversalKind) -> Self {
        self.cfg.enabled_methods.retain(|k| *k != kind);
        self
    }

    /// Set the per-method timeout.
    pub fn per_method_timeout(mut self, timeout: Duration) -> Self {
        self.cfg.per_method_timeout = timeout;
        self
    }

    /// Override the relay endpoint (defaults to the canonical relay).
    pub fn relay_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.cfg.relay_endpoint = endpoint.into();
        self
    }

    /// Set the STUN server used for reflexive-address discovery.
    pub fn stun_server(mut self, addr: std::net::SocketAddr) -> Self {
        self.cfg.stun_server = Some(addr);
        self
    }

    /// Set the #1204 cert-binding verification stance for the peer's certificate (default
    /// [`BindingPolicy::Opportunistic`]). Use [`BindingPolicy::Required`] on a node that seals
    /// payloads to peers (fail-closed, anti-downgrade).
    pub fn binding_policy(mut self, policy: BindingPolicy) -> Self {
        self.cfg.binding_policy = policy;
        self
    }

    /// Set the fast-connect ([`crate::connect_fast`]) post-promotion drain window (default
    /// [`DEFAULT_FAST_CONNECT_GRACE`]). A test uses a tiny value for fast, deterministic teardown.
    pub fn fast_connect_grace(mut self, grace: Duration) -> Self {
        self.cfg.fast_connect_grace = grace;
        self
    }

    /// Finalize the config.
    pub fn build(self) -> NatConfig {
        self.cfg
    }
}
