//! Connection configuration — the local identity, relay endpoint, enabled methods, and timeouts
//! that shape a [`crate::connect`] call. Built with a fluent builder; the caller never selects the
//! traversal method (only which ones are *enabled*).

use std::time::Duration;

use zeroize::Zeroizing;

use crate::identity::PeerId;
use crate::method::TraversalKind;

/// The local node's mTLS identity: its certificate + private key (both DER) and the derived
/// [`PeerId`] the remote will verify.
///
/// The certificate is self-signed and its public key IS the identity (see [`crate::mtls`]). Callers
/// typically load a persisted `ChiaCertificate`-style pair; [`LocalIdentity::from_der`] derives the
/// `peer_id` from the cert's SPKI so it always matches what a remote computes.
#[derive(Clone)]
pub struct LocalIdentity {
    /// This node's leaf certificate, DER-encoded.
    pub cert_der: Vec<u8>,
    /// The matching private key, DER-encoded (PKCS#8).
    ///
    /// #179 finding 4: wrapped in [`Zeroizing`] (rather than a plain `Vec<u8>`) so every clone
    /// (`LocalIdentity` is cloned per dial, see `dialer.rs`) and every drop scrubs the private-key
    /// bytes from memory instead of leaving them in freed heap. Derefs transparently to `&[u8]` for
    /// existing call sites (e.g. building a `rustls::pki_types::PrivateKeyDer`).
    pub key_der: Zeroizing<Vec<u8>>,
    /// This node's own `peer_id` = SHA-256(cert SPKI DER).
    pub peer_id: PeerId,
}

impl LocalIdentity {
    /// Build a local identity from a DER cert + PKCS#8 key, deriving `peer_id` from the cert SPKI.
    /// Returns `None` if the certificate cannot be parsed.
    pub fn from_der(cert_der: Vec<u8>, key_der: Vec<u8>) -> Option<Self> {
        let peer_id = crate::identity::peer_id_from_leaf_cert_der(&cert_der)?;
        Some(LocalIdentity {
            cert_der,
            key_der: Zeroizing::new(key_der),
            peer_id,
        })
    }
}

impl std::fmt::Debug for LocalIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalIdentity")
            .field("peer_id", &self.peer_id)
            .field("cert_der", &format!("<{} bytes>", self.cert_der.len()))
            .field("key_der", &"<redacted>")
            .finish()
    }
}

/// Which traversal methods are enabled + the per-method deadline and relay settings for a connect.
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
}

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

    /// Finalize the config.
    pub fn build(self) -> NatConfig {
        self.cfg
    }
}
