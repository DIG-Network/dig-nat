//! The production [`Dialer`] — performs the real rustls **mTLS** dial to a reachable address and
//! returns a [`PeerConnection`] whose remote `peer_id` has been verified.
//!
//! This is the single place transport detail lives: (happy-eyeballs) TCP connect → rustls client
//! handshake presenting THIS node's [`NodeCert`] (mutual TLS). The rustls `ClientConfig` comes
//! ready-made from [`dig_tls::client_config_spki_pinned`]; dig-nat holds no verifier of its own. That
//! config authenticates the peer by SPKI-pinning — `peer_id = SHA-256(TLS SPKI DER)` pinned to the
//! peer the caller asked for + rustls proof-of-possession + the #1204 BLS-binding verification —
//! with NO DigNetwork-CA chain requirement, because live §5.2 peers still present self-signed leaves
//! (the #1378 CA-everywhere migration is deferred). dig-tls captures the peer's `peer_id` (and bound
//! BLS pubkey) during the handshake and rejects it unless the derived id matches the
//! [`PeerTarget::peer_id`] the caller asked for. On success the caller gets an authenticated,
//! encrypted [`tokio_rustls::client::TlsStream`].
//!
//! ## IPv6-first, IPv4-fallback — delegated to `dig-ip` (CLAUDE.md §5.2)
//!
//! The family-selection + happy-eyeballs racing that used to live here is now the `dig-ip` crate's
//! single ecosystem responsibility. [`MtlsDialer::dial`] aggregates a [`MethodOutcome`]'s candidate
//! addresses into a [`dig_ip::PeerCandidates`] and calls [`dig_ip::connect`], handing it the local
//! host's [`dig_ip::LocalStack`] and a closure that performs one candidate's raw TCP connect.
//! `dig-ip` then dials over the **local∩peer family intersection** (never a family the local host or
//! the peer lacks — its structural guarantee), IPv6-first with graceful IPv4 fallback. Once a TCP
//! connection wins, the single mTLS handshake runs over it — the identity/cert behaviour below is
//! unchanged; only the family selection + racing moved out. See `dig-ip`'s `SPEC.md`.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use dig_ip::{CandidateSource, DialConfig, LocalStack, PeerCandidates};
use dig_tls::{BindingPolicy, NodeCert};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::error::MethodError;
use crate::method::relayed::RelayedDialer;
use crate::method::{MethodOutcome, TraversalKind};
use crate::peer::{PeerConnection, PeerTarget};
use crate::strategy::Dialer;
use crate::tunnel::RelayTunnelStream;

/// Tuning for the happy-eyeballs candidate race: how long each candidate connect may take, and how
/// long to wait before ALSO starting the next (lower-priority) candidate. A thin dig-nat-facing view
/// of [`dig_ip::DialConfig`] (which the dial converts it into) so the public dialer API stays stable.
#[derive(Debug, Clone, Copy)]
pub struct HappyEyeballsConfig {
    /// Hard timeout for a single candidate's connect attempt.
    pub per_attempt_timeout: std::time::Duration,
    /// Delay before starting the next candidate while the current one is still in flight (RFC 8305
    /// "Connection Attempt Delay"). A small value (tens of ms) hedges a stalled IPv6 without racing
    /// so hard that IPv4 routinely beats a viable IPv6.
    pub stagger: std::time::Duration,
}

impl Default for HappyEyeballsConfig {
    fn default() -> Self {
        // RFC 8305 recommends a ~250ms connection-attempt delay; the per-attempt timeout is kept
        // generous (the strategy's per-method timeout is the real outer bound).
        HappyEyeballsConfig {
            per_attempt_timeout: std::time::Duration::from_secs(10),
            stagger: std::time::Duration::from_millis(250),
        }
    }
}

impl From<HappyEyeballsConfig> for DialConfig {
    fn from(cfg: HappyEyeballsConfig) -> DialConfig {
        DialConfig {
            per_attempt_timeout: cfg.per_attempt_timeout,
            attempt_delay: cfg.stagger,
        }
    }
}

/// Aggregate a traversal [`MethodOutcome`]'s dial addresses into a family-tagged
/// [`dig_ip::PeerCandidates`] — the input `dig_ip::connect` filters by the local∩peer intersection.
///
/// The candidate ordering + IPv6-first preference is `dig-ip`'s job, so the addresses are added in
/// the order the traversal produced them; `dig-ip` derives each family and orders IPv6-first. The
/// [`CandidateSource`] tag is provenance/observability only (it never influences the intersection
/// rule): a relay-coordinated or relayed endpoint is tagged [`CandidateSource::RelayIntroduction`],
/// every direct/port-mapping endpoint the peer's advertised [`CandidateSource::ListenAddr`].
pub fn candidates_from_outcome(outcome: &MethodOutcome) -> PeerCandidates {
    let source = match outcome.kind {
        TraversalKind::HolePunch | TraversalKind::Relayed => CandidateSource::RelayIntroduction,
        TraversalKind::Direct
        | TraversalKind::Upnp
        | TraversalKind::NatPmp
        | TraversalKind::Pcp => CandidateSource::ListenAddr,
    };
    let mut candidates = PeerCandidates::new();
    candidates.extend(outcome.dial_addrs.iter().copied(), source);
    candidates
}

/// The production mTLS dialer. Holds this node's [`NodeCert`] (its dig-tls identity, presented as the
/// mutual-TLS client cert) and builds a fresh [`dig_tls::client_config_spki_pinned`] per dial.
/// The candidate race is tuned by [`MtlsDialer::happy_eyeballs`], and the local stack it dials from by
/// [`MtlsDialer::local_stack`].
///
/// The [`NodeCert`] is shared behind an [`Arc`] (it is deliberately not `Clone` — its private key is
/// held in a scrubbing wrapper), so cloning the dialer per dial never copies the key material.
///
/// `Debug` is hand-written because the relay data-plane handle is a `dyn` trait object that carries no
/// `Debug` bound (its concrete type may hold live sockets); the derived `Clone` is fine (every field
/// is `Clone`, the `Arc`s share).
#[derive(Clone)]
pub struct MtlsDialer {
    node: Arc<NodeCert>,
    happy_eyeballs: HappyEyeballsConfig,
    /// The BLS cert-binding verification stance for the peer's cert (#1204). Defaults to
    /// [`BindingPolicy::Opportunistic`] — the rollout default: verify a binding when the peer
    /// presents one, tolerate a legacy peer that does not. A node that requires sealing sets
    /// [`BindingPolicy::Required`] via [`MtlsDialer::with_binding_policy`].
    binding_policy: BindingPolicy,
    /// The local host's address-family capability used to filter the dial (`dig-ip`'s G1 gate).
    /// `None` = probe the real host per dial via [`LocalStack::cached`]; `Some` pins a deterministic
    /// stack (used by tests to exercise the intersection matrix without a host dependency).
    local_stack: Option<LocalStack>,
    /// The relay data-plane used to open the byte tunnel for a [`TraversalKind::Relayed`] dial. `None`
    /// = no relayed transport wired, so a relayed outcome cannot be dialed (the strategy will only
    /// reach it when [`crate::connect`] composed the relayed tier, which requires this handle). The
    /// tunnel carries the SAME mTLS as a direct dial — a relayed connection is not weaker.
    relayed: Option<Arc<dyn RelayedDialer>>,
}

impl MtlsDialer {
    /// Build a dialer that authenticates as `node` (presents its dig-tls cert as the mTLS client
    /// cert), using the default happy-eyeballs tuning, the real host's detected address-family stack,
    /// and the default [`BindingPolicy::Opportunistic`] cert-binding stance.
    pub fn new(node: Arc<NodeCert>) -> Self {
        MtlsDialer {
            node,
            happy_eyeballs: HappyEyeballsConfig::default(),
            binding_policy: BindingPolicy::default(),
            local_stack: None,
            relayed: None,
        }
    }

    /// Override the happy-eyeballs (IPv6-first candidate race) tuning.
    pub fn with_happy_eyeballs(mut self, config: HappyEyeballsConfig) -> Self {
        self.happy_eyeballs = config;
        self
    }

    /// Set the BLS cert-binding verification stance (#1204) for peer certs this dialer verifies.
    pub fn with_binding_policy(mut self, policy: BindingPolicy) -> Self {
        self.binding_policy = policy;
        self
    }

    /// Pin the local address-family stack the dial filters against, instead of probing the real host.
    /// The dial NEVER attempts a family this stack lacks (`dig-ip`'s G1 guarantee) — this seam lets a
    /// test drive the intersection deterministically (`LocalStack::from_flags`).
    pub fn with_local_stack(mut self, stack: LocalStack) -> Self {
        self.local_stack = Some(stack);
        self
    }

    /// Wire the relay data-plane used to dial a [`TraversalKind::Relayed`] outcome (open the RLY-002
    /// byte tunnel the mTLS session runs over). [`crate::connect`] sets this from the runtime carrier
    /// whenever it composes the relayed tier.
    pub fn with_relayed_dialer(mut self, relayed: Arc<dyn RelayedDialer>) -> Self {
        self.relayed = Some(relayed);
        self
    }

    /// Run the mTLS handshake over an already-established byte `stream` (a raced TCP connection, or a
    /// relay byte tunnel), presenting THIS node's [`NodeCert`] and pinning the remote's `peer_id` to
    /// the one the caller asked for. Shared by every tier so a relayed/hole-punched connection is
    /// authenticated IDENTICALLY to a direct one — same SPKI-pinned `peer_id` pin, same rustls
    /// proof-of-possession, same #1204 BLS binding. `remote_addr` is recorded on the connection for
    /// observability.
    async fn handshake_over<S>(
        &self,
        peer: &PeerTarget,
        kind: TraversalKind,
        stream: S,
        remote_addr: SocketAddr,
    ) -> Result<PeerConnection, MethodError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        // The rustls client config — SPKI-pinned peer_id verification (to the peer we asked for) +
        // rustls proof-of-possession + #1204 binding verification, with NO DigNetwork-CA chain
        // requirement so live §5.2 self-signed peers are accepted — comes ready-made from dig-tls,
        // along with the handles that capture WHO answered during the handshake. The safe-usage
        // contract on `client_config_spki_pinned` is satisfied: the dialer ALWAYS pins
        // `Some(peer.peer_id)`, so a wrong-peer_id leaf is still rejected (authentication preserved).
        let client_tls =
            dig_tls::client_config_spki_pinned(&self.node, Some(peer.peer_id), self.binding_policy)
                .map_err(|e| MethodError::failed(kind, format!("client cert config: {e}")))?;
        let captured = client_tls.captured_peer_id;
        let captured_bls = client_tls.captured_bls;
        let connector = TlsConnector::from(client_tls.config);

        // The server name is irrelevant to identity here (we verify by peer_id via the pinning
        // verifier, not by hostname/CA), but rustls requires a syntactically valid SNI. A peer_id
        // hex (64 chars) is not a valid DNS label (>63), so we use a fixed, well-formed placeholder.
        let server_name = ServerName::try_from("peer.dig.invalid")
            .map_err(|e| MethodError::failed(kind, format!("server name: {e}")))?;

        let tls = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| classify_tls_error(kind, &e))?;

        // The pinning verifier already rejected a mismatch; this is the authenticated identity.
        let verified = captured
            .get()
            .ok_or_else(|| MethodError::failed(kind, "peer presented no certificate"))?;

        // Wrap the single mTLS byte stream in yamux so the caller can open many concurrent
        // (range-)streams over it — the streaming-first, multiplexed transport is uniform across
        // every traversal tier.
        let session = crate::mux::PeerSession::client(tls);

        Ok(PeerConnection {
            peer_id: verified,
            method: kind,
            remote_addr,
            peer_bls_pub: captured_bls.get(),
            session,
        })
    }

    /// Dial a [`TraversalKind::Relayed`] outcome: open the RLY-002 byte tunnel to the peer over the
    /// held relay reservation, then run the SAME mTLS handshake over it. Requires a relay data-plane
    /// wired via [`with_relayed_dialer`](Self::with_relayed_dialer). The relay forwards only the TLS
    /// records it cannot read — a relayed connection is not weaker than a direct one.
    async fn dial_relayed(
        &self,
        peer: &PeerTarget,
        outcome: &MethodOutcome,
    ) -> Result<PeerConnection, MethodError> {
        let kind = TraversalKind::Relayed;
        let relayed = self.relayed.as_ref().ok_or_else(|| {
            MethodError::failed(kind, "no relay data-plane wired for the relayed tier")
        })?;
        let tunnel = relayed
            .open_dial_tunnel(&peer.peer_id.to_hex(), &peer.network_id)
            .await
            .map_err(|e| MethodError::failed(kind, e))?;
        // The relay endpoint (observability) is the outcome's dial address; the byte path is the WS.
        let remote_addr = outcome.dial_addr().unwrap_or(relayed.relay_endpoint());
        let stream = RelayTunnelStream::new(tunnel);
        self.handshake_over(peer, kind, stream, remote_addr).await
    }
}

impl std::fmt::Debug for MtlsDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MtlsDialer")
            .field("happy_eyeballs", &self.happy_eyeballs)
            .field("binding_policy", &self.binding_policy)
            .field("local_stack", &self.local_stack)
            .field(
                "relayed",
                &self.relayed.as_ref().map(|_| "<relay data-plane>"),
            )
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Dialer for MtlsDialer {
    async fn dial(
        &self,
        peer: &PeerTarget,
        outcome: &MethodOutcome,
    ) -> Result<PeerConnection, MethodError> {
        let kind = outcome.kind;

        // The relayed tier is not an IP dial — it carries mTLS over a relay byte tunnel. Every other
        // tier (direct / mapping / hole-punch) yields dialable IP candidates and dials them directly.
        if kind == TraversalKind::Relayed {
            return self.dial_relayed(peer, outcome).await;
        }

        // Delegate family selection + racing to dig-ip: it dials only the local∩peer family
        // intersection (never a family the local host or the peer lacks), IPv6-first with graceful
        // IPv4 fallback. A disjoint pair fails immediately with `NoCommonFamily` — no doomed attempt
        // that can only time out. The winning stream carries its own peer address, so `remote_addr`
        // reflects the family actually used.
        let local = self.local_stack.unwrap_or_else(LocalStack::cached);
        let candidates = candidates_from_outcome(outcome);
        let winner = dig_ip::connect(
            &local,
            &candidates,
            self.happy_eyeballs.into(),
            |addr| async move {
                TcpStream::connect(addr)
                    .await
                    .map_err(|e| format!("tcp connect {addr}: {e}"))
            },
        )
        .await
        .map_err(|e| MethodError::failed(kind, e.to_string()))?;

        // The winning raced TCP stream carries mTLS identically to every other tier.
        self.handshake_over(peer, kind, winner.conn, winner.addr)
            .await
    }
}

/// Map a rustls handshake error to a [`MethodError`], surfacing a peer_id mismatch clearly (it
/// arrives as a general error from the verifier).
fn classify_tls_error(kind: TraversalKind, e: &std::io::Error) -> MethodError {
    let msg = e.to_string();
    MethodError::failed(kind, format!("mtls handshake: {msg}"))
}
