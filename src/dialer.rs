//! The production [`Dialer`] — performs the real rustls **mTLS** dial to a reachable address and
//! returns a [`PeerConnection`] whose remote `peer_id` has been verified.
//!
//! This is the single place transport detail lives: (happy-eyeballs) TCP connect → rustls client
//! handshake presenting THIS node's certificate (mutual TLS) → the [`PeerIdPinningVerifier`]
//! captures the peer's leaf cert, derives `peer_id = SHA-256(SPKI DER)`, and rejects the handshake
//! unless it matches the [`PeerTarget::peer_id`] the caller asked for. On success the caller gets an
//! authenticated, encrypted [`tokio_rustls::client::TlsStream`].
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

use std::sync::Arc;

use async_trait::async_trait;
use dig_ip::{CandidateSource, DialConfig, LocalStack, PeerCandidates};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::cert_binding::BindingPolicy;
use crate::config::LocalIdentity;
use crate::error::MethodError;
use crate::method::{MethodOutcome, TraversalKind};
use crate::mtls::{CapturedBlsPub, CapturedPeerId, PeerIdPinningVerifier};
use crate::peer::{PeerConnection, PeerTarget};
use crate::strategy::Dialer;

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

/// The production mTLS dialer. Holds this node's [`LocalIdentity`] (its client certificate for
/// mutual TLS) and builds a fresh pinning verifier per dial. The candidate race is tuned by
/// [`MtlsDialer::happy_eyeballs`], and the local stack it dials from by [`MtlsDialer::local_stack`].
#[derive(Debug, Clone)]
pub struct MtlsDialer {
    identity: LocalIdentity,
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
}

impl MtlsDialer {
    /// Build a dialer that authenticates as `identity` (presents its cert as the mTLS client cert),
    /// using the default happy-eyeballs tuning, the real host's detected address-family stack, and
    /// the default [`BindingPolicy::Opportunistic`] cert-binding stance.
    pub fn new(identity: LocalIdentity) -> Self {
        MtlsDialer {
            identity,
            happy_eyeballs: HappyEyeballsConfig::default(),
            binding_policy: BindingPolicy::default(),
            local_stack: None,
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

    /// Construct the rustls [`ClientConfig`] for one dial: present our client cert, and verify the
    /// server (peer) via the [`PeerIdPinningVerifier`] pinned to `expected` (the peer we want).
    fn client_config(
        &self,
        expected: crate::identity::PeerId,
        captured: CapturedPeerId,
        captured_bls: CapturedBlsPub,
    ) -> Result<ClientConfig, String> {
        let cert = CertificateDer::from(self.identity.cert_der.clone());
        // `key_der` is `Zeroizing<Vec<u8>>` (#179 finding 4); `.to_vec()` copies the bytes out into
        // a plain `Vec<u8>` for rustls (which takes ownership into its own `PrivateKeyDer`) — the
        // `Zeroizing` original still scrubs itself on drop as normal.
        let key = PrivateKeyDer::try_from(self.identity.key_der.to_vec())
            .map_err(|e| format!("invalid private key: {e}"))?;

        let verifier = Arc::new(
            PeerIdPinningVerifier::new(Some(expected), captured)
                .with_binding(self.binding_policy, captured_bls),
        );
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(vec![cert], key)
            .map_err(|e| format!("client cert config: {e}"))
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
        let tcp = winner.conn;
        let addr = winner.addr;

        let captured = CapturedPeerId::default();
        let captured_bls = CapturedBlsPub::default();
        let config = self
            .client_config(peer.peer_id, captured.clone(), captured_bls.clone())
            .map_err(|e| MethodError::failed(kind, e))?;
        let connector = TlsConnector::from(Arc::new(config));

        // The server name is irrelevant to identity here (we verify by peer_id via the pinning
        // verifier, not by hostname/CA), but rustls requires a syntactically valid SNI. A peer_id
        // hex (64 chars) is not a valid DNS label (>63), so we use a fixed, well-formed placeholder.
        let server_name = ServerName::try_from("peer.dig.invalid")
            .map_err(|e| MethodError::failed(kind, format!("server name: {e}")))?;

        let tls = connector
            .connect(server_name, tcp)
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
            remote_addr: addr,
            peer_bls_pub: captured_bls.get(),
            session,
        })
    }
}

/// Map a rustls handshake error to a [`MethodError`], surfacing a peer_id mismatch clearly (it
/// arrives as a general error from the verifier).
fn classify_tls_error(kind: TraversalKind, e: &std::io::Error) -> MethodError {
    let msg = e.to_string();
    MethodError::failed(kind, format!("mtls handshake: {msg}"))
}
