//! The production [`Dialer`] — performs the real rustls **mTLS** dial to a reachable address and
//! returns a [`PeerConnection`] whose remote `peer_id` has been verified.
//!
//! This is the single place transport detail lives: (happy-eyeballs) TCP connect → rustls client
//! handshake presenting THIS node's certificate (mutual TLS) → the [`PeerIdPinningVerifier`]
//! captures the peer's leaf cert, derives `peer_id = SHA-256(SPKI DER)`, and rejects the handshake
//! unless it matches the [`PeerTarget::peer_id`] the caller asked for. On success the caller gets an
//! authenticated, encrypted [`tokio_rustls::client::TlsStream`].
//!
//! ## IPv6-first, IPv4-fallback (happy eyeballs, RFC 8305-style)
//!
//! A [`MethodOutcome`] carries the peer's candidate addresses ordered **IPv6-first**. The dialer
//! races the TCP connect across the candidates with [`happy_eyeballs_connect`]: it starts the first
//! (IPv6) candidate, and after a short [`HappyEyeballsConfig::stagger`] starts the next candidate
//! too if the first has not yet completed — so a viable IPv6 candidate is preferred and IPv4 is used
//! only as a fallback when IPv6 fails/stalls. Each attempt is bounded by
//! [`HappyEyeballsConfig::per_attempt_timeout`]. Once a TCP connection wins, the single mTLS
//! handshake runs over it. The timeout + stagger are configurable so the racing logic is unit-tested
//! deterministically with no real sockets.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::LocalIdentity;
use crate::error::MethodError;
use crate::method::{MethodOutcome, TraversalKind};
use crate::mtls::{CapturedPeerId, PeerIdPinningVerifier};
use crate::peer::{PeerConnection, PeerTarget};
use crate::strategy::Dialer;

/// Tuning for the happy-eyeballs candidate race: how long each candidate connect may take, and how
/// long to wait before ALSO starting the next (lower-priority) candidate.
#[derive(Debug, Clone, Copy)]
pub struct HappyEyeballsConfig {
    /// Hard timeout for a single candidate's connect attempt.
    pub per_attempt_timeout: Duration,
    /// Delay before starting the next candidate while the current one is still in flight (RFC 8305
    /// "Connection Attempt Delay"). A small value (tens of ms) hedges a stalled IPv6 without racing
    /// so hard that IPv4 routinely beats a viable IPv6.
    pub stagger: Duration,
}

impl Default for HappyEyeballsConfig {
    fn default() -> Self {
        // RFC 8305 recommends a ~250ms connection-attempt delay; the per-attempt timeout is kept
        // generous (the strategy's per-method timeout is the real outer bound).
        HappyEyeballsConfig {
            per_attempt_timeout: Duration::from_secs(10),
            stagger: Duration::from_millis(250),
        }
    }
}

/// Race a connect across `candidates` IPv6-first, returning the most-preferred (IPv6) success.
///
/// The candidates are (defensively) ordered **IPv6-first** ([`crate::peer::sort_ipv6_first`]) and
/// each is assigned a PRIORITY index in that order (0 = most preferred). Attempts are launched with a
/// [`HappyEyeballsConfig::stagger`] head-start between them — the IPv6 candidate(s) start first, and a
/// lower-priority (IPv4) candidate is only *launched* once the preferred one has not completed within
/// the stagger (RFC 8305 hedging). Crucially, IPv6 is the PREFERENCE, not merely the first to start:
/// a lower-priority success is returned ONLY once every higher-priority attempt has concluded
/// (failed/timed out). So a viable IPv6 candidate wins even if a hedged IPv4 attempt happens to
/// connect sooner; IPv4 wins only when IPv6 genuinely fails. Each attempt is bounded by
/// [`HappyEyeballsConfig::per_attempt_timeout`]. If every candidate fails, returns the collected
/// per-candidate errors. An empty list is an error.
///
/// `connect_one` performs one candidate's connect (in production: a TCP connect; in tests: a canned
/// closure) — it is `async` and family-aware via the [`SocketAddr`] it is handed.
pub async fn happy_eyeballs_connect<T, E, F, Fut>(
    candidates: &[std::net::SocketAddr],
    config: HappyEyeballsConfig,
    connect_one: F,
) -> Result<T, String>
where
    E: std::fmt::Display,
    F: Fn(std::net::SocketAddr) -> Fut + Sync,
    Fut: Future<Output = Result<T, E>> + Send,
    T: Send,
{
    if candidates.is_empty() {
        return Err("no candidate addresses to dial".to_string());
    }

    // Defensive IPv6-first ordering: the priority index is the position in this ordered list, so
    // index 0 is the most-preferred (IPv6) candidate regardless of the caller's input order.
    let mut ordered: Vec<std::net::SocketAddr> = candidates.to_vec();
    crate::peer::sort_ipv6_first(&mut ordered);
    let total = ordered.len();

    // Each attempt yields (priority, addr, result); FuturesUnordered runs them concurrently. The
    // attempts are boxed to a common type because the `launch!` macro expands to several distinct
    // async blocks (one per call site) that must share one FuturesUnordered element type.
    type Attempt<'f, U> = std::pin::Pin<
        Box<dyn Future<Output = (usize, std::net::SocketAddr, Result<U, String>)> + Send + 'f>,
    >;
    let mut attempts: futures::stream::FuturesUnordered<Attempt<'_, T>> =
        futures::stream::FuturesUnordered::new();
    // The priority indices still live (in flight); a held fallback success can only be returned once
    // no live attempt is more preferred than it.
    let mut live: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    let mut errors: Vec<String> = Vec::with_capacity(total);
    let mut next_prio = 0usize;
    // The most-preferred success seen so far, held until no more-preferred candidate can beat it.
    let mut best_success: Option<(usize, T)> = None;

    // A macro-free launcher: push candidate `next_prio` as a bounded attempt.
    macro_rules! launch {
        () => {
            if next_prio < total {
                let prio = next_prio;
                let addr = ordered[prio];
                next_prio += 1;
                live.insert(prio);
                let fut = &connect_one;
                attempts.push(Box::pin(async move {
                    let res =
                        match tokio::time::timeout(config.per_attempt_timeout, fut(addr)).await {
                            Ok(Ok(conn)) => Ok(conn),
                            Ok(Err(e)) => Err(e.to_string()),
                            Err(_) => Err("connect timed out".to_string()),
                        };
                    (prio, addr, res)
                }));
            }
        };
    }

    // Prime the first (highest-priority = IPv6) candidate.
    launch!();

    loop {
        // Can we settle a held success now? Yes, once no still-live attempt AND no unlaunched
        // candidate is more preferred than it (so nothing better can still arrive).
        if let Some((p, _)) = &best_success {
            let more_preferred_live = live.iter().next().map(|lo| *lo < *p).unwrap_or(false);
            let more_preferred_unlaunched = next_prio <= *p; // an index <= p not yet launched
            if !more_preferred_live && !more_preferred_unlaunched {
                return Ok(best_success.take().unwrap().1);
            }
        }

        // Nothing left running and nothing left to launch → done.
        if live.is_empty() && next_prio >= total {
            break;
        }

        let stagger = tokio::time::sleep(config.stagger);
        tokio::select! {
            biased;
            finished = futures::StreamExt::next(&mut attempts), if !live.is_empty() => {
                match finished {
                    Some((prio, addr, Ok(conn))) => {
                        live.remove(&prio);
                        // Top-priority success (IPv6, index 0) wins outright.
                        if prio == 0 {
                            return Ok(conn);
                        }
                        // Otherwise hold the most-preferred success; keep racing more-preferred ones.
                        let keep = best_success.as_ref().map(|(bp, _)| prio < *bp).unwrap_or(true);
                        if keep {
                            best_success = Some((prio, conn));
                        }
                        let _ = addr;
                        // Ensure a more-preferred candidate isn't left untried.
                        launch!();
                    }
                    Some((prio, addr, Err(e))) => {
                        live.remove(&prio);
                        errors.push(format!("{addr}: {e}"));
                        // This attempt is out of the race — launch the next candidate.
                        launch!();
                    }
                    None => break,
                }
            }
            _ = stagger, if !live.is_empty() && next_prio < total => {
                // The preferred candidate is stalling — hedge by ALSO starting the next candidate.
                launch!();
            }
        }
    }

    // Nothing left in flight: return the most-preferred success we held, else the collected errors.
    if let Some((_, conn)) = best_success {
        return Ok(conn);
    }
    Err(format!("all candidates failed: [{}]", errors.join("; ")))
}

/// The production mTLS dialer. Holds this node's [`LocalIdentity`] (its client certificate for
/// mutual TLS) and builds a fresh pinning verifier per dial. The candidate race is tuned by
/// [`MtlsDialer::happy_eyeballs`].
#[derive(Debug, Clone)]
pub struct MtlsDialer {
    identity: LocalIdentity,
    happy_eyeballs: HappyEyeballsConfig,
}

impl MtlsDialer {
    /// Build a dialer that authenticates as `identity` (presents its cert as the mTLS client cert),
    /// using the default happy-eyeballs tuning.
    pub fn new(identity: LocalIdentity) -> Self {
        MtlsDialer {
            identity,
            happy_eyeballs: HappyEyeballsConfig::default(),
        }
    }

    /// Override the happy-eyeballs (IPv6-first candidate race) tuning.
    pub fn with_happy_eyeballs(mut self, config: HappyEyeballsConfig) -> Self {
        self.happy_eyeballs = config;
        self
    }

    /// Construct the rustls [`ClientConfig`] for one dial: present our client cert, and verify the
    /// server (peer) via the [`PeerIdPinningVerifier`] pinned to `expected` (the peer we want).
    fn client_config(
        &self,
        expected: crate::identity::PeerId,
        captured: CapturedPeerId,
    ) -> Result<ClientConfig, String> {
        let cert = CertificateDer::from(self.identity.cert_der.clone());
        // `key_der` is `Zeroizing<Vec<u8>>` (#179 finding 4); `.to_vec()` copies the bytes out into
        // a plain `Vec<u8>` for rustls (which takes ownership into its own `PrivateKeyDer`) — the
        // `Zeroizing` original still scrubs itself on drop as normal.
        let key = PrivateKeyDer::try_from(self.identity.key_der.to_vec())
            .map_err(|e| format!("invalid private key: {e}"))?;

        let verifier = Arc::new(PeerIdPinningVerifier::new(Some(expected), captured));
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

        // Race the TCP connect across the peer's candidate addresses IPv6-first (happy eyeballs);
        // IPv4 is only used when the IPv6 candidate(s) fail/stall. The winning stream carries its own
        // peer address so `remote_addr` reflects the family actually used.
        let (tcp, addr) = happy_eyeballs_connect(
            &outcome.dial_addrs,
            self.happy_eyeballs,
            |addr| async move {
                TcpStream::connect(addr)
                    .await
                    .map(|s| (s, addr))
                    .map_err(|e| format!("tcp connect {addr}: {e}"))
            },
        )
        .await
        .map_err(|e| MethodError::failed(kind, e))?;

        let captured = CapturedPeerId::default();
        let config = self
            .client_config(peer.peer_id, captured.clone())
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
