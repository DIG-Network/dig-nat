//! Fast-connect — start on the fastest usable transport, then live-promote to a better one.
//!
//! [`connect`](crate::connect) races the traversal ladder and returns ONE connection over the first
//! tier that lands. For a NAT'd peer that tier is often the relay (TURN) — usable immediately, but
//! the relay carries every byte. [`connect_fast`] instead returns the first-usable transport AND keeps
//! racing a better (direct) path in the background; when a direct path lands AND proves itself, it is
//! promoted SEAMLESSLY, with no interruption to in-flight work.
//!
//! ## Why the handoff is safe (the crux)
//!
//! [`yamux`](crate::mux) runs over ONE mTLS byte stream and is transport-bound — you cannot swap the
//! byte transport under a live `yamux::Connection`. So the handoff happens at the STREAM-ROUTING layer
//! ABOVE the session, never at the byte layer: **a live logical stream NEVER migrates; only NEW
//! streams route to the promoted transport, and old streams drain on the old one.** DIG's peer API is
//! already a factory of short-lived, request-scoped streams ([`open_range_stream`](FastPeerConnection::open_range_stream),
//! [`query_availability`](FastPeerConnection::query_availability) — a fresh yamux stream each, with no
//! cross-stream ordering contract), so route-new + drain-old is correct by construction: no loss, no
//! reorder, no duplication, and no read-quiesce/flush is needed because the byte path is never swapped.
//!
//! The swap itself is a single [`ArcSwap`] pointer store: [`open_stream`](FastPeerConnection::open_stream)
//! loads the CURRENT transport slot and opens its stream; promotion stores the new slot, so only
//! subsequent `open_stream` calls see it. The swapped-out relayed slot is held in a draining state
//! until its in-flight streams finish (or a short grace cap elapses), then dropped — which releases
//! ONLY the per-peer relay tunnel, never the node's persistent relay reservation.
//!
//! ## Promotion gate (conservative — SECURITY-CRITICAL)
//!
//! A direct path is promoted ONLY when ALL hold:
//! 1. the direct-tier mTLS handshake completed with the `peer_id` pin verified (the dialer guarantees
//!    this or errors);
//! 2. the direct connection's identity EQUALS the relayed one — same `peer_id` AND same #1204 BLS
//!    pubkey (the identity-equality invariant that makes swapping transports to "the same peer" safe);
//! 3. ONE successful application round-trip over the direct session (an empty-availability probe) —
//!    proving real bidirectional mux traffic, because a NAT mapping can complete TLS then blackhole.
//!
//! Never promote on handshake-completion alone. A failed gate REFUSES promotion and stays relayed.
//!
//! ## mTLS + NC-1
//!
//! The session does not survive the swap and need not: `peer_id = SHA-256(TLS SPKI DER)` is
//! transport-bound, and the direct path runs its OWN mTLS to the SAME `peer_id`. The identity-equality
//! gate (2) is the invariant that makes the swap safe. NC-1 payload sealing sits ABOVE dig-nat, keyed
//! to the peer's BLS pubkey (identical across transports), so it is unaffected by a transport swap.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use arc_swap::ArcSwap;
use futures::future::{select, Either};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{watch, Mutex, Notify};

use crate::dialer::MtlsDialer;
use crate::error::NatError;
use crate::method::{MethodOutcome, TraversalKind};
use crate::mux::{
    AvailabilityRequest, AvailabilityResponse, ClosedHandle, PeerSession, PeerStream, RangeRequest,
};
use crate::peer::{PeerConnection, PeerTarget};
use crate::strategy::{self, Dialer};
use crate::{NatConfig, NatRuntime, NodeCert, PeerId};

/// A fresh single-tier dial attempt, produced on demand by an [`Establisher`]. `'static` + `Send` so
/// it can be moved into the background promotion guard.
type DialFuture = Pin<Box<dyn Future<Output = Result<PeerConnection, NatError>> + Send>>;

/// A reusable factory that starts ONE fresh dial over a specific transport tier (direct ladder, or
/// relayed). Reusable so the promotion guard can RE-establish (the relayed reconnect / direct-death
/// fallback) without re-plumbing the runtime handles.
type Establisher = Arc<dyn Fn() -> DialFuture + Send + Sync>;

/// One transport under a [`FastPeerConnection`]: its multiplexed session plus the metadata the
/// promotion gate + drain accounting need. Slots are swapped whole via [`ArcSwap`]; an in-flight
/// stream holds an `Arc<TransportSlot>` so its session is never dropped from under it.
struct TransportSlot {
    /// The multiplexed mTLS session. A `tokio` mutex because [`PeerSession::open_stream`] is `&mut`
    /// async; the lock is held only for the brief open (a channel send + oneshot await), never for
    /// stream IO.
    session: Mutex<PeerSession>,
    /// Which traversal tier established this slot (observability + [`FastPeerConnection::current_method`]).
    method: TraversalKind,
    /// The remote address this slot's session runs over (the peer's endpoint, or the relay).
    remote_addr: SocketAddr,
    /// The peer's verified #1204 BLS pubkey on this slot — the identity-equality invariant compares
    /// the direct slot's against the relayed one's before promoting.
    peer_bls_pub: Option<[u8; 48]>,
    /// Observer of this slot's session closing (transport death) — the guard awaits it to fall back.
    closed: ClosedHandle,
    /// Live streams opened on THIS slot not yet dropped — drain accounting for a swapped-out slot.
    outstanding: AtomicUsize,
    /// Notified when a stream on this slot drops, so the drain can complete early (before the cap).
    drained: Notify,
}

impl TransportSlot {
    /// Wrap an established [`PeerConnection`] as a swappable transport slot.
    fn from_conn(conn: PeerConnection) -> Arc<TransportSlot> {
        let closed = conn.session.closed_handle();
        Arc::new(TransportSlot {
            session: Mutex::new(conn.session),
            method: conn.method,
            remote_addr: conn.remote_addr,
            peer_bls_pub: conn.peer_bls_pub,
            closed,
            outstanding: AtomicUsize::new(0),
            drained: Notify::new(),
        })
    }
}

/// A peer connection that starts on the fastest usable transport and LIVE-PROMOTES to a better one
/// (relayed → direct) transparently, with no interruption to in-flight streams.
///
/// The public API mirrors [`PeerConnection`] but is `&self` (interior mutability): the current
/// transport is swapped atomically underneath, so a caller keeps ONE handle across a promotion. Which
/// tier is currently active is observable via [`current_method`](Self::current_method) /
/// [`subscribe`](Self::subscribe) — observability only; the caller opens streams identically
/// regardless of the tier.
pub struct FastPeerConnection {
    /// The verified remote identity — stable across every transport swap (the invariant that makes a
    /// swap safe).
    peer_id: PeerId,
    /// The current transport, swapped atomically on promotion/fallback. `open_stream` loads this.
    active: Arc<ArcSwap<TransportSlot>>,
    /// The last-published active method, for [`subscribe`](Self::subscribe) notifications.
    events: watch::Sender<TraversalKind>,
    /// Owns the background promote/fallback task; aborts it on drop so no work outlives the handle.
    _guard: PromotionGuard,
}

/// A logical stream over a [`FastPeerConnection`]'s CURRENT transport. Holds an `Arc<TransportSlot>`
/// so the transport it was opened on is never dropped from under it (an in-flight stream always
/// completes on the transport it started on — the route-new/drain-old contract), and decrements the
/// slot's drain counter on drop so a post-promotion drain can finish as soon as its streams do.
pub struct FastPeerStream {
    inner: PeerStream,
    slot: Arc<TransportSlot>,
}

impl Drop for FastPeerStream {
    fn drop(&mut self) {
        // Reaching zero wakes a waiting drain immediately (before the grace cap).
        if self.slot.outstanding.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.slot.drained.notify_waiters();
        }
    }
}

impl AsyncRead for FastPeerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FastPeerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl FastPeerConnection {
    /// The verified remote identity — stable across every transport swap.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// The traversal tier currently carrying this connection (authoritative — read from the live
    /// active slot). Flips on a live promotion (relayed→direct) or a fallback (direct→relayed).
    pub fn current_method(&self) -> TraversalKind {
        self.active.load().method
    }

    /// The remote address the current transport runs over (the peer's endpoint, or the relay).
    pub fn remote_addr(&self) -> SocketAddr {
        self.active.load().remote_addr
    }

    /// Subscribe to active-transport changes (each promotion/fallback sends the new
    /// [`TraversalKind`]). Observability only.
    pub fn subscribe(&self) -> watch::Receiver<TraversalKind> {
        self.events.subscribe()
    }

    /// Open a new concurrent logical stream over the CURRENT transport (cheap — open as many as you
    /// need). The stream completes on whichever transport was active when it opened, even if a
    /// promotion swaps the active transport meanwhile.
    pub async fn open_stream(&self) -> std::io::Result<FastPeerStream> {
        let slot = self.active.load_full();
        let stream = {
            let mut session = slot.session.lock().await;
            session.open_stream().await?
        };
        slot.outstanding.fetch_add(1, Ordering::AcqRel);
        Ok(FastPeerStream {
            inner: stream,
            slot,
        })
    }

    /// Open a `dig.fetchRange` stream for `req` over the current transport (writes the range preamble,
    /// then the caller reads [`RangeFrame`](crate::mux::RangeFrame)s).
    pub async fn open_range_stream(&self, req: &RangeRequest) -> std::io::Result<FastPeerStream> {
        let mut stream = self.open_stream().await?;
        stream.write_all(&req.encode()).await?;
        stream.flush().await?;
        Ok(stream)
    }

    /// Availability pre-check (`dig.getAvailability`) over the current transport — a short-lived
    /// control round-trip on a fresh stream.
    pub async fn query_availability(
        &self,
        items: Vec<crate::mux::AvailabilityItem>,
    ) -> std::io::Result<AvailabilityResponse> {
        let mut stream = self.open_stream().await?;
        stream
            .write_all(&AvailabilityRequest { items }.encode())
            .await?;
        stream.flush().await?;
        AvailabilityResponse::decode(&mut stream).await
    }
}

impl std::fmt::Debug for FastPeerConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FastPeerConnection")
            .field("peer_id", &self.peer_id)
            .field("method", &self.current_method())
            .field("remote_addr", &self.remote_addr())
            .finish_non_exhaustive()
    }
}

/// Owns the background promote/fallback task and aborts it when the [`FastPeerConnection`] drops, so
/// no promotion work outlives the handle it serves.
struct PromotionGuard {
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for PromotionGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Establish a mutually-authenticated connection to `peer`, returning the FIRST usable transport and
/// LIVE-PROMOTING to a better one in the background (see the module docs).
///
/// It concurrently launches (a) a relayed dial over the held relay reservation (if `runtime` wired a
/// relay data-plane) and (b) the DIRECT traversal ladder race (Direct → UPnP → NAT-PMP → PCP →
/// hole-punch — the full ladder MINUS the relayed tier), and returns a [`FastPeerConnection`] as soon
/// as EITHER lands:
/// - a NAT'd peer whose relay lands first is returned relayed-active while the direct ladder keeps
///   racing; when it lands + passes the promotion gate, the connection is promoted to direct;
/// - a public peer whose direct dial wins outright is returned direct-active and the relay is never
///   used.
///
/// `connect`/`connect_with_runtime`/[`PeerConnection`] are unchanged; this is an additive alternate
/// entry point.
///
/// # Errors
/// [`NatError::AllMethodsFailed`] if BOTH the relayed and direct attempts fail (or
/// [`NatError::NoMethodsEnabled`] if neither tier could even be composed).
pub async fn connect_fast(
    peer: &PeerTarget,
    node: &Arc<NodeCert>,
    config: &NatConfig,
    runtime: &NatRuntime,
) -> Result<FastPeerConnection, NatError> {
    // The direct ladder = the full ladder MINUS the relayed tier, composed from the current runtime.
    let mut direct_config = config.clone();
    direct_config
        .enabled_methods
        .retain(|k| *k != TraversalKind::Relayed);
    let direct_methods = crate::compose_ladder(&direct_config, runtime);
    let direct_dialer =
        Arc::new(MtlsDialer::new(Arc::clone(node)).with_binding_policy(config.binding_policy));
    let direct: Establisher = {
        let peer = peer.clone();
        let timeout = config.per_method_timeout;
        Arc::new(move || {
            let peer = peer.clone();
            let dialer = Arc::clone(&direct_dialer);
            let methods = direct_methods.clone();
            Box::pin(async move {
                strategy::connect_with_strategy(&peer, methods, dialer.as_ref(), timeout).await
            })
        })
    };

    // The relayed tier, if a relay data-plane is wired (a NAT'd node with a held reservation).
    let relayed: Option<Establisher> = runtime.relayed.as_ref().map(|relayed_dialer| {
        let relayed_dialer = Arc::clone(relayed_dialer);
        let node = Arc::clone(node);
        let peer = peer.clone();
        let binding = config.binding_policy;
        let endpoint = relayed_dialer.relay_endpoint();
        let est: Establisher = Arc::new(move || {
            let dialer = MtlsDialer::new(Arc::clone(&node))
                .with_binding_policy(binding)
                .with_relayed_dialer(Arc::clone(&relayed_dialer));
            let peer = peer.clone();
            Box::pin(async move {
                let outcome = MethodOutcome::single(TraversalKind::Relayed, endpoint);
                dialer
                    .dial(&peer, &outcome)
                    .await
                    .map_err(|e| NatError::AllMethodsFailed(vec![e]))
            })
        });
        est
    });

    connect_fast_with(
        peer.peer_id,
        direct,
        relayed,
        config.fast_connect_grace,
        config.per_method_timeout,
    )
    .await
}

/// The transport-agnostic core: race the direct + relayed establishers, return the first-usable
/// [`FastPeerConnection`], and spawn the background promote/fallback guard. Split out so the promotion
/// state machine is unit-tested with fake establishers (no real network) — see the tests below.
async fn connect_fast_with(
    expected_peer_id: PeerId,
    direct: Establisher,
    relayed: Option<Establisher>,
    grace_cap: Duration,
    probe_timeout: Duration,
) -> Result<FastPeerConnection, NatError> {
    let direct_fut = direct();
    let Some(relayed) = relayed else {
        // No relay tier: the direct ladder is the only path. First-usable == direct.
        let conn = direct_fut.await?;
        return Ok(build(
            expected_peer_id,
            conn,
            GuardPlan::none(),
            grace_cap,
            probe_timeout,
        ));
    };
    let relayed_fut = relayed();

    match select(relayed_fut, direct_fut).await {
        // Relayed landed first.
        Either::Left((relayed_res, direct_fut)) => match relayed_res {
            Ok(relayed_conn) => {
                // Relayed-active; keep the in-flight direct attempt racing for promotion, and wire
                // the relayed establisher as the direct-death fallback / relay-reconnect path.
                let plan = GuardPlan {
                    promote_from: Some(direct_fut),
                    fallback: Some(relayed),
                };
                Ok(build(
                    expected_peer_id,
                    relayed_conn,
                    plan,
                    grace_cap,
                    probe_timeout,
                ))
            }
            // Relayed failed — fall back to whatever the direct ladder produces.
            Err(relayed_err) => match direct_fut.await {
                Ok(direct_conn) => Ok(build(
                    expected_peer_id,
                    direct_conn,
                    GuardPlan::fallback_only(Some(relayed)),
                    grace_cap,
                    probe_timeout,
                )),
                Err(direct_err) => Err(merge_errors(relayed_err, direct_err)),
            },
        },
        // Direct landed first.
        Either::Right((direct_res, relayed_fut)) => match direct_res {
            // Direct won outright — return direct-active; the relay is never used (cancel it). The
            // relayed establisher stays wired as the direct-death fallback.
            Ok(direct_conn) => {
                drop(relayed_fut);
                Ok(build(
                    expected_peer_id,
                    direct_conn,
                    GuardPlan::fallback_only(Some(relayed)),
                    grace_cap,
                    probe_timeout,
                ))
            }
            // Direct failed — await the relayed attempt.
            Err(direct_err) => match relayed_fut.await {
                Ok(relayed_conn) => {
                    // Relayed-active; retry a promotion once via the direct establisher.
                    let plan = GuardPlan {
                        promote_from: Some(direct()),
                        fallback: Some(relayed),
                    };
                    Ok(build(
                        expected_peer_id,
                        relayed_conn,
                        plan,
                        grace_cap,
                        probe_timeout,
                    ))
                }
                Err(relayed_err) => Err(merge_errors(relayed_err, direct_err)),
            },
        },
    }
}

/// What the background guard should do for a given initial connection.
struct GuardPlan {
    /// A pending direct attempt to await + (on success) promote the connection to. `None` when the
    /// initial connection is already direct.
    promote_from: Option<DialFuture>,
    /// A reusable establisher to re-dial when the active transport dies (direct→relayed fallback, or
    /// relayed reconnect). `None` when there is nothing to fall back to (a public peer with no relay).
    fallback: Option<Establisher>,
}

impl GuardPlan {
    fn none() -> Self {
        GuardPlan {
            promote_from: None,
            fallback: None,
        }
    }
    fn fallback_only(fallback: Option<Establisher>) -> Self {
        GuardPlan {
            promote_from: None,
            fallback,
        }
    }
}

/// Assemble a [`FastPeerConnection`] from its initial slot + spawn the background guard for `plan`.
fn build(
    peer_id: PeerId,
    initial: PeerConnection,
    plan: GuardPlan,
    grace_cap: Duration,
    probe_timeout: Duration,
) -> FastPeerConnection {
    let slot = TransportSlot::from_conn(initial);
    let (events, _rx) = watch::channel(slot.method);
    let active = Arc::new(ArcSwap::from(slot));
    let handle = tokio::spawn(run_guard(
        peer_id,
        Arc::clone(&active),
        events.clone(),
        plan,
        grace_cap,
        probe_timeout,
    ));
    FastPeerConnection {
        peer_id,
        active,
        events,
        _guard: PromotionGuard { handle },
    }
}

/// The background promote/fallback state machine (see the module docs). Runs until the guard is
/// aborted (the [`FastPeerConnection`] dropped) or no fallback remains after a transport death.
async fn run_guard(
    peer_id: PeerId,
    active: Arc<ArcSwap<TransportSlot>>,
    events: watch::Sender<TraversalKind>,
    plan: GuardPlan,
    grace_cap: Duration,
    probe_timeout: Duration,
) {
    // Phase 1 — promotion: if a direct attempt is pending, await it and (on a passed gate) promote
    // the relayed connection to it, draining the swapped-out relayed slot.
    if let Some(promote_from) = plan.promote_from {
        if let Ok(direct_conn) = promote_from.await {
            try_promote(
                peer_id,
                &active,
                &events,
                direct_conn,
                grace_cap,
                probe_timeout,
            )
            .await;
        }
        // A failed direct attempt or a refused gate simply stays on the current (relayed) transport.
    }

    // Phase 2 — fallback: while the active transport can be re-established, watch it for death and
    // re-dial on close. On a direct death this re-dials relayed; on a relayed death this reconnects
    // relayed. With no fallback (a public peer with no relay), the guard exits — a lost direct
    // connection then simply surfaces as stream errors to the caller.
    //
    // A flapping transport (dial-succeeds-then-instantly-dies) would otherwise drive an unbounded
    // re-dial busy-loop; a capped-exponential backoff paces RAPID successive deaths. A session that
    // was held STABLY (lived past [`FALLBACK_STABILITY`]) resets the backoff, so an ordinary lone
    // death still re-dials immediately (the single-re-dial-per-death contract is unchanged).
    let Some(fallback) = plan.fallback else {
        return;
    };
    let mut rapid_deaths: u32 = 0;
    loop {
        let closed = active.load().closed.clone();
        let established_at = tokio::time::Instant::now();
        closed.closed().await;

        // Pace only RAPID re-deaths; a stably-held session resets the counter.
        if established_at.elapsed() >= FALLBACK_STABILITY {
            rapid_deaths = 0;
        } else {
            rapid_deaths = rapid_deaths.saturating_add(1);
        }
        let backoff = fallback_backoff(rapid_deaths, FALLBACK_BACKOFF_BASE, FALLBACK_BACKOFF_CAP);
        if !backoff.is_zero() {
            tokio::time::sleep(backoff).await;
        }

        match fallback().await {
            Ok(conn) => {
                let slot = TransportSlot::from_conn(conn);
                let method = slot.method;
                active.store(slot);
                let _ = events.send(method);
            }
            // Re-establish failed — give up; the caller's next `open_stream` errors.
            Err(_) => return,
        }
    }
}

/// First delay for the fallback re-dial backoff (the shortest paced wait after a rapid death).
const FALLBACK_BACKOFF_BASE: Duration = Duration::from_millis(50);
/// Upper bound on the fallback re-dial backoff — no single wait exceeds this.
const FALLBACK_BACKOFF_CAP: Duration = Duration::from_secs(5);
/// A re-established session that lives at least this long is "stable" and resets the backoff, so an
/// ordinary lone transport death always re-dials immediately.
const FALLBACK_STABILITY: Duration = Duration::from_secs(10);

/// Capped-exponential fallback re-dial backoff (mirrors the relay reservation loop's
/// [`crate::relay::backoff_secs`]). `rapid_deaths == 0` → no wait (a lone death re-dials at once);
/// each additional rapid death doubles the wait, clamped to `cap`. Pure → unit-tested.
fn fallback_backoff(rapid_deaths: u32, base: Duration, cap: Duration) -> Duration {
    if rapid_deaths == 0 {
        return Duration::ZERO;
    }
    let base_ms = base.as_millis() as u64;
    let shifted = base_ms.checked_shl(rapid_deaths - 1).unwrap_or(u64::MAX);
    Duration::from_millis(shifted).clamp(base, cap)
}

/// Run the promotion gate over a landed direct connection and, iff it passes, swap the active
/// transport to it and drain the swapped-out relayed slot. A refused gate leaves the connection
/// relayed (the `direct_conn` is dropped).
async fn try_promote(
    peer_id: PeerId,
    active: &Arc<ArcSwap<TransportSlot>>,
    events: &watch::Sender<TraversalKind>,
    mut direct_conn: PeerConnection,
    grace_cap: Duration,
    probe_timeout: Duration,
) {
    let relayed_slot = active.load_full();

    // Gate (2) — identity equality: SAME peer_id AND SAME #1204 BLS pubkey as the relayed transport.
    // This is what makes swapping "to the same peer" safe (SECURITY-CRITICAL); a mismatch is refused.
    if direct_conn.peer_id != peer_id || direct_conn.peer_bls_pub != relayed_slot.peer_bls_pub {
        tracing::warn!(
            "fast-connect: direct path identity mismatch — promotion refused, staying relayed"
        );
        return;
    }

    // Gate (3) — one successful application round-trip (empty availability). Proves real bidirectional
    // mux traffic; a NAT mapping that completes TLS then blackholes fails here. Never promote on
    // handshake-completion alone. The probe is BOUNDED by `probe_timeout` (the per-method timeout): a
    // post-TLS blackhole (TLS completes, mux never answers) would hang the probe forever, so a timeout
    // is treated as a probe FAILURE and fails closed — no promotion, stay relayed.
    match tokio::time::timeout(probe_timeout, direct_conn.query_availability(vec![])).await {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => {
            tracing::warn!(
                "fast-connect: direct path failed the availability probe — staying relayed"
            );
            return;
        }
        Err(_) => {
            tracing::warn!(
                "fast-connect: direct path availability probe timed out — staying relayed"
            );
            return;
        }
    }

    // Gate passed — swap NEW streams onto the direct transport atomically. In-flight relayed streams
    // keep running on the relayed slot (they hold its Arc); no live stream migrates.
    let direct_slot = TransportSlot::from_conn(direct_conn);
    let method = direct_slot.method;
    active.store(direct_slot);
    let _ = events.send(method);
    tracing::info!(?method, "fast-connect: promoted to a direct transport");

    // Drain + drop the swapped-out relayed slot in the background: hold it until its in-flight streams
    // finish (or the grace cap elapses), then release it — dropping the relayed session closes ONLY
    // the per-peer relay tunnel (the persistent reservation is untouched).
    tokio::spawn(drain_then_drop(relayed_slot, grace_cap));
}

/// Await the slot's in-flight streams draining to zero, bounded by `grace_cap`, then drop this task's
/// reference. A still-live stream past the cap keeps the slot alive via its own `Arc` (no truncation);
/// the cap only bounds how long THIS task waits before releasing its own hold.
async fn drain_then_drop(slot: Arc<TransportSlot>, grace_cap: Duration) {
    let deadline = tokio::time::sleep(grace_cap);
    tokio::pin!(deadline);
    loop {
        if slot.outstanding.load(Ordering::Acquire) == 0 {
            break;
        }
        let drained = slot.drained.notified();
        if slot.outstanding.load(Ordering::Acquire) == 0 {
            break;
        }
        tokio::select! {
            _ = drained => {}
            _ = &mut deadline => break,
        }
    }
    drop(slot);
}

/// Combine the two tiers' failures into one [`NatError::AllMethodsFailed`] preserving each tier's
/// per-method reasons.
fn merge_errors(relayed: NatError, direct: NatError) -> NatError {
    let mut failures = Vec::new();
    for e in [relayed, direct] {
        if let NatError::AllMethodsFailed(mut fs) = e {
            failures.append(&mut fs);
        }
    }
    NatError::AllMethodsFailed(failures)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use sha2::{Digest, Sha256};
    use tokio::io::AsyncWriteExt;
    use tokio_rustls::TlsAcceptor;

    use crate::method::relayed::ReservationRelayedTransport;
    use crate::mux::{
        AvailabilityAnswer, AvailabilityItem, AvailabilityRequest, AvailabilityResponse,
    };
    use crate::relay::{loopback_reservation_pair, RelayStatus};
    use crate::tunnel::RelayTunnelStream;
    use crate::{BindingPolicy, MethodError};
    use dig_tls::bls::SecretKey;

    const NET: &str = "DIG_MAINNET";
    const RELAY_ENDPOINT: &str = "127.0.0.1:3478";

    fn test_bls_sk(label: &str) -> SecretKey {
        let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        SecretKey::from_seed(&seed)
    }
    fn test_node(label: &str) -> Arc<NodeCert> {
        Arc::new(NodeCert::generate_signed(&test_bls_sk(label)).expect("generate node cert"))
    }

    /// Spawn a serving node over an accepted mTLS byte stream: answers every inbound stream as an
    /// availability query (so both the empty-availability promotion probe AND a real query succeed),
    /// tagging `total_length` with `tag` so a test can tell WHICH transport served a stream. If
    /// `kill` is set, the server tears its session down when notified — simulating a transport dying
    /// (post-promotion direct death), so the client's [`ClosedHandle`] fires and the guard falls back.
    fn serve_availability<S>(acceptor: TlsAcceptor, stream: S, tag: u64, kill: Option<Arc<Notify>>)
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(stream).await else {
                return;
            };
            let mut session = PeerSession::server(tls);
            loop {
                let accepted = match &kill {
                    Some(kill) => tokio::select! {
                        s = session.accept_stream() => s,
                        _ = kill.notified() => return, // drop the session → client transport dies
                    },
                    None => session.accept_stream().await,
                };
                let Some(mut s) = accepted else { return };
                tokio::spawn(async move {
                    if let Ok(req) = AvailabilityRequest::decode(&mut s).await {
                        let resp = AvailabilityResponse {
                            items: req
                                .items
                                .iter()
                                .map(|_| AvailabilityAnswer {
                                    available: true,
                                    roots: None,
                                    total_length: Some(tag),
                                    chunk_count: Some(1),
                                    complete: Some(true),
                                })
                                .collect(),
                        };
                        let _ = s.write_all(&resp.encode()).await;
                        let _ = s.shutdown().await;
                    }
                });
            }
        });
    }

    /// Spawn a server that completes the mTLS handshake + yamux session but then BLACKHOLES: it never
    /// accepts an inbound stream, so a client's `query_availability` probe writes its request and then
    /// hangs forever awaiting a response. The session is held alive (not dropped), so the client's
    /// [`ClosedHandle`] does NOT fire — this models a NAT mapping that completes TLS then silently
    /// stops answering at the mux layer (the exact case gate 3 + its timeout must catch).
    fn serve_blackhole<S>(acceptor: TlsAcceptor, stream: S)
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(stream).await else {
                return;
            };
            let _session = PeerSession::server(tls);
            // Hold the session alive but never accept/answer a stream — blackhole at the mux layer.
            std::future::pending::<()>().await;
        });
    }

    /// A direct [`Establisher`] to `server` (identity matches — same `peer_id` + BLS as a relayed
    /// establisher to the same node) whose mTLS + yamux come up, but which BLACKHOLES the mux layer
    /// (never answers the availability probe). Used to prove gate 3 refuses a post-TLS blackhole and
    /// that the probe is bounded by a timeout rather than hanging forever.
    fn blackhole_direct_establisher(
        client: &Arc<NodeCert>,
        server: &Arc<NodeCert>,
        delay: Duration,
    ) -> Establisher {
        let node = Arc::clone(client);
        let server = Arc::clone(server);
        let server_id = server.peer_id();
        Arc::new(move || {
            let node = Arc::clone(&node);
            let server = Arc::clone(&server);
            Box::pin(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let (client_io, server_io) = tokio::io::duplex(64 * 1024);
                let server_tls = dig_tls::server_config(&server, BindingPolicy::Opportunistic)
                    .expect("server config")
                    .config;
                serve_blackhole(TlsAcceptor::from(server_tls), server_io);

                let client_cfg =
                    dig_tls::client_config(&node, Some(server_id), BindingPolicy::Opportunistic)
                        .expect("client config");
                let captured = client_cfg.captured_peer_id;
                let captured_bls = client_cfg.captured_bls;
                let connector = tokio_rustls::TlsConnector::from(client_cfg.config);
                let sni = rustls_pki_types::ServerName::try_from("peer.dig.invalid").unwrap();
                let tls = connector.connect(sni, client_io).await.map_err(|e| {
                    NatError::AllMethodsFailed(vec![MethodError::failed(
                        TraversalKind::Direct,
                        format!("mtls handshake: {e}"),
                    )])
                })?;
                let verified = captured.get().expect("peer presented a cert");
                Ok(PeerConnection {
                    peer_id: verified,
                    method: TraversalKind::Direct,
                    remote_addr: "203.0.113.9:4444".parse().unwrap(),
                    peer_bls_pub: captured_bls.get(),
                    session: PeerSession::client(tls),
                })
            })
        })
    }

    /// A direct [`Establisher`] to `server` whose `peer_id` MATCHES the expected peer but whose
    /// `peer_bls_pub` is OVERWRITTEN to a value that differs from the real (relayed) slot's BLS. This
    /// isolates the BLS-equality leg of gate 2 (existing test 6 differs in BOTH peer_id and BLS, so it
    /// cannot catch a dropped BLS clause).
    fn mismatched_bls_establisher(
        client: &Arc<NodeCert>,
        server: &Arc<NodeCert>,
        tag: u64,
        delay: Duration,
    ) -> Establisher {
        let inner = direct_establisher(client, server, tag, delay);
        Arc::new(move || {
            let inner = Arc::clone(&inner);
            Box::pin(async move {
                let mut conn = inner().await?;
                // Same peer_id as the relayed slot, but a deliberately different BLS pubkey.
                conn.peer_bls_pub = Some([0xAB; 48]);
                Ok(conn)
            })
        })
    }

    /// A relayed [`Establisher`] over a loopback relay reservation to a server serving with `tag`.
    /// Returns the client's reservation handle too (tests read its tunnel registry).
    fn relayed_establisher(
        client: &Arc<NodeCert>,
        server: &Arc<NodeCert>,
        tag: u64,
    ) -> (Establisher, Arc<RelayStatus>) {
        let client_hex = client.peer_id().to_hex();
        let server_hex = server.peer_id().to_hex();
        let (client_status, server_status) = loopback_reservation_pair(&client_hex, &server_hex);

        // Server side: accept the tunnel + serve availability.
        let server_tunnel = server_status
            .open_tunnel(&client_hex, NET)
            .expect("server opens relay tunnel");
        let server_tls = dig_tls::server_config(server, BindingPolicy::Opportunistic)
            .expect("server config")
            .config;
        serve_availability(
            TlsAcceptor::from(server_tls),
            RelayTunnelStream::new(server_tunnel),
            tag,
            None,
        );

        let server_id = server.peer_id();
        let node = Arc::clone(client);
        let transport = Arc::new(ReservationRelayedTransport::new(
            Arc::clone(&client_status),
            RELAY_ENDPOINT.parse().unwrap(),
        ));
        let est: Establisher = Arc::new(move || {
            let dialer = MtlsDialer::new(Arc::clone(&node))
                .with_binding_policy(BindingPolicy::Opportunistic)
                .with_relayed_dialer(Arc::clone(&transport) as Arc<_>);
            Box::pin(async move {
                let peer = PeerTarget::relay_only(server_id, NET);
                let outcome =
                    MethodOutcome::single(TraversalKind::Relayed, RELAY_ENDPOINT.parse().unwrap());
                dialer
                    .dial(&peer, &outcome)
                    .await
                    .map_err(|e| NatError::AllMethodsFailed(vec![e]))
            })
        });
        (est, client_status)
    }

    /// An [`Establisher`] over an in-memory duplex byte stream (mTLS + yamux, no network) reporting
    /// `method`, serving with `tag`. `delay` lets a test make one path land AFTER another so the
    /// promotion race is deterministic; `kill` (if set) lets a test tear the server down to simulate
    /// a transport death. Reusable — each call spins a fresh duplex + server (so it can serve as the
    /// fallback path re-dialed after a death).
    fn duplex_establisher(
        client: &Arc<NodeCert>,
        server: &Arc<NodeCert>,
        method: TraversalKind,
        tag: u64,
        delay: Duration,
        kill: Option<Arc<Notify>>,
    ) -> Establisher {
        let node = Arc::clone(client);
        let server = Arc::clone(server);
        let server_id = server.peer_id();
        Arc::new(move || {
            let node = Arc::clone(&node);
            let server = Arc::clone(&server);
            let kill = kill.clone();
            Box::pin(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let (client_io, server_io) = tokio::io::duplex(64 * 1024);
                // Server side: accept mTLS over the duplex + serve availability.
                let server_tls = dig_tls::server_config(&server, BindingPolicy::Opportunistic)
                    .expect("server config")
                    .config;
                serve_availability(TlsAcceptor::from(server_tls), server_io, tag, kill);

                // Client side: run the client mTLS handshake over the duplex, pinning server_id.
                let client_cfg =
                    dig_tls::client_config(&node, Some(server_id), BindingPolicy::Opportunistic)
                        .expect("client config");
                let captured = client_cfg.captured_peer_id;
                let captured_bls = client_cfg.captured_bls;
                let connector = tokio_rustls::TlsConnector::from(client_cfg.config);
                let sni = rustls_pki_types::ServerName::try_from("peer.dig.invalid").unwrap();
                let tls = connector.connect(sni, client_io).await.map_err(|e| {
                    NatError::AllMethodsFailed(vec![MethodError::failed(
                        method,
                        format!("mtls handshake: {e}"),
                    )])
                })?;
                let verified = captured.get().expect("peer presented a cert");
                Ok(PeerConnection {
                    peer_id: verified,
                    method,
                    remote_addr: "203.0.113.9:4444".parse().unwrap(),
                    peer_bls_pub: captured_bls.get(),
                    session: PeerSession::client(tls),
                })
            })
        })
    }

    /// A direct duplex [`Establisher`] (the common case): reports [`TraversalKind::Direct`].
    fn direct_establisher(
        client: &Arc<NodeCert>,
        server: &Arc<NodeCert>,
        tag: u64,
        delay: Duration,
    ) -> Establisher {
        duplex_establisher(client, server, TraversalKind::Direct, tag, delay, None)
    }

    /// (1) First-usable latency: a slow direct fake means `connect_fast` returns BEFORE direct
    /// completes, relayed-active.
    #[tokio::test]
    async fn returns_first_usable_relayed_before_slow_direct() {
        let client = test_node("fc/1/client");
        let server = test_node("fc/1/server");
        let (relayed, _status) = relayed_establisher(&client, &server, 11);
        let direct = direct_establisher(&client, &server, 22, Duration::from_secs(30));

        let conn = tokio::time::timeout(
            Duration::from_secs(5),
            connect_fast_with(
                server.peer_id(),
                direct,
                Some(relayed),
                Duration::from_millis(200),
                Duration::from_secs(5),
            ),
        )
        .await
        .expect("connect_fast returns before the slow direct completes")
        .expect("relayed lands first");

        assert_eq!(conn.current_method(), TraversalKind::Relayed);
        assert_eq!(conn.peer_id(), server.peer_id());
        assert_eq!(conn.remote_addr(), RELAY_ENDPOINT.parse().unwrap());
        assert!(format!("{conn:?}").contains("FastPeerConnection"));
        // Served over the relayed transport (tag 11).
        let resp = conn.query_availability(vec![avail_item()]).await.unwrap();
        assert_eq!(resp.items[0].total_length, Some(11));
        // A range stream also opens over the current transport (exercises open_range_stream).
        let _range = conn
            .open_range_stream(&RangeRequest::resource(
                "aa".repeat(32),
                "cc".repeat(32),
                0,
                8,
            ))
            .await
            .unwrap();
    }

    /// The public [`connect_fast`] entry, direct-only (no relay wired) with NO methods enabled, fails
    /// cleanly with [`NatError::NoMethodsEnabled`] — exercising `connect_fast` + `compose_ladder` +
    /// the no-relay branch without any network.
    #[tokio::test]
    async fn connect_fast_direct_only_with_no_methods_errors() {
        let client = test_node("fc/pub/client");
        let peer = PeerTarget::relay_only(test_node("fc/pub/server").peer_id(), NET);
        let config = NatConfig::builder().enabled_methods(vec![]).build();
        let runtime = NatRuntime::default(); // no relay data-plane
        let err = connect_fast(&peer, &client, &config, &runtime)
            .await
            .unwrap_err();
        assert!(matches!(err, NatError::NoMethodsEnabled));
    }

    /// (2) Seamless promotion + zero loss: hold a relayed stream mid-transfer, let the slow direct
    /// land + pass the empty-availability probe, assert the method flips to Direct, a NEW stream is
    /// served by the direct fake, and the PRE-promotion relayed stream still completes over relayed.
    #[tokio::test]
    async fn promotes_to_direct_without_losing_inflight_relayed_stream() {
        let client = test_node("fc/2/client");
        let server = test_node("fc/2/server");
        let (relayed, _status) = relayed_establisher(&client, &server, 11);
        let direct = direct_establisher(&client, &server, 22, Duration::from_millis(150));

        let conn = connect_fast_with(
            server.peer_id(),
            direct,
            Some(relayed),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .expect("relayed lands first");
        assert_eq!(conn.current_method(), TraversalKind::Relayed);

        // Open a relayed stream and write the request BEFORE promotion, but DON'T read the response
        // yet — keep the stream open across the promotion boundary.
        let mut pre = conn.open_stream().await.unwrap();
        pre.write_all(
            &AvailabilityRequest {
                items: vec![avail_item()],
            }
            .encode(),
        )
        .await
        .unwrap();
        pre.flush().await.unwrap();

        // Wait for the promotion to Direct.
        let mut rx = conn.subscribe();
        tokio::time::timeout(Duration::from_secs(5), async {
            while *rx.borrow_and_update() != TraversalKind::Direct {
                rx.changed().await.unwrap();
            }
        })
        .await
        .expect("promoted to Direct");
        assert_eq!(conn.current_method(), TraversalKind::Direct);

        // The PRE-promotion stream still completes over the RELAYED transport (tag 11) — no loss,
        // no migration: an in-flight stream finishes on the transport it started on.
        let pre_resp = AvailabilityResponse::decode(&mut pre).await.unwrap();
        assert_eq!(
            pre_resp.items[0].total_length,
            Some(11),
            "in-flight stream stayed relayed"
        );

        // A NEW stream is now served by the DIRECT fake (tag 22).
        let post = conn.query_availability(vec![avail_item()]).await.unwrap();
        assert_eq!(post.items[0].total_length, Some(22), "new stream is direct");
    }

    /// (3) Teardown: after promotion + drain, the peer is gone from the relay reservation's tunnel
    /// registry, while the reservation itself stays Connected (only the per-peer tunnel is released).
    #[tokio::test]
    async fn drains_and_releases_relay_tunnel_after_promotion() {
        let client = test_node("fc/3/client");
        let server = test_node("fc/3/server");
        let (relayed, status) = relayed_establisher(&client, &server, 11);
        let direct = direct_establisher(&client, &server, 22, Duration::from_millis(100));
        let server_hex = server.peer_id().to_hex();

        let conn = connect_fast_with(
            server.peer_id(),
            direct,
            Some(relayed),
            Duration::from_millis(100),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        // Await promotion, then let the (short) drain elapse.
        let mut rx = conn.subscribe();
        tokio::time::timeout(Duration::from_secs(5), async {
            while *rx.borrow_and_update() != TraversalKind::Direct {
                rx.changed().await.unwrap();
            }
        })
        .await
        .expect("promoted");
        // Give the background drain task time to release the tunnel (grace cap = 100ms).
        wait_until(Duration::from_secs(3), || {
            !status.open_tunnel_exists(&server_hex)
        })
        .await;

        assert!(
            !status.open_tunnel_exists(&server_hex),
            "per-peer relay tunnel released after promotion+drain"
        );
        assert!(
            status.is_connected(),
            "the relay reservation stays Connected"
        );
    }

    /// (4) Direct never lands: `connect_fast` stays relayed, usable, with the reservation intact.
    #[tokio::test]
    async fn stays_relayed_when_direct_never_lands() {
        let client = test_node("fc/4/client");
        let server = test_node("fc/4/server");
        let (relayed, status) = relayed_establisher(&client, &server, 11);
        // A direct establisher that always fails.
        let direct: Establisher = Arc::new(|| {
            Box::pin(async {
                Err(NatError::AllMethodsFailed(vec![MethodError::failed(
                    TraversalKind::Direct,
                    "no direct path",
                )]))
            })
        });

        let conn = connect_fast_with(
            server.peer_id(),
            direct,
            Some(relayed),
            Duration::from_millis(200),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        // Give the guard a moment; it must NOT promote.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(conn.current_method(), TraversalKind::Relayed);
        let resp = conn.query_availability(vec![avail_item()]).await.unwrap();
        assert_eq!(resp.items[0].total_length, Some(11));
        assert!(status.is_connected());
    }

    /// (6) Identity-mismatch guard: a direct fake returning a DIFFERENT peer's cert/BLS is REFUSED —
    /// the connection stays relayed. (SECURITY-CRITICAL: the identity-equality invariant.)
    #[tokio::test]
    async fn refuses_promotion_on_identity_mismatch() {
        let client = test_node("fc/6/client");
        let server = test_node("fc/6/server");
        let impostor = test_node("fc/6/impostor");
        let (relayed, _status) = relayed_establisher(&client, &server, 11);
        // The direct fake pins + serves the IMPOSTOR identity (a different peer_id + BLS).
        let direct = direct_establisher(&client, &impostor, 22, Duration::from_millis(100));

        let conn = connect_fast_with(
            server.peer_id(),
            direct,
            Some(relayed),
            Duration::from_millis(200),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        // The direct path lands but its identity != the relayed peer's → promotion refused.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            conn.current_method(),
            TraversalKind::Relayed,
            "promotion refused on identity mismatch"
        );
        let resp = conn.query_availability(vec![avail_item()]).await.unwrap();
        assert_eq!(resp.items[0].total_length, Some(11), "still relayed");
    }

    /// (5) Post-promotion direct death → fallback: after promoting to direct, killing the direct
    /// transport makes the guard fall back — the method flips back to Relayed and a fresh
    /// `open_stream` succeeds over the re-dialed transport. (Uses duplex establishers for BOTH roles
    /// so the reusable fallback can be re-dialed; the relayed-role establisher reports Relayed.)
    #[tokio::test]
    async fn falls_back_to_relayed_when_promoted_direct_dies() {
        let client = test_node("fc/5/client");
        let server = test_node("fc/5/server");
        // Relayed-role establisher (reusable — a fresh duplex server per call), reports Relayed/tag 11.
        let relayed = duplex_establisher(
            &client,
            &server,
            TraversalKind::Relayed,
            11,
            Duration::ZERO,
            None,
        );
        // Direct-role establisher (tag 22) that lands after a delay and can be KILLED.
        let kill = Arc::new(Notify::new());
        let direct = duplex_establisher(
            &client,
            &server,
            TraversalKind::Direct,
            22,
            Duration::from_millis(120),
            Some(Arc::clone(&kill)),
        );

        let conn = connect_fast_with(
            server.peer_id(),
            direct,
            Some(relayed),
            Duration::from_millis(100),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        // Wait for the promotion to Direct.
        let mut rx = conn.subscribe();
        tokio::time::timeout(Duration::from_secs(5), async {
            while *rx.borrow_and_update() != TraversalKind::Direct {
                rx.changed().await.unwrap();
            }
        })
        .await
        .expect("promoted to Direct");
        let post = conn.query_availability(vec![avail_item()]).await.unwrap();
        assert_eq!(post.items[0].total_length, Some(22), "served over direct");

        // Kill the direct transport → the guard must fall back to Relayed.
        kill.notify_waiters();
        tokio::time::timeout(Duration::from_secs(5), async {
            while *rx.borrow_and_update() != TraversalKind::Relayed {
                rx.changed().await.unwrap();
            }
        })
        .await
        .expect("fell back to Relayed after direct death");
        assert_eq!(conn.current_method(), TraversalKind::Relayed);

        // A fresh stream now succeeds over the re-dialed relayed transport (tag 11).
        let after = conn.query_availability(vec![avail_item()]).await.unwrap();
        assert_eq!(after.items[0].total_length, Some(11), "re-dialed relayed");
    }

    /// (7) Gate-3 REFUSES a post-TLS blackhole, BOUNDED by the probe timeout. A direct fake whose
    /// mTLS + identity match the relayed peer but which then blackholes the mux layer must NOT be
    /// promoted — the empty-availability probe hangs, the `probe_timeout` fires, and the connection
    /// stays relayed (fail-closed). SECURITY-CRITICAL (gate 3).
    ///
    /// Red-verify: deleting the gate-3 probe block in `try_promote` (the
    /// `tokio::time::timeout(probe_timeout, direct_conn.query_availability(vec![]))` match) makes this
    /// test FAIL — with no probe the blackhole peer promotes to Direct.
    #[tokio::test]
    async fn refuses_promotion_to_a_post_tls_blackhole() {
        let client = test_node("fc/7/client");
        let server = test_node("fc/7/server");
        let (relayed, _status) = relayed_establisher(&client, &server, 11);
        // Direct fake: SAME identity (server node) but blackholes the mux after TLS.
        let direct = blackhole_direct_establisher(&client, &server, Duration::from_millis(100));

        let conn = connect_fast_with(
            server.peer_id(),
            direct,
            Some(relayed),
            Duration::from_millis(200), // grace
            Duration::from_millis(300), // probe_timeout — bounds the blackhole probe
        )
        .await
        .unwrap();
        assert_eq!(conn.current_method(), TraversalKind::Relayed);

        // Allow the direct fake to land + the (bounded) probe to time out and be refused.
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(
            conn.current_method(),
            TraversalKind::Relayed,
            "post-TLS blackhole refused — probe timed out, stays relayed"
        );
        let resp = conn.query_availability(vec![avail_item()]).await.unwrap();
        assert_eq!(resp.items[0].total_length, Some(11), "still relayed");
    }

    /// (8) Gate-2 BLS leg REFUSES same-peer_id / different-BLS. A direct fake whose `peer_id` matches
    /// the relayed peer but whose BLS pubkey differs must be refused. Isolates the BLS clause (test 6
    /// differs in BOTH peer_id and BLS, so it cannot catch a dropped BLS clause). SECURITY-CRITICAL.
    ///
    /// Red-verify: removing `|| direct_conn.peer_bls_pub != relayed_slot.peer_bls_pub` from gate 2
    /// makes this test FAIL — peer_id alone matches, so the different-BLS peer would promote to Direct.
    #[tokio::test]
    async fn refuses_promotion_on_bls_mismatch_same_peer_id() {
        let client = test_node("fc/8/client");
        let server = test_node("fc/8/server");
        let (relayed, _status) = relayed_establisher(&client, &server, 11);
        // Direct fake: peer_id == server (matches expected), but BLS pubkey overwritten to differ.
        let direct = mismatched_bls_establisher(&client, &server, 22, Duration::from_millis(100));

        let conn = connect_fast_with(
            server.peer_id(),
            direct,
            Some(relayed),
            Duration::from_millis(200),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        // The direct path lands with a matching peer_id but a mismatched BLS → gate 2 refuses.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            conn.current_method(),
            TraversalKind::Relayed,
            "promotion refused on BLS mismatch despite matching peer_id"
        );
        let resp = conn.query_availability(vec![avail_item()]).await.unwrap();
        assert_eq!(resp.items[0].total_length, Some(11), "still relayed");
    }

    /// (9) An in-flight relayed stream SURVIVES a short grace cap. With a sub-millisecond
    /// `fast_connect_grace`, the post-promotion drain task releases its own hold as soon as the cap
    /// elapses — but a stream held across the promotion boundary keeps the relayed slot alive via its
    /// OWN `Arc<TransportSlot>`, so it still completes (no truncation on cap).
    ///
    /// Red-verify: a hypothetical drain that TRUNCATED the slot on cap (e.g. forcibly closed the
    /// relayed session when `deadline` fires instead of only dropping its own reference) would make the
    /// held `pre` stream's `decode` fail — this assertion (the held stream still yields tag 11) guards
    /// against that regression.
    #[tokio::test]
    async fn inflight_relayed_stream_survives_short_grace_cap() {
        let client = test_node("fc/9/client");
        let server = test_node("fc/9/server");
        let (relayed, _status) = relayed_establisher(&client, &server, 11);
        let direct = direct_establisher(&client, &server, 22, Duration::from_millis(150));

        let conn = connect_fast_with(
            server.peer_id(),
            direct,
            Some(relayed),
            Duration::from_millis(1), // tiny grace — the drain cap fires almost immediately
            Duration::from_secs(5),
        )
        .await
        .expect("relayed lands first");
        assert_eq!(conn.current_method(), TraversalKind::Relayed);

        // Open a relayed stream + write the request BEFORE promotion; hold it open across the boundary.
        let mut pre = conn.open_stream().await.unwrap();
        pre.write_all(
            &AvailabilityRequest {
                items: vec![avail_item()],
            }
            .encode(),
        )
        .await
        .unwrap();
        pre.flush().await.unwrap();

        // Wait for promotion to Direct (the drain task then fires its ~1ms cap immediately).
        let mut rx = conn.subscribe();
        tokio::time::timeout(Duration::from_secs(5), async {
            while *rx.borrow_and_update() != TraversalKind::Direct {
                rx.changed().await.unwrap();
            }
        })
        .await
        .expect("promoted to Direct");
        // Let the grace cap elapse + the drain task run to completion.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // The held stream STILL completes over the relayed transport (tag 11) — its Arc kept the slot
        // alive past the grace cap; the cap only bounded the drain task's own hold, not the stream.
        let pre_resp = AvailabilityResponse::decode(&mut pre).await.unwrap();
        assert_eq!(
            pre_resp.items[0].total_length,
            Some(11),
            "in-flight relayed stream survived the short grace cap"
        );
    }

    #[test]
    fn fallback_backoff_is_zero_for_a_lone_death_then_capped_exponential() {
        let base = Duration::from_millis(50);
        let cap = Duration::from_secs(5);
        // A lone death (counter 0) re-dials immediately.
        assert_eq!(fallback_backoff(0, base, cap), Duration::ZERO);
        // Rapid re-deaths back off exponentially from the base.
        assert_eq!(fallback_backoff(1, base, cap), Duration::from_millis(50));
        assert_eq!(fallback_backoff(2, base, cap), Duration::from_millis(100));
        assert_eq!(fallback_backoff(3, base, cap), Duration::from_millis(200));
        // Clamped to the cap and never overflows for a large death count.
        assert_eq!(fallback_backoff(20, base, cap), cap);
        assert_eq!(fallback_backoff(u32::MAX, base, cap), cap);
    }

    fn avail_item() -> AvailabilityItem {
        AvailabilityItem {
            store_id: "bb".repeat(32),
            root: None,
            retrieval_key: None,
        }
    }

    /// Poll `cond` until true or `budget` elapses (a small helper for background-task settling).
    async fn wait_until(budget: Duration, mut cond: impl FnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + budget;
        while tokio::time::Instant::now() < deadline {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
