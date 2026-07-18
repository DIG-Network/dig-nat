//! Relay client — the LAST-RESORT transport + the node's persistent reachability channel.
//!
//! Relocated + generalized from `dig-node`'s `relay.rs`. Two responsibilities:
//!
//! 1. **Persistent reservation** ([`run_relay_connection`]) — a DIG Node behind NAT can't accept
//!    inbound dials, so it holds a CONSTANT registered connection with a publicly-reachable relay
//!    (default [`dig_constants::DIG_RELAY_URL`], override `DIG_RELAY_URL`, opt out with
//!    `DIG_RELAY_URL=off`). This is the reachability channel other peers reach it through and the
//!    rendezvous for relay-coordinated hole-punch.
//! 2. **Relayed transport** — when every NAT-traversal method fails, peer traffic is tunnelled
//!    THROUGH the relay (RLY-002 `relay_message`). This is the last resort in the traversal order.
//!
//! **Graceful-fallback guarantees (baked in):** the reservation loop NEVER blocks startup, NEVER
//! panics/exits, and NEVER hot-loops error-spam — failures log ONCE per state change (a transition
//! into `Disconnected`), and every retry sleeps a bounded, capped-exponential backoff. If the relay
//! is unreachable the node keeps serving indefinitely; the task just keeps retrying in the
//! background. State is published through [`RelayStatus`] (a cheap atomic snapshot) as one of four
//! [`RelayState`]s and surfaced verbatim to a `control.relayStatus`-style RPC / `/health`.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::wire::{RelayMessage, RelayPeerInfo};

/// Default network id a node registers under (matches dig-gossip `DEFAULT_INTRODUCER_NETWORK_ID`
/// and dig-node's `DEFAULT_NETWORK_ID`).
pub const DEFAULT_NETWORK_ID: &str = "DIG_MAINNET";

/// Relay protocol version the node advertises in `Register` (RLY-001).
pub const RELAY_PROTOCOL_VERSION: u32 = 1;

/// Base reconnect delay (dig-gossip `RelayConfig::reconnect_delay_secs` = 5).
const BASE_BACKOFF_SECS: u64 = 5;
/// Cap on the exponential backoff so a long outage doesn't push the retry interval to hours.
const MAX_BACKOFF_SECS: u64 = 300;
/// Keepalive ping period (RLY-006; dig-gossip `PING_INTERVAL_SECS` = 30).
const PING_INTERVAL_SECS: u64 = 30;
/// How often the held reservation re-pulls the relay peer list (RLY-005 `GetPeers`) over the SAME
/// persistent socket, so a peer that registers AFTER this node — or one missed on the first pull —
/// is still discovered without ever reopening the connection (the connect-leg fix).
const DISCOVERY_INTERVAL_SECS: u64 = 60;

/// Hard cap on the peers retained in the discovered set ([`RelayStatus::known_peers`]).
///
/// SECURITY: the relay is an UNTRUSTED intermediary. A hostile/compromised relay can stream an
/// unbounded flood of `PeerConnected` frames — or a single oversized `Peers` frame — with distinct
/// fabricated `peer_id`s, so an uncapped set is a memory-exhaustion DoS. 1024 is far more than any
/// honest relay reports for one network's live reservations (the set is folded into a peer pool that
/// itself selects a small working subset), yet small enough that the worst case is bounded, cheap
/// memory. Beyond the cap, further distinct peers are DROPPED rather than grown.
pub const MAX_KNOWN_PEERS: usize = 1024;

/// Hard cap on the byte length of a single RLY-002 relayed-transport payload (both directions).
///
/// SECURITY / backpressure: the relay is UNTRUSTED and a peer reached over relayed transport is the
/// last-resort TURN path, so an oversized frame is refused rather than buffered — an outbound `send`
/// larger than this errors, and an inbound frame larger than this is dropped. 1 MiB comfortably
/// holds a sealed gossip message (NC-1 ciphertext) while bounding the worst-case per-frame memory.
pub const MAX_RELAY_PAYLOAD: usize = 1 << 20;

/// Bounded inbound capacity for one open [`RelayTunnel`]. A full channel applies backpressure — the
/// reservation loop `try_send`s inbound relayed bytes and DROPS the frame when the consumer is not
/// keeping up, so a hostile relay flooding one tunnel cannot exhaust memory (matches the
/// [`MAX_KNOWN_PEERS`] bounded-set philosophy). The RLY-002 `seq` lets the consumer detect the gap.
const RELAY_TUNNEL_INBOUND_CAP: usize = 256;

/// Compute the next reconnect backoff: capped exponential in the number of consecutive failures.
/// `failures == 0` → base; doubles each failure up to [`MAX_BACKOFF_SECS`]. Pure → unit-tested.
pub fn backoff_secs(consecutive_failures: u32) -> u64 {
    backoff_secs_with(consecutive_failures, BASE_BACKOFF_SECS, MAX_BACKOFF_SECS)
}

/// Capped-exponential backoff with an explicit base + cap. Always returns a value in `[base, cap]`
/// — never zero — so a failing connect can never busy-loop.
fn backoff_secs_with(consecutive_failures: u32, base: u64, cap: u64) -> u64 {
    let shifted = base.checked_shl(consecutive_failures).unwrap_or(cap);
    shifted.clamp(base, cap)
}

/// Backoff schedule for the reconnect loop — production defaults, or fast values for tests.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    /// First-retry delay (seconds).
    pub base_secs: u64,
    /// Upper bound on the delay (seconds).
    pub cap_secs: u64,
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff {
            base_secs: BASE_BACKOFF_SECS,
            cap_secs: MAX_BACKOFF_SECS,
        }
    }
}

/// The four observable states of the relay reservation, surfaced verbatim (lowercase) as the
/// `state` field of a `control.relayStatus`-style RPC.
///
/// - `Disabled` — reservation OFF (`DIG_RELAY_URL=off`); no task runs, no attempts made.
/// - `Connecting` — actively dialing/registering.
/// - `Connected` — a reservation is held (`RegisterAck{success:true}` arrived); reachable to peers.
/// - `Disconnected` — not connected; backing off + will retry. The graceful-fallback resting state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayState {
    /// Reservation OFF (`DIG_RELAY_URL=off`); no task runs, no attempts made.
    Disabled,
    /// Actively dialing/registering (initial attempt or a reconnect in flight).
    Connecting,
    /// A reservation is held (`RegisterAck{success:true}` arrived); reachable to NAT'd peers.
    Connected,
    /// Not connected; backing off + will retry. The graceful-fallback resting state.
    Disconnected,
}

impl RelayState {
    /// The stable lowercase wire string for the RPC `state` field.
    pub fn as_str(self) -> &'static str {
        match self {
            RelayState::Disabled => "disabled",
            RelayState::Connecting => "connecting",
            RelayState::Connected => "connected",
            RelayState::Disconnected => "disconnected",
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            RelayState::Disabled => 0,
            RelayState::Connecting => 1,
            RelayState::Connected => 2,
            RelayState::Disconnected => 3,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            0 => RelayState::Disabled,
            1 => RelayState::Connecting,
            2 => RelayState::Connected,
            _ => RelayState::Disconnected,
        }
    }
}

/// The peers discovered over the live reservation socket, in insertion order with O(1) dedup +
/// membership by `peer_id`, bounded to [`MAX_KNOWN_PEERS`].
///
/// `order` preserves discovery order so [`RelayStatus::known_peers`] returns a stable sequence;
/// `ids` mirrors `order`'s `peer_id`s so dedup and removal are O(1) instead of a linear scan (the
/// old `iter().any(...)` was O(n²) over a flood). The two are kept in lockstep — every mutation
/// touches both.
#[derive(Debug, Default)]
struct DiscoveredPeers {
    order: Vec<RelayPeerInfo>,
    ids: HashSet<String>,
}

impl DiscoveredPeers {
    /// Insert `peer` unless already present or the set is full. Returns nothing — a full set simply
    /// drops the newcomer (the untrusted-relay flood defense).
    fn insert(&mut self, peer: RelayPeerInfo) {
        if self.order.len() >= MAX_KNOWN_PEERS {
            return;
        }
        if self.ids.insert(peer.peer_id.clone()) {
            self.order.push(peer);
        }
    }

    /// Remove the peer with this `peer_id`, if present.
    fn remove(&mut self, peer_id: &str) {
        if self.ids.remove(peer_id) {
            self.order.retain(|p| p.peer_id != peer_id);
        }
    }

    /// Replace the whole set from a `Peers` frame, deduped + truncated to the cap.
    fn replace(&mut self, peers: Vec<RelayPeerInfo>) {
        self.order.clear();
        self.ids.clear();
        for peer in peers {
            self.insert(peer);
        }
    }

    fn clear(&mut self) {
        self.order.clear();
        self.ids.clear();
    }
}

/// Live relay-connection status, shared (via `Arc`) between the connection task and an RPC handler.
/// Cheap atomic reads. State setters do STATE-CHANGE-ONLY logging so a long outage never hot-loops
/// identical error lines.
#[derive(Debug)]
pub struct RelayStatus {
    state: AtomicU8,
    reconnect_attempts: AtomicU32,
    connected_peers: AtomicU64,
    last_error: Mutex<Option<String>>,
    /// Peers learned over the LIVE reservation socket — the relay's `GetPeers` response (RLY-005)
    /// plus `PeerConnected`/`PeerDisconnected` pushes. This is the discovery output of the persistent
    /// reservation: a consumer (dig-gossip's pool/address book) reads it instead of reopening an
    /// ephemeral socket per pass. Keyed by `peer_id` (deduped); bounded to [`MAX_KNOWN_PEERS`] so an
    /// untrusted relay can't exhaust memory; cleared on every reconnect so a stale list is never
    /// served across a drop.
    known_peers: Mutex<DiscoveredPeers>,
    /// Sink that injects an outbound [`RelayMessage`] into the LIVE reservation socket's write half.
    /// `Some` only while a session is held (set by `connect_once`, cleared on every drop) — this is
    /// what lets a [`RelayTunnel`] reuse the ONE persistent reservation socket for RLY-002 relayed
    /// transport instead of opening a second connection.
    outbound: Mutex<Option<mpsc::UnboundedSender<RelayMessage>>>,
    /// This node's own `peer_id` (hex), stamped as `from` on every RLY-002 frame the tunnels send.
    /// Set when a session registers; needed because a tunnel is opened from the shared status handle.
    local_peer_id: Mutex<Option<String>>,
    /// Open relayed-transport tunnels, keyed by the REMOTE peer's `peer_id` (hex). An inbound RLY-002
    /// `relay_message` from a peer is routed to its tunnel's inbound channel; a frame from a peer with
    /// no open tunnel is dropped (the untrusted-relay default). Entries are removed on tunnel drop.
    tunnels: Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>,
    /// Monotonic per-node sequence number stamped on outbound RLY-002 frames (ordering/dedup).
    relay_seq: AtomicU64,
}

impl Default for RelayStatus {
    fn default() -> Self {
        RelayStatus {
            state: AtomicU8::new(RelayState::Disconnected.to_u8()),
            reconnect_attempts: AtomicU32::new(0),
            connected_peers: AtomicU64::new(0),
            last_error: Mutex::new(None),
            known_peers: Mutex::new(DiscoveredPeers::default()),
            outbound: Mutex::new(None),
            local_peer_id: Mutex::new(None),
            tunnels: Mutex::new(HashMap::new()),
            relay_seq: AtomicU64::new(0),
        }
    }
}

impl RelayStatus {
    /// A fresh status (resting `Disconnected` until the task runs / the relay is reached).
    pub fn new() -> Arc<Self> {
        Arc::new(RelayStatus::default())
    }

    /// Read the current state.
    pub fn state(&self) -> RelayState {
        RelayState::from_u8(self.state.load(Ordering::Relaxed))
    }

    /// Transition to `next`, returning `true` IFF the state actually changed. Callers use the return
    /// to log ONCE per transition (no hot-loop spam).
    fn transition_to(&self, next: RelayState) -> bool {
        let prev = self.state.swap(next.to_u8(), Ordering::Relaxed);
        prev != next.to_u8()
    }

    /// Enter `Disabled` (reservation off). Idempotent; logs only on the first entry.
    pub fn set_disabled(&self) {
        if self.transition_to(RelayState::Disabled) {
            tracing::info!("relay reservation disabled (DIG_RELAY_URL=off)");
        }
    }

    /// Enter `Connecting`. Logs only on the transition (so reconnect attempts don't spam).
    pub fn set_connecting(&self) {
        if self.transition_to(RelayState::Connecting) {
            tracing::debug!("relay connecting");
        }
    }

    /// Mark `Connected` (clears the last error, resets the attempt counter). Logs recovery once.
    pub fn set_connected(&self, connected_peers: u64) {
        self.connected_peers
            .store(connected_peers, Ordering::Relaxed);
        self.reconnect_attempts.store(0, Ordering::Relaxed);
        *self.last_error.lock().unwrap() = None;
        if self.transition_to(RelayState::Connected) {
            tracing::info!(connected_peers, "relay reservation established");
        }
    }

    /// Mark `Disconnected` with an optional error and bump the attempt counter. Logs the failure
    /// ONLY on the transition into `Disconnected` (the first drop); subsequent failed retries while
    /// already `Disconnected` update the error/counter SILENTLY.
    pub fn set_disconnected(&self, error: Option<String>) {
        self.reconnect_attempts.fetch_add(1, Ordering::Relaxed);
        if let Some(e) = &error {
            *self.last_error.lock().unwrap() = Some(e.clone());
        }
        let changed = self.transition_to(RelayState::Disconnected);
        if changed {
            match &error {
                Some(e) => tracing::warn!(
                    error = %e,
                    "relay reservation lost — node still serving; retrying in background"
                ),
                None => tracing::info!("relay reservation closed — retrying in background"),
            }
        }
    }

    /// Whether a relay session is currently held.
    pub fn is_connected(&self) -> bool {
        self.state() == RelayState::Connected
    }

    /// The current reconnect-attempt count (for tests / RPC).
    pub fn reconnect_attempts(&self) -> u32 {
        self.reconnect_attempts.load(Ordering::Relaxed)
    }

    /// Snapshot of the peers discovered over the live reservation socket (RLY-005 `Peers` +
    /// `PeerConnected` pushes, minus `PeerDisconnected`). The consumer folds these into its address
    /// book / pool. Returns a clone so the caller holds no lock.
    pub fn known_peers(&self) -> Vec<RelayPeerInfo> {
        self.known_peers.lock().unwrap().order.clone()
    }

    /// Count of peers currently discovered over the live reservation socket.
    pub fn known_peer_count(&self) -> usize {
        self.known_peers.lock().unwrap().order.len()
    }

    /// Replace the discovered-peer set with a `GetPeers` response (RLY-005 `Peers`), deduped and
    /// truncated to [`MAX_KNOWN_PEERS`] (an untrusted relay could send an oversized frame).
    fn replace_known_peers(&self, peers: Vec<RelayPeerInfo>) {
        self.known_peers.lock().unwrap().replace(peers);
    }

    /// Fold in a relay-pushed `PeerConnected` notice, deduped by `peer_id`; dropped once the set is
    /// full ([`MAX_KNOWN_PEERS`]) so a flood can't exhaust memory.
    fn add_known_peer(&self, peer: RelayPeerInfo) {
        self.known_peers.lock().unwrap().insert(peer);
    }

    /// Drop a peer on a relay-pushed `PeerDisconnected` notice.
    fn remove_known_peer(&self, peer_id: &str) {
        self.known_peers.lock().unwrap().remove(peer_id);
    }

    /// Clear the discovered-peer set (on every reconnect — the list is per-session).
    fn clear_known_peers(&self) {
        self.known_peers.lock().unwrap().clear();
    }

    // -- RLY-002 relayed transport (the tier-6 TURN fallback) ------------------------------------
    //
    // A relayed tunnel reuses the ONE persistent reservation socket: outbound frames go through
    // `outbound` (drained by the reservation loop's write half), inbound `relay_message` frames are
    // routed by `from` peer_id to the matching tunnel. Available only while the reservation is held.

    /// Install the live session's outbound sink + this node's `peer_id`. Called by `connect_once`
    /// once registered; cleared by [`clear_transport`](Self::clear_transport) on every drop.
    fn set_transport(&self, peer_id: &str, outbound: mpsc::UnboundedSender<RelayMessage>) {
        *self.local_peer_id.lock().unwrap() = Some(peer_id.to_string());
        *self.outbound.lock().unwrap() = Some(outbound);
    }

    /// Tear down the transport on session drop: drop the outbound sink (so tunnel sends fail fast)
    /// and close every open tunnel's inbound channel (so a blocked `recv` wakes with `None`).
    fn clear_transport(&self) {
        *self.outbound.lock().unwrap() = None;
        self.tunnels.lock().unwrap().clear();
    }

    /// Whether a relayed tunnel can currently be opened — a reservation is held AND its outbound sink
    /// is live. The tier-6 [`RelayedTransport`](crate::method::relayed::RelayedTransport) gates on this.
    pub fn relay_transport_ready(&self) -> bool {
        self.is_connected() && self.outbound.lock().unwrap().is_some()
    }

    /// Open an RLY-002 relayed-transport tunnel to `target_peer` (hex `peer_id`) over the held
    /// reservation socket — the traversal ladder's FINAL tier when a pair can neither direct-dial nor
    /// hole-punch. The returned [`RelayTunnel`] sends/receives opaque payloads that the relay forwards
    /// A→relay→B; per NC-1 the payload is END-TO-END SEALED to the recipient so the relay forwards
    /// ciphertext only. `Err` if no reservation is held. Dropping the tunnel deregisters it.
    pub fn open_tunnel(
        self: &Arc<Self>,
        target_peer: &str,
        network_id: &str,
    ) -> Result<RelayTunnel, String> {
        if !self.relay_transport_ready() {
            return Err("relay reservation not connected — cannot open relayed tunnel".into());
        }
        let (tx, rx) = mpsc::channel(RELAY_TUNNEL_INBOUND_CAP);
        self.tunnels
            .lock()
            .unwrap()
            .insert(target_peer.to_string(), tx);
        Ok(RelayTunnel {
            target: target_peer.to_string(),
            network_id: network_id.to_string(),
            status: Arc::clone(self),
            inbound: rx,
        })
    }

    /// Route one inbound RLY-002 `relay_message` to its tunnel by `from` peer_id. Oversized payloads
    /// are dropped (size cap); a frame from a peer with no open tunnel is dropped; a full inbound
    /// channel drops the frame (backpressure). Returns silently in every drop case (untrusted relay).
    fn route_relayed(&self, from: &str, payload: Vec<u8>) {
        if payload.len() > MAX_RELAY_PAYLOAD {
            tracing::debug!(
                from,
                len = payload.len(),
                "dropping oversized relayed frame"
            );
            return;
        }
        let sink = self.tunnels.lock().unwrap().get(from).cloned();
        if let Some(sink) = sink {
            if sink.try_send(payload).is_err() {
                tracing::debug!(from, "relayed tunnel inbound full/closed — frame dropped");
            }
        }
    }

    /// Remove a tunnel's routing entry (called on [`RelayTunnel`] drop).
    fn close_tunnel(&self, target_peer: &str) {
        self.tunnels.lock().unwrap().remove(target_peer);
    }

    /// A JSON snapshot for a `control.relayStatus`-style RPC. `state` is the canonical truth;
    /// `connected` is a convenience boolean (== `state == connected`).
    pub fn snapshot_json(&self, endpoint: &str, peer_id: &str) -> serde_json::Value {
        let state = self.state();
        serde_json::json!({
            "state": state.as_str(),
            "connected": state == RelayState::Connected,
            "endpoint": endpoint,
            "peer_id": peer_id,
            "reconnect_attempts": self.reconnect_attempts.load(Ordering::Relaxed),
            "connected_peers": self.connected_peers.load(Ordering::Relaxed),
            "last_error": *self.last_error.lock().unwrap(),
        })
    }
}

/// A live RLY-002 relayed-transport tunnel to one peer, multiplexed over the node's persistent relay
/// reservation socket (the tier-6 TURN fallback). Writes are framed as RLY-002 `relay_message` to the
/// target and forwarded A→relay→B; reads are the payloads the relay forwards back from that peer.
///
/// Per NC-1 the payload MUST be END-TO-END SEALED to the recipient's key by the caller — the relay is
/// an untrusted forwarder that sees only ciphertext. Dropping the tunnel deregisters its routing.
pub struct RelayTunnel {
    /// The remote peer's `peer_id` (hex) — the RLY-002 `to`, and the routing key for inbound frames.
    target: String,
    /// The network the tunnel is scoped to (echoed for the consumer; relay routes by peer_id).
    network_id: String,
    /// Shared status handle — provides the live outbound sink, this node's `peer_id`, and the seq.
    status: Arc<RelayStatus>,
    /// Inbound payloads the relay forwarded from `target`, in arrival order (bounded — see
    /// [`RELAY_TUNNEL_INBOUND_CAP`]).
    inbound: mpsc::Receiver<Vec<u8>>,
}

impl RelayTunnel {
    /// The remote peer this tunnel forwards to/from (hex `peer_id`).
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The network the tunnel is scoped to.
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// Send `payload` to the target peer through the relay (RLY-002 `relay_message`). `payload` MUST
    /// already be sealed to the recipient (NC-1). `Err` if the reservation dropped (send after the
    /// session closed) or `payload` exceeds [`MAX_RELAY_PAYLOAD`].
    pub fn send(&self, payload: Vec<u8>) -> Result<(), String> {
        if payload.len() > MAX_RELAY_PAYLOAD {
            return Err(format!(
                "relayed payload {} exceeds cap {MAX_RELAY_PAYLOAD}",
                payload.len()
            ));
        }
        let from = self
            .status
            .local_peer_id
            .lock()
            .unwrap()
            .clone()
            .ok_or("relay reservation not connected — no local peer_id")?;
        let seq = self.status.relay_seq.fetch_add(1, Ordering::Relaxed);
        let frame = RelayMessage::RelayGossipMessage {
            from,
            to: self.target.clone(),
            payload,
            seq,
        };
        let guard = self.status.outbound.lock().unwrap();
        let sink = guard
            .as_ref()
            .ok_or("relay reservation not connected — cannot send relayed frame")?;
        sink.send(frame)
            .map_err(|_| "relay reservation write half closed".to_string())
    }

    /// Await the next payload the relay forwards from the target peer. `None` once the reservation
    /// drops (the session closed) — the caller should re-open the tunnel after the relay reconnects.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.inbound.recv().await
    }
}

impl Drop for RelayTunnel {
    fn drop(&mut self) {
        self.status.close_tunnel(&self.target);
    }
}

/// Resolve the relay endpoint: `DIG_RELAY_URL` if set + non-empty (and not the opt-out token), else
/// the canonical [`dig_constants::DIG_RELAY_URL`].
pub fn relay_url_from_env() -> String {
    std::env::var("DIG_RELAY_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .filter(|s| !is_off_token(s))
        .unwrap_or_else(|| dig_constants::DIG_RELAY_URL.to_string())
}

/// Whether the relay connection is enabled. Disabled when `DIG_RELAY_URL` is `off`/`disabled`/
/// empty-after-trim — an explicit opt-out for air-gapped/standalone nodes.
pub fn relay_enabled() -> bool {
    match std::env::var("DIG_RELAY_URL") {
        Ok(v) => !is_off_token(&v),
        Err(_) => true,
    }
}

/// `true` if `v` is the reservation opt-out token (`off`/`disabled`, case-insensitive, trimmed).
fn is_off_token(v: &str) -> bool {
    let v = v.trim();
    v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("disabled")
}

/// Current unix time (seconds), saturating.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Maintain a CONSTANT relay reservation forever: connect, register, keepalive, and on any drop
/// reconnect with capped exponential backoff. Spawned as a background task; tolerates the relay
/// being down (retries forever, never crashes). `peer_id` is the node's stable identity hex.
pub async fn run_relay_connection(
    endpoint: String,
    peer_id: String,
    network_id: String,
    listen_addrs: Vec<SocketAddr>,
    status: Arc<RelayStatus>,
) {
    run_relay_connection_with(
        endpoint,
        peer_id,
        network_id,
        listen_addrs,
        status,
        Backoff::default(),
    )
    .await
}

/// [`run_relay_connection`] with an explicit backoff schedule (tests pass tiny values for fast,
/// deterministic reconnect timing; the LOGIC is identical — only the sleep durations differ).
pub async fn run_relay_connection_with(
    endpoint: String,
    peer_id: String,
    network_id: String,
    listen_addrs: Vec<SocketAddr>,
    status: Arc<RelayStatus>,
    backoff: Backoff,
) {
    let mut consecutive_failures: u32 = 0;
    loop {
        status.set_connecting();
        match connect_once(&endpoint, &peer_id, &network_id, &listen_addrs, &status).await {
            Ok(()) => {
                consecutive_failures = 0;
                status.set_disconnected(None);
            }
            Err(e) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                status.set_disconnected(Some(e));
            }
        }
        // ALWAYS sleep a bounded backoff before retrying — prevents a busy error loop.
        let delay = backoff_secs_with(consecutive_failures, backoff.base_secs, backoff.cap_secs);
        tokio::time::sleep(Duration::from_secs(delay)).await;
    }
}

/// One connect → register → serve cycle. Returns `Ok` on a clean close, `Err(reason)` on failure.
async fn connect_once(
    endpoint: &str,
    peer_id: &str,
    network_id: &str,
    listen_addrs: &[SocketAddr],
    status: &Arc<RelayStatus>,
) -> Result<(), String> {
    // Each session's discovered-peer set + transport are independent — never carry state across a
    // drop. `clear_transport` also runs at the end so a dropped session's tunnels/sink never linger.
    status.clear_known_peers();
    status.clear_transport();

    let (ws, _resp) = tokio_tungstenite::connect_async(endpoint)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let (mut write, mut read) = ws.split();

    // RLY-001: register immediately so the relay holds our reservation, advertising the node's gossip
    // listen candidates (B1) so the relay can hand other peers a dialable candidate (§5.2 IPv6-first).
    let register = RelayMessage::Register {
        peer_id: peer_id.to_string(),
        network_id: network_id.to_string(),
        protocol_version: RELAY_PROTOCOL_VERSION,
        listen_addrs: listen_addrs.to_vec(),
    };
    send(&mut write, &register).await?;

    // Publish the outbound sink so RLY-002 relayed tunnels can reuse THIS persistent socket. Drained
    // in the select loop below; cleared when the session ends.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<RelayMessage>();
    status.set_transport(peer_id, out_tx);

    // RLY-005: pull the current peer list right away, then again periodically — all over THIS
    // persistent socket, so discovery never requires reopening a connection.
    let get_peers = RelayMessage::GetPeers {
        network_id: Some(network_id.to_string()),
    };
    send(&mut write, &get_peers).await?;

    let mut ping = tokio::time::interval(Duration::from_secs(PING_INTERVAL_SECS));
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await; // skip the immediate first tick

    let mut discovery = tokio::time::interval(Duration::from_secs(DISCOVERY_INTERVAL_SECS));
    discovery.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    discovery.tick().await; // skip the immediate first tick (we already pulled once above)

    // Run the session; whatever the outcome, tear the transport down so a dropped session never
    // leaves a stale outbound sink or open tunnels behind (they'd send into a closed socket).
    let result = serve_session(
        &mut write,
        &mut read,
        &mut ping,
        &mut discovery,
        &mut out_rx,
        network_id,
        status,
    )
    .await;
    status.clear_transport();
    result
}

/// The connected-session select loop: keepalive pings, periodic RLY-005 discovery, draining the
/// outbound relayed-transport sink onto the socket, and handling inbound frames. Returns `Ok` on a
/// clean close, `Err(reason)` on a failure. Split out of `connect_once` so its caller can always run
/// transport teardown regardless of how the session ends.
#[allow(clippy::too_many_arguments)]
async fn serve_session<W, R>(
    write: &mut W,
    read: &mut R,
    ping: &mut tokio::time::Interval,
    discovery: &mut tokio::time::Interval,
    out_rx: &mut mpsc::UnboundedReceiver<RelayMessage>,
    network_id: &str,
    status: &Arc<RelayStatus>,
) -> Result<(), String>
where
    W: SinkExt<Message> + Unpin,
    <W as futures_util::Sink<Message>>::Error: std::fmt::Display,
    R: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        tokio::select! {
            _ = ping.tick() => {
                send(write, &RelayMessage::Ping { timestamp: now_secs() }).await?;
            }
            _ = discovery.tick() => {
                send(write, &RelayMessage::GetPeers {
                    network_id: Some(network_id.to_string()),
                }).await?;
            }
            // A relayed tunnel queued an RLY-002 frame — forward it over THIS persistent socket.
            Some(frame) = out_rx.recv() => {
                send(write, &frame).await?;
            }
            frame = read.next() => {
                match frame {
                    None => return Ok(()),
                    Some(Err(e)) => return Err(format!("read: {e}")),
                    Some(Ok(Message::Close(_))) => return Ok(()),
                    Some(Ok(Message::Ping(p))) => {
                        write.send(Message::Pong(p)).await.map_err(|e| format!("pong: {e}"))?;
                    }
                    Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
                    Some(Ok(Message::Text(t))) => {
                        handle_incoming(t.into_bytes(), write, status).await?;
                    }
                    Some(Ok(Message::Binary(b))) => {
                        handle_incoming(b, write, status).await?;
                    }
                }
            }
        }
    }
}

/// Handle one decoded inbound relay frame: track RegisterAck (→ connected), answer relay Pings.
async fn handle_incoming<W>(
    bytes: Vec<u8>,
    write: &mut W,
    status: &Arc<RelayStatus>,
) -> Result<(), String>
where
    W: SinkExt<Message> + Unpin,
    <W as futures_util::Sink<Message>>::Error: std::fmt::Display,
{
    let Ok(msg) = serde_json::from_slice::<RelayMessage>(&bytes) else {
        return Ok(()); // ignore anything we can't parse; the relay is untrusted
    };
    match msg {
        RelayMessage::RegisterAck {
            success,
            message,
            connected_peers,
        } => {
            if success {
                status.set_connected(connected_peers as u64);
            } else {
                return Err(format!("register rejected: {message}"));
            }
        }
        RelayMessage::Ping { timestamp } => {
            send(write, &RelayMessage::Pong { timestamp }).await?;
        }
        // RLY-005 + push notices: fold peers discovered over the live socket into the status so the
        // consumer's pool/address book sees them without opening an ephemeral discovery connection.
        RelayMessage::Peers { peers } => status.replace_known_peers(peers),
        RelayMessage::PeerConnected { peer } => status.add_known_peer(peer),
        RelayMessage::PeerDisconnected { peer_id } => status.remove_known_peer(&peer_id),
        // RLY-002 relayed transport (tier-6 TURN): route a payload the relay forwarded from `from` to
        // that peer's open tunnel. Unknown-peer / oversized / full-channel frames are dropped inside
        // `route_relayed` (untrusted-relay defense). `to`/`seq` are the relay's concern; we key on
        // `from`. Per NC-1 `payload` is sealed ciphertext the relay could not read.
        RelayMessage::RelayGossipMessage { from, payload, .. } => {
            status.route_relayed(&from, payload)
        }
        RelayMessage::Error { code, message } => {
            return Err(format!("relay error {code}: {message}"));
        }
        other => tracing::debug!(?other, "relay message ignored by reservation loop"),
    }
    Ok(())
}

/// Serialize + send one `RelayMessage` as a WebSocket text frame.
async fn send<W>(write: &mut W, msg: &RelayMessage) -> Result<(), String>
where
    W: SinkExt<Message> + Unpin,
    <W as futures_util::Sink<Message>>::Error: std::fmt::Display,
{
    let txt = serde_json::to_string(msg).map_err(|e| format!("encode: {e}"))?;
    write
        .send(Message::Text(txt))
        .await
        .map_err(|e| format!("send: {e}"))
}
