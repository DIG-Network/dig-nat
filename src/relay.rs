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
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dig_ip::{CandidateSource, DialConfig, LocalStack, PeerCandidates};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{client_async_tls_with_config, MaybeTlsStream, WebSocketStream};

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

/// Upper bound on concurrently-registered relay tunnels (outbound dial + inbound accept combined)
/// before the RESPONDER path refuses to create a new inbound circuit.
///
/// SECURITY: the relay is UNTRUSTED. When the accept path ([`RelayStatus::enable_accept`]) is on, an
/// inbound RLY-002 frame from an unknown peer creates a server-role tunnel + surfaces an accept — so
/// an uncapped accept lets a hostile relay flood distinct fabricated `from` ids to spawn unbounded
/// tunnels/accept-tasks (a memory/task-exhaustion DoS). Beyond this cap the introduced circuit is
/// DROPPED rather than accepted. 256 is far more concurrent relayed peers than the last-resort tier
/// ever legitimately carries, yet bounds the worst case to cheap, bounded memory.
pub const MAX_RELAY_TUNNELS: usize = 256;

/// Bounded capacity of the inbound-accept channel ([`RelayStatus::enable_accept`]). A full channel
/// means the consumer is not accepting introduced circuits fast enough; the newest is dropped
/// (bounded backpressure), never queued unboundedly.
const INBOUND_ACCEPT_CAP: usize = 64;

/// The mTLS role a locally-registered [`RelayTunnel`] runs — the discriminator that resolves the
/// GLARE / simultaneous-mutual-dial case (#1536). A relay circuit needs exactly ONE mTLS client + ONE
/// mTLS server; when two NAT'd peers fall to the relay tier and dial EACH OTHER at the same time (the
/// common two-NAT'd-peer flywheel case), both open a `Client` tunnel and both send a ClientHello —
/// each ClientHello would route into the OTHER side's client session (double-ClientHello deadlock).
/// Tagging the tunnel with its role lets [`route_relayed`](RelayStatus::route_relayed) detect that a
/// ClientHello arrived on a tunnel where WE are also the client (the glare signature) and apply the
/// deterministic tie-break instead of feeding it to our doomed client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelRole {
    /// WE initiated the dial — running [`PeerSession::client`](crate::mux::PeerSession::client) over
    /// this tunnel; inbound frames are the peer's ServerHello / server-side records.
    Client,
    /// WE accepted an introduced circuit — running [`PeerSession::server`](crate::mux::PeerSession::server)
    /// over this tunnel; inbound frames are the dialing peer's client-side records.
    Server,
}

/// A registered relayed tunnel: the inbound sink frames are routed into, the mTLS [`TunnelRole`] we
/// run over it (for the #1536 glare tie-break), and a monotonic `id` distinguishing this registration
/// from a later one on the SAME peer key. The id matters when the glare tie-break REPLACES our client
/// tunnel with a server tunnel under the same `from` key: the old client [`RelayTunnel`]'s `Drop`
/// (fired when its doomed dial fails) must not deregister the NEW server entry, so `close_tunnel` only
/// removes when the stored id still matches.
#[derive(Debug)]
struct TunnelEntry {
    sink: mpsc::Sender<Vec<u8>>,
    role: TunnelRole,
    id: u64,
}

/// Whether `payload` begins with a TLS handshake record whose first message is a ClientHello — a TLS
/// record has content-type `0x16` (handshake) at byte 0 and the handshake message type at byte 5
/// (`0x01` = ClientHello, `0x02` = ServerHello). A rustls client ships its ClientHello flight as the
/// first `poll_write`, so the first relayed frame from a fresh dialer matches this. Used ONLY to
/// distinguish a peer's GLARE ClientHello (a competing simultaneous dial) from the ServerHello / app
/// records expected on a tunnel where we are the client (#1536).
fn is_tls_client_hello(payload: &[u8]) -> bool {
    payload.len() >= 6 && payload[0] == 0x16 && payload[5] == 0x01
}

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
    /// The network id this reservation registered under. Echoed onto an inbound accepted tunnel (the
    /// RLY-002 frame itself does not carry it). Set alongside [`local_peer_id`] when a session registers.
    local_network_id: Mutex<Option<String>>,
    /// Sink that surfaces an INTRODUCED inbound circuit — a frame from a peer with NO open outbound
    /// tunnel — as a server-role [`RelayTunnel`] for a consumer to accept + serve
    /// ([`crate::accept::RelayAcceptor`]). `None` (default) = the original untrusted-relay behavior:
    /// drop an unknown-peer frame. `Some` once a consumer calls [`RelayStatus::enable_accept`].
    ///
    /// This is the RESPONDER counterpart to [`open_tunnel`](Self::open_tunnel): a relay circuit needs
    /// exactly ONE mTLS client + ONE mTLS server. The DIALER calls `open_tunnel` and runs
    /// `PeerSession::client`; the reservation-HOLDER that RECEIVES the introduced circuit accepts here
    /// and runs `PeerSession::server`. Without this path both ends acted as TLS client and the
    /// handshake deadlocked (`got ClientHello when expecting ServerHello`, #1536).
    inbound_accept: Mutex<Option<mpsc::Sender<RelayTunnel>>>,
    /// Open relayed-transport tunnels, keyed by the REMOTE peer's `peer_id` (hex). An inbound RLY-002
    /// `relay_message` from a peer is routed to its tunnel's inbound channel; a frame from a peer with
    /// no open tunnel is dropped (the untrusted-relay default). Entries are removed on tunnel drop.
    /// Each entry carries the mTLS [`TunnelRole`] we run over it so `route_relayed` can resolve the
    /// #1536 simultaneous-mutual-dial glare deterministically.
    tunnels: Mutex<HashMap<String, TunnelEntry>>,
    /// Monotonic per-node sequence number stamped on outbound RLY-002 frames (ordering/dedup).
    relay_seq: AtomicU64,
    /// Monotonic id assigned to each tunnel registration so a stale [`RelayTunnel`]'s `Drop` never
    /// deregisters a NEWER entry under the same peer key (see [`TunnelEntry::id`]; #1536 glare replace).
    next_tunnel_id: AtomicU64,
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
            local_network_id: Mutex::new(None),
            inbound_accept: Mutex::new(None),
            tunnels: Mutex::new(HashMap::new()),
            relay_seq: AtomicU64::new(0),
            next_tunnel_id: AtomicU64::new(0),
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

    /// Install the live session's outbound sink + this node's `peer_id` + the registered `network_id`.
    /// Called by `connect_once` once registered; cleared by [`clear_transport`](Self::clear_transport)
    /// on every drop.
    fn set_transport(
        &self,
        peer_id: &str,
        network_id: &str,
        outbound: mpsc::UnboundedSender<RelayMessage>,
    ) {
        *self.local_peer_id.lock().unwrap() = Some(peer_id.to_string());
        *self.local_network_id.lock().unwrap() = Some(network_id.to_string());
        *self.outbound.lock().unwrap() = Some(outbound);
    }

    /// Enable the RESPONDER (accept) path and return the receiver of INTRODUCED inbound circuits.
    ///
    /// A relayed connection needs one mTLS client + one mTLS server. The dialer opens a tunnel and
    /// runs the client; the reservation-HOLDER calls this once at startup and, for every inbound
    /// frame from a peer it has no open outbound tunnel to, receives a server-role [`RelayTunnel`]
    /// here to hand to a [`crate::accept::RelayAcceptor`] (which runs `PeerSession::server`). Until a
    /// consumer calls this, unknown-peer frames are DROPPED (the untrusted-relay default), so the
    /// accept path is strictly opt-in. The channel is bounded ([`INBOUND_ACCEPT_CAP`]).
    pub fn enable_accept(&self) -> mpsc::Receiver<RelayTunnel> {
        let (tx, rx) = mpsc::channel(INBOUND_ACCEPT_CAP);
        *self.inbound_accept.lock().unwrap() = Some(tx);
        rx
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
        // Self / SPKI-collision guard: a relayed circuit to our OWN peer_id has no lower/higher end
        // for the glare tie-break, so it could never converge to one-client-one-server — refuse it
        // (#1536).
        let local = self
            .local_peer_id
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_default();
        if !local.is_empty() && local == target_peer {
            return Err("refusing relayed self-dial (target == local peer_id)".into());
        }
        // NON-CLOBBER (#1536): if a circuit to this peer already exists — because an introduced
        // ClientHello made us its SERVER before this dial ran (a timing-ordered glare) — do NOT open a
        // second, conflicting circuit under the same key. The existing circuit IS the connection; a
        // duplicate would orphan one role and leave two mTLS sessions racing to one peer. Checked +
        // inserted under ONE lock so a concurrent `route_relayed` cannot slip a role in between.
        let mut tunnels = self.tunnels.lock().unwrap();
        if tunnels.contains_key(target_peer) {
            return Err("existing relay circuit to peer — not opening a duplicate".into());
        }
        // A dialer runs the mTLS client over the tunnel it opens.
        Ok(self.insert_entry(&mut tunnels, target_peer, network_id, TunnelRole::Client))
    }

    /// Register a tunnel routing entry for `target_peer` and build its [`RelayTunnel`], overwriting any
    /// existing entry under the key. Test-only (the `open_server_tunnel` + flood-cap tests use it); the
    /// production paths ([`open_tunnel`](Self::open_tunnel) + [`accept_introduced`](Self::accept_introduced))
    /// go through non-clobber checks first.
    #[cfg(test)]
    fn register_tunnel(
        self: &Arc<Self>,
        target_peer: &str,
        network_id: &str,
        role: TunnelRole,
    ) -> RelayTunnel {
        let mut tunnels = self.tunnels.lock().unwrap();
        self.insert_entry(&mut tunnels, target_peer, network_id, role)
    }

    /// Build a fresh [`RelayTunnel`] for `target_peer` with `role` and insert its entry into the
    /// already-locked `tunnels` map (assigning a monotonic id so a stale `Drop` never evicts a newer
    /// registration). The caller holds the lock, so the check-then-insert is atomic — the #1536
    /// non-clobber + role-race defense.
    fn insert_entry(
        self: &Arc<Self>,
        tunnels: &mut HashMap<String, TunnelEntry>,
        target_peer: &str,
        network_id: &str,
        role: TunnelRole,
    ) -> RelayTunnel {
        let (tx, rx) = mpsc::channel(RELAY_TUNNEL_INBOUND_CAP);
        let id = self.next_tunnel_id.fetch_add(1, Ordering::Relaxed);
        tunnels.insert(target_peer.to_string(), TunnelEntry { sink: tx, role, id });
        RelayTunnel {
            target: target_peer.to_string(),
            network_id: network_id.to_string(),
            status: Arc::clone(self),
            inbound: rx,
            id,
        }
    }

    /// Route one inbound RLY-002 `relay_message` to its tunnel by `from` peer_id. Oversized payloads
    /// are dropped (size cap); a frame from a peer with no open tunnel becomes an introduced circuit
    /// (accepted as a server, or dropped when the responder path is off / a flood cap is hit); a full
    /// inbound channel drops the frame (backpressure). Returns silently in every drop case (untrusted
    /// relay).
    ///
    /// GLARE (#1536): when a ClientHello arrives on a tunnel where WE are ALSO the client — the peer
    /// dialed us at the same time we dialed it — a deterministic tie-break makes exactly ONE side the
    /// server: the numerically-LOWER `peer_id` becomes the server. Both ends compute the same rule, so
    /// a crossed pair converges to one-client-one-server under ANY frame ordering with no retry loop.
    /// The TIMING-ordered variant (a peer's ClientHello arrives BEFORE our own dial registers) cannot
    /// produce a conflicting second circuit either: [`open_tunnel`](Self::open_tunnel) is non-clobber,
    /// so once we serve a peer our later dial to it is refused. The per-frame role LOOKUP + any
    /// same-frame yield (client-tunnel removal) happen under a single lock acquisition; the server
    /// registration in [`accept_introduced`](Self::accept_introduced) re-acquires and re-checks
    /// (non-clobber), so a dial racing between the two regions is abandoned, never a double-session.
    fn route_relayed(self: &Arc<Self>, from: &str, payload: Vec<u8>) {
        if payload.len() > MAX_RELAY_PAYLOAD {
            tracing::debug!(
                from,
                len = payload.len(),
                "dropping oversized relayed frame"
            );
            return;
        }
        let local = self
            .local_peer_id
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_default();
        // Self / SPKI-collision guard: a frame stamped with our OWN id can never be a real remote peer
        // (and the tie-break has no lower/higher end for it) — drop it rather than risk a no-server
        // hang (#1536).
        if !local.is_empty() && local == from {
            tracing::debug!("dropping relayed frame stamped with our own peer_id (self/collision)");
            return;
        }

        // Decide the action for this frame under ONE tunnels-lock so a concurrent `open_tunnel` cannot
        // race the role assignment.
        enum Route {
            /// Deliver into an existing tunnel's inbound sink.
            Deliver(mpsc::Sender<Vec<u8>>),
            /// Drop the frame (we retain our client role, or cannot serve).
            Ignore,
            /// Accept as an introduced server-role circuit.
            Accept,
        }
        let route = {
            let mut tunnels = self.tunnels.lock().unwrap();
            match tunnels.get(from).map(|e| (e.sink.clone(), e.role, e.id)) {
                // We are the SERVER for this peer — every frame is the client's; route it.
                Some((sink, TunnelRole::Server, _)) => Route::Deliver(sink),
                // We are the CLIENT. A ServerHello / app record is the expected response; a ClientHello
                // means the peer dialed us at the same time (GLARE).
                Some((sink, TunnelRole::Client, id)) => {
                    if !is_tls_client_hello(&payload) {
                        Route::Deliver(sink)
                    } else if local.as_str() > from {
                        // Higher id → WE keep the client role; ignore the peer's competing ClientHello
                        // (the lower-id peer yields to server and answers with a ServerHello).
                        tracing::debug!(
                            from,
                            "relay glare — retaining client role (peer yields to server)"
                        );
                        Route::Ignore
                    } else if self.inbound_accept.lock().unwrap().is_none() {
                        // Lower id → should be server, but no responder path is enabled; cannot serve,
                        // so keep the (doomed) client tunnel and drop rather than tear it down.
                        tracing::debug!(
                            from,
                            "relay glare — should be server but accept path off; dropping"
                        );
                        Route::Ignore
                    } else {
                        // Lower id → yield to the server role: drop our client tunnel (only if it is
                        // still ours) and accept the peer's circuit as server below.
                        if tunnels.get(from).map(|e| e.id) == Some(id) {
                            tunnels.remove(from);
                        }
                        tracing::debug!(from, "relay glare — yielding to server role");
                        Route::Accept
                    }
                }
                // No circuit yet — an INTRODUCED inbound circuit (a peer dialing us over the relay).
                None => Route::Accept,
            }
        };

        match route {
            Route::Deliver(sink) => {
                if sink.try_send(payload).is_err() {
                    tracing::debug!(from, "relayed tunnel inbound full/closed — frame dropped");
                }
            }
            Route::Ignore => {}
            Route::Accept => self.accept_introduced(from, payload),
        }
    }

    /// Accept an INTRODUCED inbound circuit from `from` as a server-role tunnel and surface it to the
    /// consumer's [`RelayAcceptor`](crate::accept::RelayAcceptor) — the RESPONDER path. Gated on: the
    /// responder path being enabled ([`enable_accept`](Self::enable_accept)), NON-CLOBBER (a circuit
    /// already under this key is kept, never replaced by a racing registration — the #1536
    /// double-session defense), and the flood cap ([`MAX_RELAY_TUNNELS`]). The opening frame (the
    /// dialer's ClientHello) is delivered into the fresh tunnel so the server handshake sees it; a full
    /// accept channel drops the newest circuit (bounded backpressure).
    fn accept_introduced(self: &Arc<Self>, from: &str, payload: Vec<u8>) {
        let Some(accept_tx) = self.inbound_accept.lock().unwrap().clone() else {
            return;
        };
        let network_id = self
            .local_network_id
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_default();
        let tunnel = {
            let mut tunnels = self.tunnels.lock().unwrap();
            if tunnels.contains_key(from) {
                // A circuit to this peer already exists (a racing dial claimed the key) — do NOT
                // clobber it into a conflicting second session.
                return;
            }
            if tunnels.len() >= MAX_RELAY_TUNNELS {
                tracing::debug!(
                    from,
                    "inbound relay accept cap reached — dropping introduced circuit"
                );
                return;
            }
            self.insert_entry(&mut tunnels, from, &network_id, TunnelRole::Server)
        };
        // Deliver the opening frame so the server-side handshake sees the ClientHello.
        if let Some(sink) = self
            .tunnels
            .lock()
            .unwrap()
            .get(from)
            .map(|e| e.sink.clone())
        {
            let _ = sink.try_send(payload);
        }
        // Hand the server-role tunnel to the consumer to run `PeerSession::server` over. A full/closed
        // accept channel drops the tunnel here — its `Drop` deregisters the routing.
        if accept_tx.try_send(tunnel).is_err() {
            tracing::debug!(
                from,
                "inbound accept channel full/closed — dropping introduced circuit"
            );
        }
    }

    /// Remove a tunnel's routing entry (called on [`RelayTunnel`] drop) — but ONLY when the stored
    /// entry is still THIS registration (`id` matches). A glare tie-break can replace our client
    /// tunnel with a server tunnel under the same peer key (#1536); the old client tunnel's `Drop`
    /// must not then evict the newer server entry.
    fn close_tunnel(&self, target_peer: &str, id: u64) {
        let mut tunnels = self.tunnels.lock().unwrap();
        if tunnels.get(target_peer).map(|e| e.id) == Some(id) {
            tunnels.remove(target_peer);
        }
    }

    /// Whether a relayed tunnel to `target_peer` is currently registered — the test hook fast-connect
    /// uses to assert the per-peer tunnel was released (dropped) after a relayed→direct promotion,
    /// while the reservation itself stays held.
    #[cfg(test)]
    pub(crate) fn open_tunnel_exists(&self, target_peer: &str) -> bool {
        self.tunnels.lock().unwrap().contains_key(target_peer)
    }

    /// Test-only: register a SERVER-role tunnel to `target_peer` directly, for tests that drive an mTLS
    /// SERVER over a hand-wired relay tunnel (the production server path is [`enable_accept`] +
    /// [`route_relayed`]'s accept branch). A server-role tunnel routes an incoming ClientHello straight
    /// through instead of treating it as the #1536 glare signal, so these tests mirror a real server
    /// receiving a dialer's ClientHello.
    #[cfg(test)]
    pub(crate) fn open_server_tunnel(
        self: &Arc<Self>,
        target_peer: &str,
        network_id: &str,
    ) -> RelayTunnel {
        self.register_tunnel(target_peer, network_id, TunnelRole::Server)
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
    /// This registration's monotonic id — so `Drop` only deregisters when the map still holds THIS
    /// entry (a glare replace may have superseded it under the same key; #1536).
    id: u64,
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

    /// Poll for the next inbound payload. This is the non-`async` primitive the
    /// [`RelayTunnelStream`](crate::tunnel::RelayTunnelStream) `AsyncRead` adapter drives so an mTLS
    /// session can run OVER the relay tunnel. `Poll::Ready(None)` once the reservation drops.
    pub(crate) fn poll_recv(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Vec<u8>>> {
        self.inbound.poll_recv(cx)
    }
}

impl Drop for RelayTunnel {
    fn drop(&mut self) {
        self.status.close_tunnel(&self.target, self.id);
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

/// A relay WebSocket endpoint parsed into the pieces the happy-eyeballs dial needs: the host to
/// resolve and the TCP port. The scheme (`ws`/`wss`) only selects the default port here — the
/// plaintext-vs-TLS choice is re-derived from the URL by [`client_async_tls_with_config`] during the
/// handshake, so a single code path serves both.
#[derive(Debug, PartialEq, Eq)]
struct RelayEndpoint {
    host: String,
    port: u16,
}

/// Parse a relay endpoint URL (`ws://host[:port][/path]` / `wss://host[:port][/path]`, IPv6 hosts in
/// `[…]`) into its host + port. Only the authority is needed for the dial; any path/query/fragment and
/// userinfo are ignored (the full URL is still handed to the WS handshake for the correct `Host`/SNI).
fn parse_relay_endpoint(endpoint: &str) -> Result<RelayEndpoint, String> {
    let (scheme, rest) = endpoint
        .split_once("://")
        .ok_or_else(|| format!("relay endpoint missing scheme: {endpoint}"))?;
    let default_port = match scheme.to_ascii_lowercase().as_str() {
        "ws" => 80,
        "wss" => 443,
        other => return Err(format!("unsupported relay scheme: {other}")),
    };
    // Authority only: drop any path/query/fragment, then any `userinfo@`.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let authority = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);

    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal: `[addr]` or `[addr]:port`.
        let (h, after) = stripped
            .split_once(']')
            .ok_or_else(|| format!("malformed IPv6 authority: {authority}"))?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| format!("bad relay port: {after}"))?,
            None => default_port,
        };
        (h.to_string(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (
            h.to_string(),
            p.parse().map_err(|_| format!("bad relay port: {p}"))?,
        )
    } else {
        (authority.to_string(), default_port)
    };

    if host.is_empty() {
        return Err(format!("relay endpoint missing host: {endpoint}"));
    }
    Ok(RelayEndpoint { host, port })
}

/// Resolve a relay host to its family-tagged dial candidates: a literal IP yields one candidate (no
/// DNS), a hostname is resolved to its full A + AAAA set. The candidates feed `dig_ip::connect`, which
/// applies the §5.2 IPv6-first preference + local∩peer family intersection, so no ordering is imposed
/// here — the addresses are added as resolved and tagged by family for observability.
async fn resolve_relay_candidates(host: &str, port: u16) -> Result<PeerCandidates, String> {
    let mut candidates = PeerCandidates::new();
    let source_for = |ip: &IpAddr| {
        if ip.is_ipv6() {
            CandidateSource::DnsAAAA
        } else {
            CandidateSource::DnsA
        }
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        candidates.add(SocketAddr::new(ip, port), source_for(&ip));
    } else {
        let resolved = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| format!("resolve {host}:{port}: {e}"))?;
        for addr in resolved {
            candidates.add(addr, source_for(&addr.ip()));
        }
    }
    if candidates.is_empty() {
        return Err(format!("no addresses resolved for {host}:{port}"));
    }
    Ok(candidates)
}

/// Race the relay `candidates` IPv6-first with graceful IPv4 fallback via `dig_ip::connect` (§5.2,
/// RFC 8305). The transport connect stays a caller-supplied closure so the racing logic is unit-tested
/// with a fake dial (no real DNS/sockets) exactly as the direct-peer dialer does in `dialer.rs`; the
/// production caller ([`open_relay_ws`]) hands it a real [`TcpStream::connect`].
async fn race_relay_candidates<C, F, Fut>(
    local: &LocalStack,
    candidates: &PeerCandidates,
    config: DialConfig,
    dial_fn: F,
) -> Result<dig_ip::DialWinner<C>, String>
where
    F: Fn(SocketAddr) -> Fut + Sync,
    Fut: std::future::Future<Output = Result<C, String>> + Send,
    C: Send,
{
    dig_ip::connect(local, candidates, config, dial_fn)
        .await
        .map_err(|e| format!("relay happy-eyeballs dial: {e}"))
}

/// Open the relay WebSocket over an IPv6-first happy-eyeballs TCP race (§5.2), matching the direct-peer
/// dial path in `dialer.rs`: resolve the endpoint host to its A + AAAA candidates, race the TCP connect
/// via `dig_ip::connect` (IPv6-first, fast IPv4 fallback), then run the WS handshake over the WINNING
/// socket — TLS-over-that-stream for `wss://`, plaintext for `ws://` (the mode is taken from the URL by
/// [`client_async_tls_with_config`]). Replaces `tokio_tungstenite::connect_async`, whose sequential,
/// single-family resolve-and-connect contradicted the IPv6-first reservation guarantee.
async fn open_relay_ws(
    endpoint: &str,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, String> {
    let parsed = parse_relay_endpoint(endpoint)?;
    let candidates = resolve_relay_candidates(&parsed.host, parsed.port).await?;
    let local = LocalStack::cached();
    let winner = race_relay_candidates(
        &local,
        &candidates,
        DialConfig::default(),
        |addr| async move {
            TcpStream::connect(addr)
                .await
                .map_err(|e| format!("tcp connect {addr}: {e}"))
        },
    )
    .await?;
    let (ws, _resp) = client_async_tls_with_config(endpoint, winner.conn, None, None)
        .await
        .map_err(|e| format!("ws handshake: {e}"))?;
    Ok(ws)
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

    let ws = open_relay_ws(endpoint).await?;
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
    status.set_transport(peer_id, network_id, out_tx);

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

/// Wire two in-memory relay reservations to forward RLY-002 frames to each OTHER — a loopback relay
/// with no real network. Each returned [`RelayStatus`] is `Connected` with a live outbound sink whose
/// frames are routed into the peer's tunnels by `from` peer_id, exactly as a real relay would forward
/// A→relay→B. Used to prove a full mTLS session round-trips over [`RelayTunnel`]s (see `tunnel.rs`).
///
/// `a` opens tunnels targeting `b_id`; `b` opens tunnels targeting `a_id`.
#[cfg(test)]
pub(crate) fn loopback_reservation_pair(
    a_id: &str,
    b_id: &str,
) -> (Arc<RelayStatus>, Arc<RelayStatus>) {
    let a = RelayStatus::new();
    let b = RelayStatus::new();
    a.set_connected(1);
    b.set_connected(1);

    let (a_tx, mut a_rx) = mpsc::unbounded_channel::<RelayMessage>();
    let (b_tx, mut b_rx) = mpsc::unbounded_channel::<RelayMessage>();
    a.set_transport(a_id, DEFAULT_NETWORK_ID, a_tx);
    b.set_transport(b_id, DEFAULT_NETWORK_ID, b_tx);

    // Drain a's outbound → forward into b (route by `from`), and symmetrically b → a. This is the
    // relay's forwarding role, in-process.
    let b_route = Arc::clone(&b);
    tokio::spawn(async move {
        while let Some(RelayMessage::RelayGossipMessage { from, payload, .. }) = a_rx.recv().await {
            b_route.route_relayed(&from, payload);
        }
    });
    let a_route = Arc::clone(&a);
    tokio::spawn(async move {
        while let Some(RelayMessage::RelayGossipMessage { from, payload, .. }) = b_rx.recv().await {
            a_route.route_relayed(&from, payload);
        }
    });

    (a, b)
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

#[cfg(test)]
mod tests {
    use super::*;
    use dig_ip::Family;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::Mutex as StdMutex;

    #[test]
    fn parses_wss_host_and_explicit_port() {
        let ep = parse_relay_endpoint("wss://relay.dig.net:443").unwrap();
        assert_eq!(ep.host, "relay.dig.net");
        assert_eq!(ep.port, 443);
    }

    #[test]
    fn parses_default_ports_by_scheme() {
        assert_eq!(
            parse_relay_endpoint("wss://relay.dig.net").unwrap().port,
            443
        );
        assert_eq!(parse_relay_endpoint("ws://relay.dig.net").unwrap().port, 80);
    }

    #[test]
    fn parses_bracketed_ipv6_authority_with_and_without_port() {
        let with_port = parse_relay_endpoint("wss://[2001:db8::1]:8443").unwrap();
        assert_eq!(with_port.host, "2001:db8::1");
        assert_eq!(with_port.port, 8443);
        let no_port = parse_relay_endpoint("wss://[2001:db8::1]/ws").unwrap();
        assert_eq!(no_port.host, "2001:db8::1");
        assert_eq!(no_port.port, 443);
    }

    #[test]
    fn ignores_path_query_and_userinfo() {
        let ep = parse_relay_endpoint("wss://user@relay.dig.net:9443/ws?x=1#f").unwrap();
        assert_eq!(ep.host, "relay.dig.net");
        assert_eq!(ep.port, 9443);
    }

    #[test]
    fn rejects_malformed_endpoints() {
        assert!(parse_relay_endpoint("relay.dig.net:443").is_err()); // no scheme
        assert!(parse_relay_endpoint("http://relay.dig.net").is_err()); // wrong scheme
        assert!(parse_relay_endpoint("wss://relay.dig.net:notaport").is_err());
    }

    #[tokio::test]
    async fn resolve_relay_candidates_handles_ip_literals_without_dns() {
        let v6 = resolve_relay_candidates("2001:db8::1", 443).await.unwrap();
        assert_eq!(v6.all().len(), 1);
        assert_eq!(v6.all()[0].family, Family::V6);
        assert_eq!(v6.all()[0].source, CandidateSource::DnsAAAA);

        let v4 = resolve_relay_candidates("203.0.113.7", 443).await.unwrap();
        assert_eq!(v4.all()[0].family, Family::V4);
        assert_eq!(v4.all()[0].source, CandidateSource::DnsA);
    }

    /// The relay dial races BOTH families and falls back to IPv4 when the IPv6 candidate is dead —
    /// the §5.2 happy-eyeballs guarantee, proven with a FAKE dial closure (no real DNS/sockets). A
    /// dead IPv6 candidate + a live IPv4 candidate on a dual-stack host must yield the IPv4 winner,
    /// and BOTH families must have been attempted.
    #[tokio::test]
    async fn relay_dial_races_both_families_and_falls_back_to_ipv4() {
        let mut candidates = PeerCandidates::new();
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let v4: SocketAddr = "203.0.113.7:443".parse().unwrap();
        candidates.add(v6, CandidateSource::DnsAAAA);
        candidates.add(v4, CandidateSource::DnsA);

        let dual = LocalStack::from_flags(true, true);
        let attempted: StdMutex<Vec<SocketAddr>> = StdMutex::new(Vec::new());
        // Fast attempt-delay so the hedged IPv4 starts promptly once the IPv6 attempt fails.
        let cfg = DialConfig {
            per_attempt_timeout: Duration::from_secs(1),
            attempt_delay: Duration::from_millis(5),
        };

        let winner = race_relay_candidates(&dual, &candidates, cfg, |addr| {
            let attempted = &attempted;
            async move {
                attempted.lock().unwrap().push(addr);
                if addr.is_ipv6() {
                    Err(format!("simulated dead IPv6 {addr}"))
                } else {
                    Ok(addr) // the fake "connection" is just the address that won
                }
            }
        })
        .await
        .expect("IPv4 fallback wins when IPv6 is dead");

        assert_eq!(winner.conn, v4, "the live IPv4 candidate won");
        assert_eq!(winner.family, Family::V4);
        let tried = attempted.lock().unwrap();
        assert!(
            tried.contains(&v6),
            "the IPv6 candidate was attempted first"
        );
        assert!(
            tried.contains(&v4),
            "the IPv4 candidate was attempted as fallback"
        );
    }

    /// IPv6 is the PREFERENCE, not merely first-attempted: with both families live on a dual-stack
    /// host, the IPv6 candidate wins the race (IPv4 is only a fallback).
    #[tokio::test]
    async fn relay_dial_prefers_ipv6_when_both_live() {
        let mut candidates = PeerCandidates::new();
        let v6: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
        let v4: SocketAddr = "203.0.113.8:443".parse().unwrap();
        candidates.add(v6, CandidateSource::DnsAAAA);
        candidates.add(v4, CandidateSource::DnsA);

        let dual = LocalStack::from_flags(true, true);
        let calls = AtomicUsize::new(0);
        let winner = race_relay_candidates(&dual, &candidates, DialConfig::default(), |addr| {
            calls.fetch_add(1, AtomicOrdering::Relaxed);
            async move { Ok::<SocketAddr, String>(addr) }
        })
        .await
        .unwrap();

        assert_eq!(winner.conn, v6, "IPv6 preferred when both are viable");
        assert_eq!(winner.family, Family::V6);
    }

    /// Build a `Connected` status with a live (dummy) outbound sink + local identity, so
    /// `route_relayed`'s introduced-circuit path can run without a real relay socket.
    fn connected_status(local_id: &str) -> Arc<RelayStatus> {
        let status = RelayStatus::new();
        status.set_connected(1);
        let (out_tx, _out_rx) = mpsc::unbounded_channel::<RelayMessage>();
        status.set_transport(local_id, DEFAULT_NETWORK_ID, out_tx);
        // These tests exercise the introduced-circuit ROUTING (register/accept/drop), which never uses
        // the outbound sink, so the receiver may drop at end of scope — the sink stays `Some`.
        status
    }

    /// SECURITY (accept OFF): with NO responder path enabled, an introduced RLY-002 frame from an
    /// unknown peer is DROPPED — no tunnel is created and nothing is surfaced. This is the
    /// untrusted-relay default: a node that never opted into accepting relayed circuits cannot be made
    /// to spawn one by a hostile relay.
    #[test]
    fn introduced_frame_dropped_when_accept_disabled() {
        let status = connected_status("00aa");
        // A ClientHello-shaped frame from a peer we hold NO tunnel to — the introduced-circuit trigger.
        status.route_relayed("ffbb", vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0, 0, 0, 0]);
        assert!(
            !status.open_tunnel_exists("ffbb"),
            "no tunnel surfaced for an introduced circuit while accept is off"
        );
        assert_eq!(
            status.tunnels.lock().unwrap().len(),
            0,
            "accept-off drops the introduced circuit entirely"
        );
    }

    /// SECURITY (flood defense, tunnel cap): once [`MAX_RELAY_TUNNELS`] tunnels are open, a further
    /// introduced circuit from a new peer is DROPPED rather than registered — a hostile relay flooding
    /// distinct fabricated `from` ids cannot spawn unbounded server tunnels/accept-tasks.
    #[test]
    fn introduced_circuit_dropped_at_max_tunnels_cap() {
        let status = connected_status("00aa");
        let mut accept_rx = status.enable_accept();
        // Saturate the tunnel table at the cap (held open by the returned RelayTunnels).
        let mut held = Vec::new();
        for i in 0..MAX_RELAY_TUNNELS {
            held.push(status.register_tunnel(
                &format!("peer{i:05}"),
                DEFAULT_NETWORK_ID,
                TunnelRole::Server,
            ));
        }
        assert_eq!(status.tunnels.lock().unwrap().len(), MAX_RELAY_TUNNELS);

        status.route_relayed("overflowpeer", vec![1, 2, 3]);
        assert!(
            !status.open_tunnel_exists("overflowpeer"),
            "an introduced circuit beyond the tunnel cap is dropped, not registered"
        );
        assert_eq!(
            status.tunnels.lock().unwrap().len(),
            MAX_RELAY_TUNNELS,
            "tunnel count never grows past the cap"
        );
        assert!(
            accept_rx.try_recv().is_err(),
            "the capped circuit is never surfaced to the acceptor"
        );
        drop(held);
    }

    /// SECURITY (flood defense, accept channel): when the bounded inbound-accept channel
    /// ([`INBOUND_ACCEPT_CAP`]) is full — the consumer is not accepting fast enough — a further
    /// introduced circuit is DROPPED (its freshly-registered tunnel is torn down), bounded
    /// backpressure rather than unbounded queueing.
    #[test]
    fn introduced_circuit_dropped_when_accept_channel_full() {
        let status = connected_status("00aa");
        let mut accept_rx = status.enable_accept();
        // Fill the accept channel to capacity WITHOUT draining it — each surfaced circuit occupies one
        // slot and keeps its server tunnel registered (the RelayTunnel lives in the channel).
        for i in 0..INBOUND_ACCEPT_CAP {
            status.route_relayed(&format!("in{i:05}"), vec![9, 9, 9]);
        }
        assert_eq!(
            status.tunnels.lock().unwrap().len(),
            INBOUND_ACCEPT_CAP,
            "each surfaced circuit registered exactly one server tunnel"
        );

        // One more: the accept channel is full → the tunnel is registered then immediately dropped,
        // so its routing is deregistered and nothing new is surfaced.
        status.route_relayed("overflow", vec![9, 9, 9]);
        assert!(
            !status.open_tunnel_exists("overflow"),
            "an introduced circuit is dropped when the accept channel is full"
        );

        let mut surfaced = 0;
        while accept_rx.try_recv().is_ok() {
            surfaced += 1;
        }
        assert_eq!(
            surfaced, INBOUND_ACCEPT_CAP,
            "exactly the channel capacity surfaced — never the overflow circuit"
        );
    }

    /// REGRESSION (#1536 glare, TIMING order): a peer's ClientHello arrives BEFORE our own dial to it
    /// registers. We accept it as a server; our later dial to the SAME peer MUST then be refused
    /// (non-clobber) so no conflicting second circuit / double mTLS session is created. This is the
    /// deeper ordering the first tie-break missed (role was decided by who-registered-first).
    #[test]
    fn clienthello_before_local_dial_does_not_double_register() {
        let status = connected_status("bbbb");
        let mut accept_rx = status.enable_accept();

        // The peer's introduced ClientHello arrives first → we accept it as a server-role circuit.
        status.route_relayed("aaaa", vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0, 0, 0, 0]);
        assert!(status.open_tunnel_exists("aaaa"));
        let _server_tunnel = accept_rx
            .try_recv()
            .expect("introduced circuit surfaced as a server");

        // Our own dial to that peer now must be REFUSED — the existing circuit is the connection.
        let dial = status.open_tunnel("aaaa", DEFAULT_NETWORK_ID);
        assert!(
            dial.is_err(),
            "a second dial to a peer we already serve is refused (no double-session)"
        );
        assert_eq!(
            status.tunnels.lock().unwrap().len(),
            1,
            "exactly one circuit per peer — never a conflicting client+server pair"
        );
    }

    /// REGRESSION (#1536 equal-id): a relayed self-dial, or a frame stamped with our OWN peer_id
    /// (theoretical SPKI collision / a hostile relay reflecting our id), has no lower/higher end for
    /// the tie-break — it MUST be rejected outright, never producing a no-server hang.
    #[test]
    fn self_dial_and_self_stamped_frame_rejected() {
        let status = connected_status("cccc");
        assert!(
            status.open_tunnel("cccc", DEFAULT_NETWORK_ID).is_err(),
            "a relayed self-dial (target == local id) is refused"
        );

        let mut accept_rx = status.enable_accept();
        status.route_relayed("cccc", vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0, 0, 0, 0]);
        assert!(
            !status.open_tunnel_exists("cccc"),
            "a frame stamped with our own id is dropped, never registered"
        );
        assert!(
            accept_rx.try_recv().is_err(),
            "a self-stamped frame is never surfaced as an accept"
        );
    }

    /// SECURITY (#1536 relay-injected-ClientHello DoS): an untrusted relay can inject a bogus
    /// ClientHello on a lower-id node's client tunnel to force it to yield its outbound dial to a
    /// server accept that no real peer completes. mTLS identity is never bypassed, but the outbound
    /// dial MUST NOT be permanently lost — once the bogus (never-completing) server circuit is dropped,
    /// the peer key frees and a fresh dial is possible.
    #[test]
    fn injected_clienthello_yield_does_not_permanently_block_redial() {
        // local id "00aa" is numerically lower than the peer "ffff", so we are the yield-to-server side.
        let status = connected_status("00aa");
        let mut accept_rx = status.enable_accept();

        let client_tunnel = status
            .open_tunnel("ffff", DEFAULT_NETWORK_ID)
            .expect("outbound relayed dial opens");
        assert!(status.open_tunnel_exists("ffff"));

        // The relay injects a bogus ClientHello with from=ffff → glare on our client tunnel → we (the
        // lower id) yield: drop the client tunnel, surface a server accept.
        status.route_relayed("ffff", vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0, 0, 0, 0]);
        let server_tunnel = accept_rx
            .try_recv()
            .expect("the injected ClientHello yielded a server accept");

        // The original outbound dial is cancelled; dropping its handle must NOT evict the newer server
        // entry (generation-id guard).
        drop(client_tunnel);
        assert!(
            status.open_tunnel_exists("ffff"),
            "the server circuit survives the cancelled client dial's drop"
        );

        // The bogus circuit completes no handshake; once its tunnel is dropped the key frees...
        drop(server_tunnel);
        assert!(
            !status.open_tunnel_exists("ffff"),
            "dropping the never-completing server circuit releases the peer key"
        );
        // ...and a fresh dial is possible — no permanent lockout from the injected frame.
        assert!(
            status.open_tunnel("ffff", DEFAULT_NETWORK_ID).is_ok(),
            "a fresh outbound dial succeeds after the bogus injection is cleaned up"
        );
    }
}
