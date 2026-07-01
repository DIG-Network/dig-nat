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

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

use crate::wire::RelayMessage;

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

/// Live relay-connection status, shared (via `Arc`) between the connection task and an RPC handler.
/// Cheap atomic reads. State setters do STATE-CHANGE-ONLY logging so a long outage never hot-loops
/// identical error lines.
#[derive(Debug)]
pub struct RelayStatus {
    state: AtomicU8,
    reconnect_attempts: AtomicU32,
    connected_peers: AtomicU64,
    last_error: Mutex<Option<String>>,
}

impl Default for RelayStatus {
    fn default() -> Self {
        RelayStatus {
            state: AtomicU8::new(RelayState::Disconnected.to_u8()),
            reconnect_attempts: AtomicU32::new(0),
            connected_peers: AtomicU64::new(0),
            last_error: Mutex::new(None),
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
    status: Arc<RelayStatus>,
) {
    run_relay_connection_with(endpoint, peer_id, network_id, status, Backoff::default()).await
}

/// [`run_relay_connection`] with an explicit backoff schedule (tests pass tiny values for fast,
/// deterministic reconnect timing; the LOGIC is identical — only the sleep durations differ).
pub async fn run_relay_connection_with(
    endpoint: String,
    peer_id: String,
    network_id: String,
    status: Arc<RelayStatus>,
    backoff: Backoff,
) {
    let mut consecutive_failures: u32 = 0;
    loop {
        status.set_connecting();
        match connect_once(&endpoint, &peer_id, &network_id, &status).await {
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
    status: &Arc<RelayStatus>,
) -> Result<(), String> {
    let (ws, _resp) = tokio_tungstenite::connect_async(endpoint)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let (mut write, mut read) = ws.split();

    // RLY-001: register immediately so the relay holds our reservation.
    let register = RelayMessage::Register {
        peer_id: peer_id.to_string(),
        network_id: network_id.to_string(),
        protocol_version: RELAY_PROTOCOL_VERSION,
    };
    send(&mut write, &register).await?;

    let mut ping = tokio::time::interval(Duration::from_secs(PING_INTERVAL_SECS));
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await; // skip the immediate first tick

    loop {
        tokio::select! {
            _ = ping.tick() => {
                send(&mut write, &RelayMessage::Ping { timestamp: now_secs() }).await?;
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
                        handle_incoming(t.into_bytes(), &mut write, status).await?;
                    }
                    Some(Ok(Message::Binary(b))) => {
                        handle_incoming(b, &mut write, status).await?;
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
