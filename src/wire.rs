//! Relay protocol wire types — **vendored, byte-identical** to `dig-relay`'s `src/wire.rs`,
//! `dig-node`'s `relay::RelayMessage`, and `dig-gossip`'s `relay_types` (requirements
//! **RLY-001** through **RLY-007**).
//!
//! # Provenance & contract
//!
//! The canonical relay wire lives in `dig-gossip` (`src/relay/relay_types.rs`); `dig-relay` is the
//! SERVER, `dig-node`/`dig-nat` are CLIENTS of the same JSON-over-WebSocket wire. These types are
//! copied here verbatim rather than depending on `dig-gossip` because the wire depends only on
//! `serde` + `std`, whereas `dig-gossip` pulls the entire L2/Chia stack just to expose two structs.
//! The `#[serde(tag = "type")]` discriminators + field names MUST stay byte-identical to the
//! server's so both speak the same JSON; this is pinned by `tests/wire_conformance.rs`. The
//! superproject `SYSTEM.md` records the change-impact edge: a change to the relay wire must be
//! mirrored across all four copies in the same unit of work.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Complete relay protocol message enum — JSON over WebSocket, `#[serde(tag = "type")]`.
// Field-level docs are intentionally omitted on this VENDORED type: the fields are the wire
// contract, kept byte-identical to the four copies (dig-relay, dig-node, dig-gossip, dig-nat), and
// documenting them per-copy would invite drift. The variant docs above each `#[serde(rename)]`
// carry the RLY-00x meaning; the field names ARE the JSON keys.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RelayMessage {
    // -- RLY-001: Registration --
    /// Client → Relay: register after WebSocket connect.
    #[serde(rename = "register")]
    Register {
        peer_id: String,
        network_id: String,
        protocol_version: u32,
    },

    /// Relay → Client: registration acknowledgement.
    #[serde(rename = "register_ack")]
    RegisterAck {
        success: bool,
        message: String,
        connected_peers: usize,
    },

    /// Client → Relay: graceful disconnect.
    #[serde(rename = "unregister")]
    Unregister { peer_id: String },

    // -- RLY-002: Targeted message forwarding --
    /// Client → Relay → Client: forward to a specific peer.
    #[serde(rename = "relay_message")]
    RelayGossipMessage {
        from: String,
        to: String,
        payload: Vec<u8>,
        seq: u64,
    },

    // -- RLY-003: Broadcast --
    /// Client → Relay → All: broadcast to all relay peers.
    #[serde(rename = "broadcast")]
    Broadcast {
        from: String,
        payload: Vec<u8>,
        exclude: Vec<String>,
    },

    // -- Peer notifications --
    /// Relay → Client: new peer connected to relay.
    #[serde(rename = "peer_connected")]
    PeerConnected { peer: RelayPeerInfo },

    /// Relay → Client: peer disconnected from relay.
    #[serde(rename = "peer_disconnected")]
    PeerDisconnected { peer_id: String },

    // -- RLY-005: Peer list --
    /// Client → Relay: request connected peer list.
    #[serde(rename = "get_peers")]
    GetPeers { network_id: Option<String> },

    /// Relay → Client: peer list response.
    #[serde(rename = "peers")]
    Peers { peers: Vec<RelayPeerInfo> },

    // -- RLY-006: Keepalive --
    /// Bidirectional keepalive.
    #[serde(rename = "ping")]
    Ping { timestamp: u64 },

    /// Keepalive response.
    #[serde(rename = "pong")]
    Pong { timestamp: u64 },

    // -- RLY-007: NAT traversal --
    /// Client → Relay: request hole-punch coordination.
    #[serde(rename = "hole_punch_request")]
    HolePunchRequest {
        peer_id: String,
        target_peer_id: String,
        external_addr: SocketAddr,
    },

    /// Relay → Client: hole-punch coordination (the other peer's external address).
    #[serde(rename = "hole_punch_coordinate")]
    HolePunchCoordinate {
        peer_id: String,
        external_addr: SocketAddr,
    },

    /// Client → Relay: hole-punch result.
    #[serde(rename = "hole_punch_result")]
    HolePunchResult { peer_id: String, success: bool },

    // -- Error --
    /// Relay → Client: error notification.
    #[serde(rename = "error")]
    Error { code: u32, message: String },
}

/// Peer info as tracked by the relay server. `#[serde]` field names are part of the wire contract
/// (vendored byte-identical — see the module docs; field-level docs omitted to avoid drift).
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayPeerInfo {
    pub peer_id: String,
    pub network_id: String,
    pub protocol_version: u32,
    pub connected_at: u64,
    pub last_seen: u64,
}

impl RelayPeerInfo {
    /// Build a `RelayPeerInfo` stamped with the current unix time for `connected_at`/`last_seen`.
    pub fn new(peer_id: String, network_id: String, protocol_version: u32) -> Self {
        let now = unix_secs();
        Self {
            peer_id,
            network_id,
            protocol_version,
            connected_at: now,
            last_seen: now,
        }
    }
}

/// Current unix time in seconds (saturating). Mirrors dig-gossip's metric timestamp helper.
fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
