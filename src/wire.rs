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
// `non_exhaustive` so ADDING a wire message is no longer a breaking change.
//
// This wire grows: RLY-008 added PEX, RLY-009 added the DHT-record view. Each addition was a
// semver-major event for a `pub enum`, because a downstream exhaustive `match` stops compiling —
// and in this ecosystem that meant every consumer pinned to the old minor (dig-gossip, dig-dht,
// dig-download, dig-peer-selector, dig-peer) had to be bumped and re-released before dig-node could
// pick the change up at all. RLY-009 cost exactly that cascade (dig_ecosystem #1935).
//
// With this attribute a new variant is ADDITIVE: external matches already carry a wildcard arm, so
// the next RLY-0xx ships as a PATCH and reaches every consumer on a plain `cargo update`. Adding it
// is itself the last breaking change of this class.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[non_exhaustive]
pub enum RelayMessage {
    // -- RLY-001: Registration --
    /// Client → Relay: register after WebSocket connect.
    #[serde(rename = "register")]
    Register {
        peer_id: String,
        network_id: String,
        protocol_version: u32,
        // The node's advertised gossip LISTEN candidate address(es), IPv6-first (§5.2). Additive
        // since protocol v1 (NC-6 soft-fork): appended LAST, default-empty + skip-when-empty so the
        // wire stays byte-identical for pre-#924 peers. Byte-identical to dig-relay-protocol 0.2.0.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        listen_addrs: Vec<SocketAddr>,
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

    // -- RLY-009: DHT record observability (dig_ecosystem #1935) --
    /// Relay → Client: ask this node for an AGGREGATED view of its DHT provider records.
    ///
    /// The relay is not a DHT node and holds no records, but it already keeps a live reservation to
    /// every registered peer — and a Kademlia node stores records for keys near its OWN `peer_id`,
    /// so its store describes MANY OTHER peers' content. Asking each connected node therefore yields
    /// a broad slice of the real DHT without the relay ever joining it.
    ///
    /// `max_keys` bounds the answer. Additive (NC-6 soft-fork): a pre-RLY-009 node does not
    /// recognise this `type` and simply never answers, which the relay MUST treat as "no data"
    /// rather than an error.
    #[serde(rename = "get_dht_records")]
    GetDhtRecords { max_keys: usize },

    /// Client → Relay: the aggregated view requested by [`RelayMessage::GetDhtRecords`].
    ///
    /// Carries COUNTS, never provider identities — a provider record is a `(peer_id, content_key)`
    /// pair, and publishing that linkage is exactly what the relay's `/map` privacy contract
    /// forbids.
    #[serde(rename = "dht_records")]
    DhtRecords {
        records: Vec<DhtRecordEntry>,
        /// Keys with a live provider BEFORE `max_keys` was applied, so the relay can report
        /// "showing N of M" instead of presenting a truncated view as complete.
        total_keys: usize,
        truncated: bool,
    },

    // -- Error --
    /// Relay → Client: error notification.
    #[serde(rename = "error")]
    Error { code: u32, message: String },
}

/// One content key in a [`RelayMessage::DhtRecords`] answer: the key and how many live providers the
/// answering node knows for it.
///
/// Deliberately carries no provider identity (see [`RelayMessage::DhtRecords`]). Mirrors
/// `dig_dht::ProviderSnapshotEntry` by shape rather than by dependency — `dig-dht` sits ABOVE
/// `dig-nat` in the crate hierarchy, so the type is defined here and the node maps into it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DhtRecordEntry {
    /// The 64-hex content key.
    pub content_key: String,
    /// How many non-expired providers the answering node holds a record for.
    pub providers: usize,
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
    // Relay-resolved dialable candidate address(es) for this peer, IPv6-first (§5.2) — the relay
    // substitutes the observed reflexive IP for any unspecified/loopback/private advertised
    // `listen_addr` host (keeping the port). Additive since protocol v1 (NC-6 soft-fork): appended
    // LAST, default-empty + skip-when-empty. Byte-identical to dig-relay-protocol 0.2.0.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<SocketAddr>,
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
            addresses: Vec::new(),
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
