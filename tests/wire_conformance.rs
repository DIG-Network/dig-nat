//! Wire conformance — pins the vendored [`RelayMessage`] serde shape byte-identical to the
//! `dig-relay` server / `dig-node` client / `dig-gossip` canonical wire (RLY-001..007). If any
//! discriminator or field name drifts, these fail — the shared-contract guard.

use dig_nat::wire::{RelayMessage, RelayPeerInfo};

#[test]
fn register_discriminator_and_fields() {
    let m = RelayMessage::Register {
        peer_id: "abc".into(),
        network_id: "DIG_MAINNET".into(),
        protocol_version: 1,
    };
    let v = serde_json::to_value(&m).unwrap();
    assert_eq!(v["type"], "register");
    assert_eq!(v["peer_id"], "abc");
    assert_eq!(v["network_id"], "DIG_MAINNET");
    assert_eq!(v["protocol_version"], 1);
}

#[test]
fn register_ack_parses_server_json() {
    // Exactly as the dig-relay server emits it.
    let raw =
        r#"{"type":"register_ack","success":true,"message":"registered","connected_peers":3}"#;
    let m: RelayMessage = serde_json::from_str(raw).unwrap();
    match m {
        RelayMessage::RegisterAck {
            success,
            connected_peers,
            ..
        } => {
            assert!(success);
            assert_eq!(connected_peers, 3);
        }
        other => panic!("expected RegisterAck, got {other:?}"),
    }
}

#[test]
fn hole_punch_wire_discriminators() {
    let coord = RelayMessage::HolePunchCoordinate {
        peer_id: "p".into(),
        external_addr: "203.0.113.5:5555".parse().unwrap(),
    };
    let v = serde_json::to_value(&coord).unwrap();
    assert_eq!(v["type"], "hole_punch_coordinate");
    assert_eq!(v["peer_id"], "p");
    assert_eq!(v["external_addr"], "203.0.113.5:5555");
}

#[test]
fn all_discriminators_present() {
    // Lock every RLY-00x `type` string so none silently changes.
    let cases: Vec<(RelayMessage, &str)> = vec![
        (
            RelayMessage::Unregister {
                peer_id: "p".into(),
            },
            "unregister",
        ),
        (RelayMessage::GetPeers { network_id: None }, "get_peers"),
        (RelayMessage::Ping { timestamp: 1 }, "ping"),
        (RelayMessage::Pong { timestamp: 1 }, "pong"),
        (RelayMessage::Peers { peers: vec![] }, "peers"),
        (
            RelayMessage::Error {
                code: 1,
                message: "x".into(),
            },
            "error",
        ),
    ];
    for (msg, expected) in cases {
        assert_eq!(serde_json::to_value(&msg).unwrap()["type"], expected);
    }
}

#[test]
fn relay_peer_info_field_names() {
    let info = RelayPeerInfo::new("p".into(), "DIG_MAINNET".into(), 1);
    let v = serde_json::to_value(&info).unwrap();
    // Field names are the wire contract.
    for key in [
        "peer_id",
        "network_id",
        "protocol_version",
        "connected_at",
        "last_seen",
    ] {
        assert!(v.get(key).is_some(), "missing wire field {key}");
    }
}
