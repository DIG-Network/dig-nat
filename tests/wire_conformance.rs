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
        listen_addrs: vec![],
    };
    let v = serde_json::to_value(&m).unwrap();
    assert_eq!(v["type"], "register");
    assert_eq!(v["peer_id"], "abc");
    assert_eq!(v["network_id"], "DIG_MAINNET");
    assert_eq!(v["protocol_version"], 1);
    // B1 (additive, NC-6 soft-fork): an EMPTY `listen_addrs` is SKIPPED from the wire, keeping the
    // frame byte-identical to a pre-#924 peer's `register`.
    assert!(
        v.get("listen_addrs").is_none(),
        "empty listen_addrs must not appear on the wire"
    );
}

/// B1 wire: a non-empty `Register.listen_addrs` serializes under the exact `listen_addrs` key (the
/// advertised gossip listen candidates, IPv6-first) and round-trips, while an OLD relay's `register`
/// lacking the field still parses (serde default) — the soft-fork guarantee.
#[test]
fn register_listen_addrs_roundtrips_and_is_backward_compatible() {
    let m = RelayMessage::Register {
        peer_id: "abc".into(),
        network_id: "DIG_MAINNET".into(),
        protocol_version: 1,
        listen_addrs: vec![
            "[::]:9445".parse().unwrap(),
            "0.0.0.0:9445".parse().unwrap(),
        ],
    };
    let v = serde_json::to_value(&m).unwrap();
    assert_eq!(v["listen_addrs"][0], "[::]:9445");
    assert_eq!(v["listen_addrs"][1], "0.0.0.0:9445");

    // An old peer's register (no listen_addrs) still parses — the field defaults to empty.
    let raw =
        r#"{"type":"register","peer_id":"p","network_id":"DIG_MAINNET","protocol_version":1}"#;
    match serde_json::from_str::<RelayMessage>(raw).unwrap() {
        RelayMessage::Register { listen_addrs, .. } => assert!(listen_addrs.is_empty()),
        other => panic!("expected Register, got {other:?}"),
    }
}

/// B1 wire: `RelayPeerInfo.addresses` (the relay-resolved dialable candidates) serializes under the
/// `addresses` key when present and is SKIPPED when empty; an old relay's peer info still parses.
#[test]
fn relay_peer_info_addresses_roundtrips_and_is_backward_compatible() {
    // Empty → skipped (byte-identical to a pre-#924 relay's peer info).
    let empty = RelayPeerInfo::new("p".into(), "DIG_MAINNET".into(), 1);
    let v = serde_json::to_value(&empty).unwrap();
    assert!(
        v.get("addresses").is_none(),
        "empty addresses must not appear on the wire"
    );

    // Populated → present under `addresses`.
    let mut info = RelayPeerInfo::new("p".into(), "DIG_MAINNET".into(), 1);
    info.addresses = vec!["[2001:db8::1]:9445".parse().unwrap()];
    let v = serde_json::to_value(&info).unwrap();
    assert_eq!(v["addresses"][0], "[2001:db8::1]:9445");

    // An old relay's peer info (no addresses) still parses — defaults to empty.
    let raw = r#"{"peer_id":"p","network_id":"DIG_MAINNET","protocol_version":1,"connected_at":1,"last_seen":2}"#;
    let parsed: RelayPeerInfo = serde_json::from_str(raw).unwrap();
    assert!(parsed.addresses.is_empty());
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
