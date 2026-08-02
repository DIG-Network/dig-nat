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
        // RLY-009 (dig_ecosystem #1935) — pinned like every other discriminator, because the relay
        // server, dig-gossip and dig-node all carry a vendored copy of this enum and must agree.
        (
            RelayMessage::GetDhtRecords { max_keys: 8 },
            "get_dht_records",
        ),
        (
            RelayMessage::DhtRecords {
                records: vec![],
                total_keys: 0,
                truncated: false,
            },
            "dht_records",
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

// -- RangeFrame `bytes` — base64, the canonical `dig.fetchRange` frame wire (#1586) ---------------

/// A `dig.fetchRange` frame as the CANONICAL producer serves it: `bytes` is a **base64 string**
/// (`dig_rpc_protocol::types::RangeFrame` — "this window's ciphertext, base64"; the dig-node peer
/// serve path emits exactly this shape). dig-nat's [`RangeFrame`] MUST decode it to the raw
/// ciphertext.
///
/// Regression for the #1586 read-leg blocker: `bytes` was declared `#[serde(with = "serde_bytes")]`,
/// which over JSON reads a string as its literal UTF-8 characters — so a 1-byte window arrived as the
/// 4 characters of its base64 (`"AA=="`), the reassembler rejected the frame with "range frame
/// overflows expected length 1", and the download aborted before any bytes were read.
#[test]
fn range_frame_bytes_decode_from_the_canonical_base64_wire() {
    let wire = serde_json::json!({
        "offset": 0,
        "length": 3,
        "bytes": "AAEC",
        "complete": true,
        "total_length": 3,
        "chunk_lens": [3],
        "chunk_index": 0,
        "root": "ab".repeat(32),
    });
    let frame: dig_nat::RangeFrame = serde_json::from_value(wire).expect("canonical frame decodes");
    assert_eq!(
        frame.bytes,
        vec![0u8, 1, 2],
        "`bytes` is base64 of the ciphertext window, not its literal characters"
    );
    assert_eq!(frame.total_length, Some(3));
}

/// The frame SERIALIZES back to the same canonical base64-string wire, so a dig-nat-produced frame is
/// interchangeable with the node's hand-built one (one wire, both directions).
#[test]
fn range_frame_bytes_serialize_as_base64() {
    let frame = dig_nat::RangeFrame::data(0, vec![0, 1, 2]).with_complete(true);
    let v = serde_json::to_value(&frame).expect("frame serializes");
    assert_eq!(v["bytes"], serde_json::json!("AAEC"));
    let back: dig_nat::RangeFrame = serde_json::from_value(v).expect("round-trips");
    assert_eq!(back, frame);
}

/// Backwards compatibility: a frame produced by an OLDER dig-nat (`bytes` as a JSON byte ARRAY) still
/// decodes — the reader is tolerant of both encodings, so a mixed-version peer is never dropped.
#[test]
fn range_frame_bytes_still_decode_from_the_legacy_array_wire() {
    let wire = serde_json::json!({
        "offset": 0, "length": 3, "bytes": [0, 1, 2], "complete": true,
    });
    let frame: dig_nat::RangeFrame = serde_json::from_value(wire).expect("legacy frame decodes");
    assert_eq!(frame.bytes, vec![0u8, 1, 2]);
}

/// §5.1 backwards compatibility for the 0.13.0 prologue fields: a NEWER reader parses an OLDER message
/// with each new field absent, and a message that sets none of them serializes byte-identically to the
/// 0.12.0 wire. Both directions matter — a mixed-version peer must never be dropped for a field it does
/// not know about.
#[test]
fn the_prologue_fields_are_additive_in_both_directions() {
    // An older sender's frame: no chunk_count, no chunk_lens_offset.
    let old_wire = serde_json::json!({
        "offset": 0, "length": 3, "bytes": "AAEC", "complete": true,
        "total_length": 3, "chunk_lens": [3], "chunk_index": 0, "root": "ab".repeat(32),
    });
    let parsed: dig_nat::RangeFrame =
        serde_json::from_value(old_wire).expect("a 0.12.0 frame must still decode");
    assert_eq!(parsed.chunk_count, None);
    assert_eq!(parsed.chunk_lens_offset, None);

    // And a frame that sets neither omits them entirely, so an older reader sees its own wire.
    let plain = serde_json::to_value(dig_nat::RangeFrame::data(0, vec![0, 1, 2])).unwrap();
    assert!(plain.get("chunk_count").is_none());
    assert!(plain.get("chunk_lens_offset").is_none());

    // Same for the request field.
    let old_req = serde_json::json!({ "store_id": "ab".repeat(32), "length": 16 });
    let req: dig_nat::RangeRequest =
        serde_json::from_value(old_req).expect("a 0.12.0 request must still decode");
    assert_eq!(req.skip_layout, None);
    assert!(
        serde_json::to_value(dig_nat::RangeRequest::capsule("ab".repeat(32), 0, 16))
            .unwrap()
            .get("skip_layout")
            .is_none()
    );
}

/// The prologue fields carry their values across the wire under the field names `SPEC.md` publishes —
/// a paged frame is located by `chunk_lens_offset` against a total of `chunk_count`, and a client that
/// already holds the layout says so with `skip_layout`.
#[test]
fn a_paged_prologue_frame_round_trips_under_the_published_field_names() {
    let page = dig_nat::RangeFrame::data(4096, vec![7, 7, 7])
        .with_identity("cd".repeat(32), 1_000_000, 4_000)
        .with_chunk_lens_page(2_048, vec![262_144; 3])
        .with_chunk_index(2_048)
        .with_inclusion_proof("cHJvb2Y=");

    let v = serde_json::to_value(&page).expect("frame serializes");
    assert_eq!(v["chunk_count"], 4_000);
    assert_eq!(v["chunk_lens_offset"], 2_048);
    assert_eq!(v["root"], "cd".repeat(32));
    assert_eq!(
        serde_json::from_value::<dig_nat::RangeFrame>(v).expect("frame round-trips"),
        page
    );

    let req = dig_nat::RangeRequest::resource("ab".repeat(32), "cd".repeat(32), 0, 16)
        .with_root("ef".repeat(32))
        .with_skip_layout(true);
    let rv = serde_json::to_value(&req).expect("request serializes");
    assert_eq!(rv["skip_layout"], true);
    assert_eq!(rv["root"], "ef".repeat(32));
    assert_eq!(
        serde_json::from_value::<dig_nat::RangeRequest>(rv).expect("request round-trips"),
        req
    );
}

/// An availability answer built through its constructors carries every optional field under its
/// published name, and `unavailable()` states exactly one thing — no other field is meaningful when the
/// peer does not hold the item.
#[test]
fn availability_answers_serialize_under_the_published_field_names() {
    let held = dig_nat::AvailabilityAnswer::available()
        .with_roots(vec!["ab".repeat(32)])
        .with_total_length(4_096)
        .with_chunk_count(2)
        .with_complete(true);
    let v = serde_json::to_value(&held).expect("answer serializes");
    assert_eq!(v["available"], true);
    assert_eq!(v["roots"][0], "ab".repeat(32));
    assert_eq!(v["total_length"], 4_096);
    assert_eq!(v["chunk_count"], 2);
    assert_eq!(v["complete"], true);

    let missing = serde_json::to_value(dig_nat::AvailabilityAnswer::unavailable()).unwrap();
    assert_eq!(missing["available"], false);
    assert_eq!(missing.as_object().map(serde_json::Map::len), Some(1));

    let item = serde_json::to_value(
        dig_nat::AvailabilityItem::store("ab".repeat(32)).with_retrieval_key("cd".repeat(32)),
    )
    .unwrap();
    assert_eq!(item["retrieval_key"], "cd".repeat(32));
    assert!(item.get("root").is_none(), "an unset root is omitted");
}

/// A chunk-aligned CONTINUATION frame states its `chunk_index` and carries NO prologue set — the shape
/// `SPEC.md` §5.1.1 requires of every frame after the first.
///
/// `chunk_index` used to be settable only as a parameter of `with_inclusion_proof`, so this shape was
/// unreachable through the API: a caller had to repeat a once-per-stream proof (a §5.1.1 MUST NOT, and
/// 4,096 B per frame against a budget with zero slack) or reach around the constructors and assign the
/// public field. It is the ONE field every reader wants on every frame, so the API had to express it
/// alone. The assertions below are on the absent fields as much as the present one: stating alignment
/// must not drag the resource-scaling set along with it.
#[test]
fn a_chunk_aligned_continuation_frame_states_its_index_without_a_proof() {
    let continuation = dig_nat::RangeFrame::data(32_768, vec![4, 5, 6])
        .with_identity("ab".repeat(32), 1_000_000, 4_000)
        .with_chunk_index(512);

    assert_eq!(continuation.chunk_index, Some(512));
    assert_eq!(
        continuation.inclusion_proof, None,
        "a continuation frame must be able to state alignment WITHOUT repeating the proof"
    );
    assert_eq!(continuation.chunk_lens, None);
    assert_eq!(continuation.chunk_lens_offset, None);

    let v = serde_json::to_value(&continuation).expect("frame serializes");
    assert_eq!(v["chunk_index"], 512);
    assert!(v.get("inclusion_proof").is_none());
    assert!(v.get("chunk_lens").is_none());
    assert!(
        continuation.encode().is_ok(),
        "the identity-only continuation shape must encode"
    );
}

/// RLY-009 field names are the wire contract, same as `relay_peer_info_field_names` (#1935).
#[test]
fn dht_records_field_names() {
    let msg = RelayMessage::DhtRecords {
        records: vec![dig_nat::wire::DhtRecordEntry {
            content_key: "ab".repeat(32),
            providers: 3,
        }],
        total_keys: 7,
        truncated: true,
    };
    let v = serde_json::to_value(&msg).unwrap();
    assert_eq!(v["type"], "dht_records");
    for key in ["records", "total_keys", "truncated"] {
        assert!(v.get(key).is_some(), "missing `{key}`");
    }
    let entry = &v["records"][0];
    for key in ["content_key", "providers"] {
        assert!(entry.get(key).is_some(), "missing entry `{key}`");
    }

    // The privacy property, asserted on the SERIALIZED bytes: a provider record is a
    // (peer_id, content_key) pair, and RLY-009 must publish only the count. If an identity field is
    // ever added to the entry this fails, which is the point.
    let raw = serde_json::to_string(&msg).unwrap();
    assert!(
        !raw.contains("peer_id"),
        "RLY-009 must never carry a provider identity: {raw}"
    );
}

/// A request pins its own field name too — the relay depends on `max_keys` to bound the answer.
#[test]
fn get_dht_records_carries_the_bound() {
    let v = serde_json::to_value(RelayMessage::GetDhtRecords { max_keys: 128 }).unwrap();
    assert_eq!(v["type"], "get_dht_records");
    assert_eq!(v["max_keys"], 128);
}
