//! Multiplexing + byte-range + availability transport tests over a real (in-memory) yamux session
//! pair — no network. Conforms to the L7 peer-network spec shapes (`dig.getAvailability`,
//! `dig.fetchRange` + `RangeFrame`). Proves: concurrent streams on one connection, a range stream
//! delivers exactly [offset,len) as streamed frames, many range streams across peers run
//! concurrently + reassemble, and the availability pre-check.

use std::sync::Arc;

use dig_nat::mux::{
    AvailabilityAnswer, AvailabilityItem, AvailabilityRequest, AvailabilityResponse, PeerSession,
    RangeFrame, RangeRequest,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Build a connected client/server session pair over an in-memory duplex.
fn pair() -> (PeerSession, PeerSession) {
    let (a, b) = tokio::io::duplex(1024 * 1024);
    (PeerSession::client(a), PeerSession::server(b))
}

/// Two logical streams over ONE connection carry independent data concurrently (multiplexing works,
/// no head-of-line blocking between them).
#[tokio::test]
async fn concurrent_streams_on_one_connection() {
    let (mut client, mut server) = pair();

    tokio::spawn(async move {
        while let Some(mut s) = server.accept_stream().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let _ = s.read_to_end(&mut buf).await;
                let upper: Vec<u8> = buf.iter().map(|b| b.to_ascii_uppercase()).collect();
                let _ = s.write_all(&upper).await;
                let _ = s.shutdown().await;
            });
        }
    });

    let mut s1 = client.open_stream().await.unwrap();
    let mut s2 = client.open_stream().await.unwrap();
    s1.write_all(b"hello").await.unwrap();
    s1.shutdown().await.unwrap();
    s2.write_all(b"world").await.unwrap();
    s2.shutdown().await.unwrap();

    let mut r1 = Vec::new();
    let mut r2 = Vec::new();
    s1.read_to_end(&mut r1).await.unwrap();
    s2.read_to_end(&mut r2).await.unwrap();
    assert_eq!(r1, b"HELLO");
    assert_eq!(r2, b"WORLD");
}

/// A range stream carries the RangeRequest preamble; the server streams back RangeFrames covering
/// EXACTLY [offset,len). The client reassembles from frames and gets exactly the requested bytes.
#[tokio::test]
async fn range_stream_delivers_exact_range_as_frames() {
    // A resource: 256 bytes 0..=255.
    let resource: Arc<Vec<u8>> = Arc::new((0u8..=255).collect());
    let (mut client, mut server) = pair();

    let res = resource.clone();
    tokio::spawn(async move {
        while let Some(mut s) = server.accept_stream().await {
            let res = res.clone();
            tokio::spawn(async move {
                let req = RangeRequest::decode(&mut s).await.unwrap();
                let start = req.offset as usize;
                let end = start + req.length as usize;
                // Stream the range as two frames to exercise multi-frame reassembly.
                let mid = start + (end - start) / 2;
                let f1 = RangeFrame {
                    offset: 0,
                    length: (mid - start) as u64,
                    bytes: res[start..mid].to_vec(),
                    complete: false,
                    total_length: Some(res.len() as u64),
                    chunk_lens: Some(vec![res.len() as u64]),
                    chunk_index: Some(0),
                    inclusion_proof: Some("cHJvb2Y=".into()),
                    root: Some("00".repeat(32)),
                };
                let f2 = RangeFrame {
                    offset: (mid - start) as u64,
                    length: (end - mid) as u64,
                    bytes: res[mid..end].to_vec(),
                    complete: true,
                    total_length: None,
                    chunk_lens: None,
                    chunk_index: None,
                    inclusion_proof: None,
                    root: None,
                };
                let _ = s.write_all(&f1.encode()).await;
                let _ = s.write_all(&f2.encode()).await;
                let _ = s.shutdown().await;
            });
        }
    });

    // Ask for bytes [100, 100+16).
    let req = RangeRequest::resource("00".repeat(32), "11".repeat(32), 100, 16);
    let mut stream = client.open_range_stream(&req).await.unwrap();

    let mut assembled = Vec::new();
    let mut first = true;
    while let Some(frame) = RangeFrame::decode(&mut stream).await.unwrap() {
        if first {
            // First frame carries verification metadata.
            assert_eq!(frame.total_length, Some(256));
            assert!(frame.inclusion_proof.is_some());
            assert_eq!(frame.chunk_index, Some(0));
            first = false;
        }
        assert_eq!(
            frame.offset as usize,
            assembled.len(),
            "frames tile in order"
        );
        assembled.extend_from_slice(&frame.bytes);
        if frame.complete {
            break;
        }
    }
    assert_eq!(assembled.len(), 16);
    assert_eq!(assembled, (100u8..116).collect::<Vec<u8>>());
}

/// Many range streams across TWO peers (two holders) run concurrently and reassemble into the whole
/// resource — the multi-source parallel download pattern.
#[tokio::test]
async fn concurrent_range_fetches_across_peers_reassemble() {
    let full: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();

    let make_holder = |content: Vec<u8>| {
        let (client, mut server) = pair();
        let content = Arc::new(content);
        tokio::spawn(async move {
            while let Some(mut s) = server.accept_stream().await {
                let content = content.clone();
                tokio::spawn(async move {
                    let req = RangeRequest::decode(&mut s).await.unwrap();
                    let start = req.offset as usize;
                    let end = start + req.length as usize;
                    let frame = RangeFrame {
                        offset: 0,
                        length: (end - start) as u64,
                        bytes: content[start..end].to_vec(),
                        complete: true,
                        total_length: Some(content.len() as u64),
                        chunk_lens: Some(vec![content.len() as u64]),
                        chunk_index: Some(0),
                        inclusion_proof: Some("cHJvb2Y=".into()),
                        root: Some("00".repeat(32)),
                    };
                    let _ = s.write_all(&frame.encode()).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        client
    };
    let mut holder_a = make_holder(full.clone());
    let mut holder_b = make_holder(full.clone());

    let half = (full.len() / 2) as u64;
    let sid = "00".repeat(32);
    let rk = "11".repeat(32);
    let req_a = RangeRequest::resource(sid.clone(), rk.clone(), 0, half);
    let req_b = RangeRequest::resource(sid, rk, half, full.len() as u64 - half);
    let mut sa = holder_a.open_range_stream(&req_a).await.unwrap();
    let mut sb = holder_b.open_range_stream(&req_b).await.unwrap();

    // Read both concurrently.
    async fn read_all(stream: &mut dig_nat::mux::PeerStream) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(f) = RangeFrame::decode(stream).await.unwrap() {
            out.extend_from_slice(&f.bytes);
            if f.complete {
                break;
            }
        }
        out
    }
    let (part_a, part_b) = tokio::join!(read_all(&mut sa), read_all(&mut sb));

    let mut reassembled = part_a;
    reassembled.extend_from_slice(&part_b);
    assert_eq!(
        reassembled, full,
        "ranges from two peers reassemble to the whole resource"
    );
}

/// The availability pre-check: the requester asks which items a peer holds at store/root/resource
/// granularity; the holder answers per-item positionally.
#[tokio::test]
async fn availability_precheck_reports_per_item() {
    let (mut client, mut server) = pair();

    tokio::spawn(async move {
        while let Some(mut s) = server.accept_stream().await {
            tokio::spawn(async move {
                let req = AvailabilityRequest::decode(&mut s).await.unwrap();
                // Holds store "aa", but not root "bb"+"cc".
                let answers = req
                    .items
                    .iter()
                    .map(|item| {
                        let has = item.store_id == "aa".repeat(32);
                        AvailabilityAnswer {
                            available: has && item.root.is_none(),
                            roots: if has && item.root.is_none() {
                                Some(vec!["dd".repeat(32)])
                            } else {
                                None
                            },
                            total_length: None,
                            chunk_count: None,
                            complete: None,
                        }
                    })
                    .collect();
                let resp = AvailabilityResponse { items: answers };
                let _ = s.write_all(&resp.encode()).await;
                let _ = s.shutdown().await;
            });
        }
    });

    let resp = client
        .query_availability(vec![
            AvailabilityItem {
                store_id: "aa".repeat(32),
                root: None,
                retrieval_key: None,
            },
            AvailabilityItem {
                store_id: "bb".repeat(32),
                root: Some("cc".repeat(32)),
                retrieval_key: None,
            },
        ])
        .await
        .unwrap();
    assert_eq!(resp.items.len(), 2);
    assert!(resp.items[0].available);
    assert_eq!(resp.items[0].roots, Some(vec!["dd".repeat(32)]));
    assert!(!resp.items[1].available);
}

/// Framing round-trips byte-for-byte, and the spec JSON field names/discriminators are exact.
#[tokio::test]
async fn framed_messages_round_trip_and_match_spec_shape() {
    let req = RangeRequest {
        store_id: "aa".repeat(32),
        retrieval_key: Some("bb".repeat(32)),
        root: None,
        capsule: false,
        offset: 42,
        length: 4096,
    };
    let mut cursor = std::io::Cursor::new(req.encode());
    assert_eq!(RangeRequest::decode(&mut cursor).await.unwrap(), req);

    // Spec field names: store_id, retrieval_key, offset, length; `capsule:false`/`root:None` omitted.
    let v = serde_json::to_value(&req).unwrap();
    assert_eq!(v["store_id"], "aa".repeat(32));
    assert_eq!(v["offset"], 42);
    assert_eq!(v["length"], 4096);
    assert!(v.get("root").is_none(), "None root omitted");
    assert!(v.get("capsule").is_none(), "false capsule omitted");

    let avail = AvailabilityRequest {
        items: vec![AvailabilityItem {
            store_id: "aa".repeat(32),
            root: Some("bb".repeat(32)),
            retrieval_key: Some("cc".repeat(32)),
        }],
    };
    let mut c2 = std::io::Cursor::new(avail.encode());
    assert_eq!(AvailabilityRequest::decode(&mut c2).await.unwrap(), avail);
    let av = serde_json::to_value(&avail).unwrap();
    assert_eq!(av["items"][0]["store_id"], "aa".repeat(32));
    assert_eq!(av["items"][0]["retrieval_key"], "cc".repeat(32));
}
