//! PeerConnection mux passthroughs over a real loopback session, plus construction of the
//! production UPnP method — lifts coverage of the thin passthrough + constructor surface with no
//! network.

use dig_nat::method::upnp::{RealIgd, RealUpnpMethod};
use dig_nat::method::{TraversalKind, TraversalMethod};
use dig_nat::mux::{PeerSession, RangeRequest};
use dig_nat::peer::PeerConnection;
use dig_nat::PeerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Build a PeerConnection wrapping the client half of a loopback session; keep the server half
/// draining so the link stays open.
fn loopback_conn() -> (PeerConnection, tokio::task::JoinHandle<()>) {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let client = PeerSession::client(a);
    let mut server = PeerSession::server(b);
    let handle = tokio::spawn(async move {
        // Echo any bytes on each accepted stream (so open_stream round-trips).
        while let Some(mut s) = server.accept_stream().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let _ = s.read_to_end(&mut buf).await;
                let _ = s.write_all(&buf).await;
                let _ = s.shutdown().await;
            });
        }
    });
    let conn = PeerConnection {
        peer_id: PeerId::from_bytes([3u8; 32]),
        method: TraversalKind::Direct,
        remote_addr: "127.0.0.1:1".parse().unwrap(),
        session: client,
    };
    (conn, handle)
}

/// `PeerConnection::open_stream` opens a working logical stream (round-trips through the echo server).
#[tokio::test]
async fn peer_connection_open_stream_passthrough() {
    let (mut conn, _srv) = loopback_conn();
    let mut s = conn.open_stream().await.unwrap();
    s.write_all(b"ping").await.unwrap();
    s.shutdown().await.unwrap();
    let mut back = Vec::new();
    s.read_to_end(&mut back).await.unwrap();
    assert_eq!(back, b"ping");
}

/// `PeerConnection::open_range_stream` writes the range preamble (the echo server returns it verbatim).
#[tokio::test]
async fn peer_connection_open_range_stream_passthrough() {
    let (mut conn, _srv) = loopback_conn();
    let req = RangeRequest::resource("00".repeat(32), "11".repeat(32), 0, 8);
    let mut s = conn.open_range_stream(&req).await.unwrap();
    s.shutdown().await.unwrap();
    // The echo server returns the preamble bytes; decoding them back yields the same request.
    let decoded = RangeRequest::decode(&mut s).await.unwrap();
    assert_eq!(decoded, req);
}

/// The production UPnP method + RealIgd construct cleanly (their live SSDP call is integration-only).
#[test]
fn real_upnp_method_constructs() {
    let m: RealUpnpMethod = RealUpnpMethod::real(9444);
    assert_eq!(m.kind(), TraversalKind::Upnp);
    assert_eq!(m.local_port, 9444);
    let _default = RealIgd::default();
}

/// The PeerConnection Debug impl renders without exposing the stream internals.
#[tokio::test]
async fn peer_connection_debug_is_safe() {
    let (conn, _srv) = loopback_conn();
    let s = format!("{conn:?}");
    assert!(s.contains("PeerConnection"));
    assert!(s.contains("Direct"));
}
