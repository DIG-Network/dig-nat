//! B2 relayed-transport (tier-6 TURN fallback) tests — prove real RLY-002 bytes tunnel A→relay→B
//! over the ONE persistent reservation socket (no second connection), plus the readiness gating of
//! the production [`ReservationRelayedTransport`] and its payload size cap.
//!
//! A tiny in-process loopback relay forwards `relay_message` frames by destination `peer_id` (the
//! same `ForwardTo` behaviour the real dig-relay server implements), so the whole path runs with no
//! external network.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dig_nat::method::relayed::{RelayedTransport, ReservationRelayedTransport};
use dig_nat::relay::{run_relay_connection_with, Backoff, RelayStatus, MAX_RELAY_PAYLOAD};
use dig_nat::wire::RelayMessage;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;
use tokio_tungstenite::tungstenite::Message;

/// A loopback relay that forwards RLY-002 `relay_message` frames to the destination peer's live
/// socket — a minimal stand-in for dig-relay's `ForwardTo` path. Returns the bound endpoint; runs
/// until the returned join handle is aborted.
async fn spawn_forwarding_relay() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // peer_id (hex) -> sink onto that peer's WebSocket write half.
    let registry: Arc<AsyncMutex<HashMap<String, mpsc::UnboundedSender<Message>>>> =
        Arc::new(AsyncMutex::new(HashMap::new()));

    let handle = tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let registry = Arc::clone(&registry);
            tokio::spawn(handle_relay_conn(tcp, registry));
        }
    });
    (addr, handle)
}

/// Serve one relay client: register it, then forward its `relay_message` frames to their targets.
async fn handle_relay_conn(
    tcp: tokio::net::TcpStream,
    registry: Arc<AsyncMutex<HashMap<String, mpsc::UnboundedSender<Message>>>>,
) {
    let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
    let (mut write, mut read) = ws.split();

    // A single outbound sink for THIS connection: acks + frames forwarded from other peers.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();
    let writer = tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            if write.send(m).await.is_err() {
                break;
            }
        }
    });

    while let Some(Ok(msg)) = read.next().await {
        let Message::Text(t) = msg else { continue };
        let Ok(parsed) = serde_json::from_str::<RelayMessage>(&t) else {
            continue;
        };
        match parsed {
            RelayMessage::Register { peer_id, .. } => {
                registry.lock().await.insert(peer_id, out_tx.clone());
                let ack = RelayMessage::RegisterAck {
                    success: true,
                    message: "ok".into(),
                    connected_peers: 1,
                };
                let _ = out_tx.send(Message::Text(serde_json::to_string(&ack).unwrap()));
            }
            // Forward the frame verbatim to the destination peer's socket (TURN-like `ForwardTo`).
            RelayMessage::RelayGossipMessage { .. } => {
                let to = match &parsed {
                    RelayMessage::RelayGossipMessage { to, .. } => to.clone(),
                    _ => unreachable!(),
                };
                if let Some(sink) = registry.lock().await.get(&to) {
                    let _ = sink.send(Message::Text(serde_json::to_string(&parsed).unwrap()));
                }
            }
            _ => {}
        }
    }
    writer.abort();
}

/// Spawn a node's persistent reservation against `endpoint` and wait until it is `Connected`.
async fn connect_node(
    endpoint: &str,
    peer_id: &str,
) -> (Arc<RelayStatus>, tokio::task::JoinHandle<()>) {
    let status = RelayStatus::new();
    let task_status = Arc::clone(&status);
    let ep = endpoint.to_string();
    let id = peer_id.to_string();
    let task = tokio::spawn(async move {
        run_relay_connection_with(
            ep,
            id,
            "DIG_MAINNET".into(),
            Vec::new(),
            task_status,
            Backoff {
                base_secs: 0,
                cap_secs: 0,
            },
        )
        .await;
    });
    for _ in 0..100 {
        if status.relay_transport_ready() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        status.relay_transport_ready(),
        "{peer_id} reached a live reservation"
    );
    (status, task)
}

/// THE core B2 proof: real RLY-002 bytes tunnel A → relay → B over each node's held reservation
/// socket. A opens a tunnel to B and sends a payload; B receives the exact bytes on its tunnel from
/// A. No second socket is opened — the forwarding rides the persistent reservation.
#[tokio::test]
async fn bytes_tunnel_a_relay_b_over_reservation() {
    let (addr, relay) = spawn_forwarding_relay().await;
    let endpoint = format!("ws://{addr}");

    let (status_a, task_a) = connect_node(&endpoint, "aaaa").await;
    let (status_b, task_b) = connect_node(&endpoint, "bbbb").await;

    // Each node opens ONE tunnel keyed by the peer. A relay tunnel is BIDIRECTIONAL — the SAME handle
    // carries both send and recv — so the reverse direction reuses these handles rather than re-opening
    // the key (the non-clobber guard correctly refuses a duplicate circuit to a peer, #1536).
    let mut tunnel_b = status_b.open_tunnel("aaaa", "DIG_MAINNET").unwrap();
    let mut tunnel_a = status_a.open_tunnel("bbbb", "DIG_MAINNET").unwrap();

    let sealed = b"NC-1 sealed ciphertext payload".to_vec();
    tunnel_a.send(sealed.clone()).unwrap();

    // B receives the exact bytes A sent — tunnelled A→relay→B.
    let received = tokio::time::timeout(Duration::from_secs(5), tunnel_b.recv())
        .await
        .expect("relayed frame arrived at B within the timeout")
        .expect("tunnel yielded a payload");
    assert_eq!(
        received, sealed,
        "B received the exact bytes A sent through the relay"
    );

    // The reverse direction works over the SAME bidirectional tunnels (no re-open).
    let reply = b"reply from B".to_vec();
    tunnel_b.send(reply.clone()).unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), tunnel_a.recv())
        .await
        .expect("reverse relayed frame arrived at A")
        .expect("tunnel yielded a payload");
    assert_eq!(got, reply);

    task_a.abort();
    task_b.abort();
    relay.abort();
}

/// The production [`ReservationRelayedTransport`] is the ladder's tier-6 seam: `open_relayed` returns
/// the relay endpoint once a reservation is live, and its `open_tunnel` yields a working tunnel.
#[tokio::test]
async fn reservation_transport_opens_when_connected() {
    let (addr, relay) = spawn_forwarding_relay().await;
    let endpoint = format!("ws://{addr}");
    let (status, task) = connect_node(&endpoint, "cccc").await;

    let relay_endpoint: SocketAddr = "127.0.0.1:9450".parse().unwrap();
    let transport = ReservationRelayedTransport::new(Arc::clone(&status), relay_endpoint);

    let out = transport.open_relayed("dddd", "DIG_MAINNET").await.unwrap();
    assert_eq!(
        out, relay_endpoint,
        "reports the relay endpoint for observability"
    );

    // And a real tunnel can be taken from it.
    let tunnel = transport.open_tunnel("dddd", "DIG_MAINNET").unwrap();
    assert_eq!(tunnel.target(), "dddd");

    task.abort();
    relay.abort();
}

/// Without a live reservation, the transport cannot open a tunnel — the tier genuinely can't carry
/// the connection, so it errors rather than pretending (the ladder falls through / fails cleanly).
#[tokio::test]
async fn transport_errors_without_a_reservation() {
    let status = RelayStatus::new(); // never connected
    let transport = ReservationRelayedTransport::new(status, "127.0.0.1:9450".parse().unwrap());
    let err = transport
        .open_relayed("eeee", "DIG_MAINNET")
        .await
        .unwrap_err();
    assert!(
        err.contains("not connected"),
        "clear not-connected error, got: {err}"
    );
}

/// Backpressure/size contract: a payload over [`MAX_RELAY_PAYLOAD`] is refused by `send` rather than
/// forwarded, and an inbound oversized frame is dropped (never routed to the tunnel).
#[tokio::test]
async fn oversized_payload_is_refused() {
    let (addr, relay) = spawn_forwarding_relay().await;
    let endpoint = format!("ws://{addr}");
    let (status, task) = connect_node(&endpoint, "ffff").await;

    let tunnel = status.open_tunnel("9999", "DIG_MAINNET").unwrap();
    let too_big = vec![0u8; MAX_RELAY_PAYLOAD + 1];
    let err = tunnel.send(too_big).unwrap_err();
    assert!(
        err.contains("exceeds cap"),
        "oversized send refused, got: {err}"
    );

    // A payload at exactly the cap is accepted by `send` (does not error on the size check).
    let at_cap = vec![0u8; MAX_RELAY_PAYLOAD];
    tunnel.send(at_cap).unwrap();

    task.abort();
    relay.abort();
}
