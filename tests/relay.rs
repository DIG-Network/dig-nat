//! Relay client tests — status transitions, capped-exponential backoff, `DIG_RELAY_URL` resolution
//! plus `=off` opt-out, the canonical endpoint from dig-constants, and a loopback WebSocket relay
//! that the client registers with (plus graceful reconnect when the relay drops). No external network.

use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use dig_nat::relay::{
    backoff_secs, relay_enabled, relay_url_from_env, run_relay_connection_with, Backoff,
    RelayState, RelayStatus,
};
use dig_nat::wire::RelayMessage;
use dig_nat::wire::RelayPeerInfo;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

/// Serializes env-mutating tests so they don't race under the parallel runner.
static ENV_LOCK: StdMutex<()> = StdMutex::new(());

#[test]
fn backoff_is_capped_exponential() {
    assert_eq!(backoff_secs(0), 5);
    assert_eq!(backoff_secs(1), 10);
    assert_eq!(backoff_secs(2), 20);
    assert_eq!(backoff_secs(3), 40);
    assert_eq!(backoff_secs(20), 300, "capped");
    assert_eq!(backoff_secs(64), 300, "overflow saturates to cap");
}

#[test]
fn status_transitions_and_snapshot() {
    let s = RelayStatus::new();
    assert_eq!(s.state(), RelayState::Disconnected);
    assert!(!s.is_connected());

    s.set_connecting();
    assert_eq!(s.state(), RelayState::Connecting);

    s.set_connected(7);
    assert!(s.is_connected());
    let v = s.snapshot_json("wss://relay.dig.net:9450", "pk");
    assert_eq!(v["state"], "connected");
    assert_eq!(v["connected"], true);
    assert_eq!(v["connected_peers"], 7);
    assert_eq!(v["reconnect_attempts"], 0);
    assert!(v["last_error"].is_null());

    s.set_disconnected(Some("read: reset".into()));
    let v = s.snapshot_json("e", "p");
    assert_eq!(v["state"], "disconnected");
    assert_eq!(v["reconnect_attempts"], 1);
    assert_eq!(v["last_error"], "read: reset");
}

#[test]
fn disabled_is_distinct_from_disconnected() {
    let s = RelayStatus::new();
    s.set_disabled();
    assert_eq!(s.state(), RelayState::Disabled);
    assert_eq!(s.snapshot_json("e", "p")["state"], "disabled");
}

#[test]
fn repeated_disconnects_count_but_stay_disconnected() {
    let s = RelayStatus::new();
    s.set_connecting();
    for i in 1..=5 {
        s.set_disconnected(Some(format!("attempt {i}")));
        assert_eq!(s.state(), RelayState::Disconnected);
        s.set_connecting();
    }
    assert_eq!(s.reconnect_attempts(), 5);
}

#[test]
fn env_off_opt_out_and_url_resolution() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    std::env::set_var("DIG_RELAY_URL", "off");
    assert!(!relay_enabled());
    std::env::set_var("DIG_RELAY_URL", "  DISABLED ");
    assert!(!relay_enabled(), "trimmed, case-insensitive");
    // When off/disabled, url resolution falls back to the canonical endpoint (never the token).
    assert_eq!(relay_url_from_env(), dig_constants::DIG_RELAY_URL);

    std::env::set_var("DIG_RELAY_URL", "ws://example:1234");
    assert!(relay_enabled());
    assert_eq!(relay_url_from_env(), "ws://example:1234");

    std::env::remove_var("DIG_RELAY_URL");
    assert!(relay_enabled());
    assert_eq!(relay_url_from_env(), dig_constants::DIG_RELAY_URL);
}

#[test]
fn default_endpoint_is_canonical() {
    assert_eq!(dig_constants::DIG_RELAY_URL, "wss://relay.dig.net:9450");
}

/// End-to-end: a loopback WebSocket relay accepts the client's Register (RLY-001) and replies with
/// RegisterAck → the client's RelayStatus goes Connected. Proves the connect+register handshake over
/// the real vendored wire.
#[tokio::test]
async fn client_registers_with_loopback_relay() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Minimal relay server: accept one WS conn, expect a Register, reply RegisterAck.
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        let (mut write, mut read) = ws.split();
        // First inbound frame should be a Register.
        if let Some(Ok(Message::Text(t))) = read.next().await {
            let msg: RelayMessage = serde_json::from_str(&t).unwrap();
            assert!(
                matches!(msg, RelayMessage::Register { .. }),
                "first frame is Register"
            );
            let ack = RelayMessage::RegisterAck {
                success: true,
                message: "registered".into(),
                connected_peers: 1,
            };
            write
                .send(Message::Text(serde_json::to_string(&ack).unwrap()))
                .await
                .unwrap();
        }
        // Keep the connection open briefly so the client observes Connected.
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let status = RelayStatus::new();
    let endpoint = format!("ws://{addr}");
    let task_status = Arc::clone(&status);
    let client = tokio::spawn(async move {
        run_relay_connection_with(
            endpoint,
            "peerhex".into(),
            "DIG_MAINNET".into(),
            task_status,
            // Fast backoff so the test never waits the production 5s.
            Backoff {
                base_secs: 0,
                cap_secs: 0,
            },
        )
        .await;
    });

    // Poll until Connected (the RegisterAck arrived).
    let mut connected = false;
    for _ in 0..50 {
        if status.is_connected() {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(connected, "client reached Connected after RegisterAck");

    client.abort();
    let _ = server.await;
}

/// Graceful fallback: pointing the client at a dead endpoint never panics/hangs — it just cycles
/// through Connecting→Disconnected and keeps retrying (bounded). We observe it reach Disconnected
/// with a recorded error and a bumped attempt count, then abort.
#[tokio::test]
async fn dead_relay_degrades_gracefully_without_crashing() {
    let status = RelayStatus::new();
    let task_status = Arc::clone(&status);
    // An address with nothing listening → connect fails immediately.
    let client = tokio::spawn(async move {
        run_relay_connection_with(
            "ws://127.0.0.1:1".into(),
            "peerhex".into(),
            "DIG_MAINNET".into(),
            task_status,
            Backoff {
                base_secs: 0,
                cap_secs: 0,
            },
        )
        .await;
    });

    // The loop cycles Connecting→Disconnected→Connecting rapidly with a dead endpoint; rather than
    // race the instantaneous state, assert it RETRIED (attempts keep climbing) and recorded a
    // connect error — the proof it degraded gracefully instead of crashing/hanging.
    let mut retried = false;
    for _ in 0..300 {
        // At least one failed attempt recorded proves it degraded to the retry loop rather than
        // crashing/hanging; the loop keeps climbing (bounded backoff) thereafter.
        if status.reconnect_attempts() >= 1 {
            retried = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        retried,
        "dead relay → keeps retrying (bounded), never a crash/hang"
    );
    // The last recorded error is a connect failure (never a panic).
    let v = status.snapshot_json("ws://127.0.0.1:1", "p");
    assert!(
        v["last_error"].as_str().unwrap_or("").contains("connect"),
        "recorded a connect error, got {:?}",
        v["last_error"]
    );

    client.abort();
}

/// Covers the production [`run_relay_connection`] wrapper + `handle_incoming` branches: the relay
/// acks (→ Connected), forwards a `peer_connected` notice (ignored), answers the client's `pong` to
/// a relay `ping`, then sends an `error` frame — which the client treats as a session failure and
/// drops to Disconnected (bumping the reconnect count). Robustly asserts the observable
/// Connected → (error) → Disconnected transition rather than racing the pong frame.
#[tokio::test]
async fn client_handles_frames_and_error_drops_session() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        let (mut write, mut read) = ws.split();
        // Consume Register, ack it → client goes Connected.
        let _ = read.next().await;
        let ack = RelayMessage::RegisterAck {
            success: true,
            message: "ok".into(),
            connected_peers: 2,
        };
        write
            .send(Message::Text(serde_json::to_string(&ack).unwrap()))
            .await
            .unwrap();
        // A relay ping (client answers with a pong — exercises that handle_incoming branch) and a
        // peer_connected notice (ignored branch).
        write
            .send(Message::Text(
                serde_json::to_string(&RelayMessage::Ping { timestamp: 1 }).unwrap(),
            ))
            .await
            .unwrap();
        let info = dig_nat::wire::RelayPeerInfo::new("other".into(), "DIG_MAINNET".into(), 1);
        write
            .send(Message::Text(
                serde_json::to_string(&RelayMessage::PeerConnected { peer: info }).unwrap(),
            ))
            .await
            .unwrap();
        // Give the client a moment to be Connected, then send an error frame → session failure.
        tokio::time::sleep(Duration::from_millis(150)).await;
        write
            .send(Message::Text(
                serde_json::to_string(&RelayMessage::Error {
                    code: 3,
                    message: "PEER_NOT_FOUND".into(),
                })
                .unwrap(),
            ))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
    });

    let status = RelayStatus::new();
    let task_status = Arc::clone(&status);
    let endpoint = format!("ws://{addr}");
    let endpoint_for_task = endpoint.clone();
    // Production wrapper (default backoff): after the error drop it would sleep 5s before retry, so
    // we observe the Connected→Disconnected transition and abort before the sleep completes.
    let client = tokio::spawn(async move {
        run_relay_connection(
            endpoint_for_task,
            "peerhex".into(),
            "DIG_MAINNET".into(),
            task_status,
        )
        .await
    });

    // Observe Connected (RegisterAck), then Disconnected with a bumped attempt count (the error).
    let mut connected = false;
    for _ in 0..150 {
        if status.is_connected() {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(connected, "reached Connected via RegisterAck");

    let mut dropped = false;
    for _ in 0..150 {
        if status.state() == RelayState::Disconnected && status.reconnect_attempts() >= 1 {
            dropped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(dropped, "error frame dropped the session to Disconnected");
    let v = status.snapshot_json(&endpoint, "peerhex");
    assert!(
        v["last_error"]
            .as_str()
            .unwrap_or("")
            .contains("relay error 3"),
        "recorded the relay error, got {:?}",
        v["last_error"]
    );

    client.abort();
    let _ = server.await;
}

use dig_nat::relay::run_relay_connection;

/// The persistent reservation is ALSO the discovery channel (the connect-leg fix): over the SAME
/// long-lived socket the client (1) sends RLY-005 `GetPeers` right after registering, folds the
/// `Peers` response into `RelayStatus`, and (2) folds relay-pushed `PeerConnected` notices — so a
/// peer that registers is discovered WITHOUT reopening the socket. Also proves the reservation is
/// PERSISTENT: exactly ONE `Register` is sent for the whole session (never re-registered per pass),
/// which is the regression the old ephemeral open-register-getpeers-close discovery caused.
#[tokio::test]
async fn persistent_reservation_discovers_peers_over_live_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let registers = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let server_registers = Arc::clone(&registers);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        let (mut write, mut read) = ws.split();
        // Drive the session: ack the (single) Register, answer GetPeers with one peer, then push a
        // second peer as a live `peer_connected` — all over the ONE persistent socket.
        while let Some(Ok(msg)) = read.next().await {
            let Message::Text(t) = msg else { continue };
            let parsed: RelayMessage = serde_json::from_str(&t).unwrap();
            match parsed {
                RelayMessage::Register { .. } => {
                    server_registers.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let ack = RelayMessage::RegisterAck {
                        success: true,
                        message: "ok".into(),
                        connected_peers: 1,
                    };
                    write
                        .send(Message::Text(serde_json::to_string(&ack).unwrap()))
                        .await
                        .unwrap();
                }
                RelayMessage::GetPeers { .. } => {
                    let peers = RelayMessage::Peers {
                        peers: vec![RelayPeerInfo::new("peerA".into(), "DIG_MAINNET".into(), 1)],
                    };
                    write
                        .send(Message::Text(serde_json::to_string(&peers).unwrap()))
                        .await
                        .unwrap();
                    let joined = RelayMessage::PeerConnected {
                        peer: RelayPeerInfo::new("peerB".into(), "DIG_MAINNET".into(), 1),
                    };
                    write
                        .send(Message::Text(serde_json::to_string(&joined).unwrap()))
                        .await
                        .unwrap();
                }
                _ => {}
            }
        }
    });

    let status = RelayStatus::new();
    let endpoint = format!("ws://{addr}");
    let task_status = Arc::clone(&status);
    let client = tokio::spawn(async move {
        run_relay_connection_with(
            endpoint,
            "self".into(),
            "DIG_MAINNET".into(),
            task_status,
            Backoff {
                base_secs: 0,
                cap_secs: 0,
            },
        )
        .await;
    });

    // Poll until both the GetPeers response (peerA) and the pushed notice (peerB) are folded in.
    let mut discovered = false;
    for _ in 0..100 {
        if status.known_peer_count() >= 2 {
            discovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        discovered,
        "discovered both peerA (get_peers) and peerB (peer_connected) over the live socket"
    );
    let ids: Vec<String> = status
        .known_peers()
        .into_iter()
        .map(|p| p.peer_id)
        .collect();
    assert!(ids.contains(&"peerA".to_string()) && ids.contains(&"peerB".to_string()));

    // The reservation is PERSISTENT: exactly one Register for the whole session.
    assert_eq!(
        registers.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "registered exactly once (persistent socket, not re-registered per discovery pass)"
    );

    client.abort();
    server.abort();
    let _ = server.await;
}
