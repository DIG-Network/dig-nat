//! Dialer + PeerConnection integration over a real LOOPBACK mTLS server (in-process, no external
//! network). Proves the production `MtlsDialer` — presenting a dig-tls `NodeCert` and using
//! `dig_tls::client_config` for the handshake — establishes an mTLS session, verifies the peer_id,
//! rejects a mismatch, and that the resulting PeerConnection's mux passthroughs work end-to-end.

mod tls_harness;

use std::sync::Arc;
use std::time::Duration;

use dig_ip::LocalStack;
use dig_nat::dialer::{HappyEyeballsConfig, MtlsDialer};
use dig_nat::method::{MethodOutcome, TraversalKind};
use dig_nat::mux::{
    AvailabilityAnswer, AvailabilityItem, AvailabilityRequest, AvailabilityResponse,
};
use dig_nat::peer::PeerTarget;
use dig_nat::strategy::Dialer;
use dig_nat::{BindingPolicy, NodeCert, PeerId, PeerSession};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use tls_harness::test_node;

/// Stand up a loopback mTLS server that presents `server`'s CA-signed cert (requiring the client's
/// cert to chain to the DigNetwork CA) and, once connected, runs a yamux SERVER session that answers
/// one availability query. Returns its address + the server's `peer_id`.
async fn spawn_mtls_server(server: &Arc<NodeCert>) -> (std::net::SocketAddr, PeerId) {
    let server_id = server.peer_id();
    // dig-tls server config: mutual TLS, verify the client chains to the DigNetwork CA.
    let server_tls =
        dig_tls::server_config(server, BindingPolicy::Off).expect("build server config");
    let acceptor = TlsAcceptor::from(server_tls.config);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(tls) = acceptor.accept(tcp).await {
                let mut session = PeerSession::server(tls);
                while let Some(mut s) = session.accept_stream().await {
                    tokio::spawn(async move {
                        if let Ok(req) = AvailabilityRequest::decode(&mut s).await {
                            let resp = AvailabilityResponse {
                                items: req
                                    .items
                                    .iter()
                                    .map(|_| AvailabilityAnswer {
                                        available: true,
                                        roots: None,
                                        total_length: Some(123),
                                        chunk_count: Some(1),
                                        complete: Some(true),
                                    })
                                    .collect(),
                            };
                            let _ = s.write_all(&resp.encode()).await;
                            let _ = s.shutdown().await;
                        }
                    });
                }
            }
        }
    });
    (addr, server_id)
}

/// Dialing a server whose cert derives the expected peer_id succeeds, verifies identity, and yields
/// a working multiplexed PeerConnection (availability passthrough round-trips over the real mTLS).
#[tokio::test]
async fn dial_success_verifies_identity_and_muxes() {
    let server = test_node("dialer/server-a");
    let (addr, server_id) = spawn_mtls_server(&server).await;

    let dialer = MtlsDialer::new(test_node("dialer/client-a"));
    let peer = PeerTarget::with_addr(server_id, addr, "DIG_MAINNET");
    let outcome = MethodOutcome::single(TraversalKind::Direct, addr);

    let mut conn = dialer.dial(&peer, &outcome).await.expect("dial succeeds");
    assert_eq!(
        conn.peer_id, server_id,
        "verified identity == server cert id"
    );
    assert_eq!(conn.method, TraversalKind::Direct);

    let resp = conn
        .query_availability(vec![AvailabilityItem {
            store_id: "aa".repeat(32),
            root: None,
            retrieval_key: None,
        }])
        .await
        .expect("availability over mTLS");
    assert_eq!(resp.items.len(), 1);
    assert!(resp.items[0].available);
    assert_eq!(resp.items[0].total_length, Some(123));
}

/// Dialing with a pinned peer_id that does NOT match the server's cert fails the handshake — the
/// self-authenticating guarantee (now enforced by dig-tls's client verifier).
#[tokio::test]
async fn dial_rejects_wrong_peer_id() {
    let server = test_node("dialer/server-b");
    let (addr, _server_id) = spawn_mtls_server(&server).await;

    let dialer = MtlsDialer::new(test_node("dialer/client-b"));
    let wrong = PeerId::from_bytes([0x7fu8; 32]);
    let peer = PeerTarget::with_addr(wrong, addr, "DIG_MAINNET");
    let outcome = MethodOutcome::single(TraversalKind::Direct, addr);

    let err = dialer.dial(&peer, &outcome).await.unwrap_err();
    assert_eq!(err.kind, TraversalKind::Direct);
    assert!(
        err.reason.contains("mtls handshake") || err.reason.contains("peer_id"),
        "handshake rejected on identity mismatch, got: {}",
        err.reason
    );
}

/// Happy eyeballs end-to-end over the PRODUCTION dialer: given an unreachable IPv6 candidate FIRST
/// and a working IPv4 loopback second, the dialer tries IPv6 first, falls back to IPv4, and
/// establishes the mTLS session — proving the IPv6-first / IPv4-fallback dial path is wired through
/// the real `MtlsDialer` (not just the pure racing helper).
#[tokio::test]
async fn dial_falls_back_from_unreachable_ipv6_to_ipv4() {
    let server = test_node("dialer/server-c");
    let (addr, server_id) = spawn_mtls_server(&server).await; // IPv4 loopback

    let dialer = MtlsDialer::new(test_node("dialer/client-c"))
        .with_happy_eyeballs(HappyEyeballsConfig {
            per_attempt_timeout: Duration::from_secs(2),
            stagger: Duration::from_millis(30),
        })
        .with_local_stack(LocalStack::from_flags(true, true));

    let unreachable_v6: std::net::SocketAddr = "[2001:db8::1]:9".parse().unwrap();
    let peer = PeerTarget::with_addrs(server_id, vec![unreachable_v6, addr], "DIG_MAINNET");
    let outcome = MethodOutcome::candidates(TraversalKind::Direct, peer.direct_addrs().to_vec());

    let conn = dialer
        .dial(&peer, &outcome)
        .await
        .expect("falls back to the reachable IPv4 candidate");
    assert_eq!(
        conn.peer_id, server_id,
        "mTLS identity verified over IPv4 fallback"
    );
    assert_eq!(
        conn.remote_addr, addr,
        "connected over the IPv4 loopback address"
    );
    assert!(conn.remote_addr.is_ipv4());
}

/// A v4-only local host asked to dial a peer that ONLY advertises an IPv6 candidate fails cleanly and
/// IMMEDIATELY (dig-ip's `NoCommonFamily`) — it never emits a doomed IPv6 SYN that could only hang.
#[tokio::test]
async fn dial_v4_only_host_to_v6_only_peer_is_clean_no_common_family() {
    let dialer = MtlsDialer::new(test_node("dialer/client-d"))
        .with_local_stack(LocalStack::from_flags(false, true));
    let v6_only: std::net::SocketAddr = "[2001:db8::1]:9".parse().unwrap();
    let peer = PeerTarget::with_addr(PeerId::from_bytes([1u8; 32]), v6_only, "DIG_MAINNET");
    let outcome = MethodOutcome::single(TraversalKind::Direct, v6_only);

    let err = dialer.dial(&peer, &outcome).await.unwrap_err();
    assert_eq!(err.kind, TraversalKind::Direct);
    assert!(
        err.reason.contains("no common address family"),
        "reports a clean no-common-family error, got: {}",
        err.reason
    );
    assert!(!err.reason.contains("tcp connect"));
}

/// Dialing an address with nothing listening fails cleanly (tcp connect error), no panic/hang.
#[tokio::test]
async fn dial_tcp_refused_is_clean_error() {
    let dialer = MtlsDialer::new(test_node("dialer/client-e"));
    let peer = PeerTarget::with_addr(
        PeerId::from_bytes([1u8; 32]),
        "127.0.0.1:9".parse().unwrap(),
        "DIG_MAINNET",
    );
    let outcome = MethodOutcome::single(TraversalKind::Direct, "127.0.0.1:9".parse().unwrap());
    let err = dialer.dial(&peer, &outcome).await.unwrap_err();
    assert_eq!(err.kind, TraversalKind::Direct);
    assert!(err.reason.contains("tcp connect"));
}
