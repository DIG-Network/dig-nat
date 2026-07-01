//! Dialer + PeerConnection integration over a real LOOPBACK mTLS server (in-process, no external
//! network). Proves the production `MtlsDialer` establishes an mTLS session, verifies the peer_id,
//! rejects a mismatch, and that the resulting PeerConnection's mux passthroughs work end-to-end.

use std::sync::Arc;

use dig_nat::config::LocalIdentity;
use dig_nat::dialer::MtlsDialer;
use dig_nat::identity::peer_id_from_leaf_cert_der;
use dig_nat::method::{MethodOutcome, TraversalKind};
use dig_nat::mux::{
    AvailabilityAnswer, AvailabilityItem, AvailabilityRequest, AvailabilityResponse,
};
use dig_nat::peer::PeerTarget;
use dig_nat::strategy::Dialer;
use dig_nat::{PeerId, PeerSession};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Generate a self-signed identity (cert DER, key DER, derived peer_id).
fn gen() -> (Vec<u8>, Vec<u8>, PeerId) {
    let c = rcgen::generate_simple_self_signed(vec!["peer.dig".into()]).unwrap();
    let cert = c.cert.der().to_vec();
    let key = c.key_pair.serialize_der();
    let id = peer_id_from_leaf_cert_der(&cert).unwrap();
    (cert, key, id)
}

/// Stand up a loopback mTLS server that presents `server_cert` and, once connected, runs a yamux
/// SERVER session that answers one availability query + serves accepted streams. Returns its addr.
async fn spawn_mtls_server(server_cert: Vec<u8>, server_key: Vec<u8>) -> std::net::SocketAddr {
    // The server accepts any client cert (client auth optional) — we only test server-identity here.
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(server_cert)],
            PrivateKeyDer::try_from(server_key).unwrap(),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(tls) = acceptor.accept(tcp).await {
                // Run a yamux server over the accepted mTLS stream; echo availability requests.
                let mut session = PeerSession::server(tls);
                while let Some(mut s) = session.accept_stream().await {
                    tokio::spawn(async move {
                        // If it's an availability request, answer; otherwise echo.
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
    addr
}

fn local_identity() -> LocalIdentity {
    let (cert, key, _) = gen();
    LocalIdentity::from_der(cert, key).unwrap()
}

/// Dialing a server whose cert derives the expected peer_id succeeds, verifies identity, and yields
/// a working multiplexed PeerConnection (availability passthrough round-trips over the real mTLS).
#[tokio::test]
async fn dial_success_verifies_identity_and_muxes() {
    let (scert, skey, server_id) = gen();
    let addr = spawn_mtls_server(scert, skey).await;

    let dialer = MtlsDialer::new(local_identity());
    let peer = PeerTarget::with_addr(server_id, addr, "DIG_MAINNET");
    let outcome = MethodOutcome {
        kind: TraversalKind::Direct,
        dial_addr: addr,
    };

    let mut conn = dialer.dial(&peer, &outcome).await.expect("dial succeeds");
    assert_eq!(
        conn.peer_id, server_id,
        "verified identity == server cert id"
    );
    assert_eq!(conn.method, TraversalKind::Direct);

    // Exercise the PeerConnection passthroughs over the real mTLS+mux link.
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
/// self-authenticating guarantee.
#[tokio::test]
async fn dial_rejects_wrong_peer_id() {
    let (scert, skey, _server_id) = gen();
    let addr = spawn_mtls_server(scert, skey).await;

    let dialer = MtlsDialer::new(local_identity());
    // Pin to a different id than the server presents.
    let wrong = PeerId::from_bytes([0x7fu8; 32]);
    let peer = PeerTarget::with_addr(wrong, addr, "DIG_MAINNET");
    let outcome = MethodOutcome {
        kind: TraversalKind::Direct,
        dial_addr: addr,
    };

    let err = dialer.dial(&peer, &outcome).await.unwrap_err();
    assert_eq!(err.kind, TraversalKind::Direct);
    assert!(
        err.reason.contains("mtls handshake") || err.reason.contains("peer_id"),
        "handshake rejected on identity mismatch, got: {}",
        err.reason
    );
}

/// Dialing an address with nothing listening fails cleanly (tcp connect error), no panic/hang.
#[tokio::test]
async fn dial_tcp_refused_is_clean_error() {
    let dialer = MtlsDialer::new(local_identity());
    let peer = PeerTarget::with_addr(
        PeerId::from_bytes([1u8; 32]),
        "127.0.0.1:9".parse().unwrap(),
        "DIG_MAINNET",
    );
    let outcome = MethodOutcome {
        kind: TraversalKind::Direct,
        dial_addr: "127.0.0.1:9".parse().unwrap(),
    };
    let err = dialer.dial(&peer, &outcome).await.unwrap_err();
    assert_eq!(err.kind, TraversalKind::Direct);
    assert!(err.reason.contains("tcp connect"));
}
