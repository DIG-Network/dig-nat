//! Unit tests for the tier-6 relayed dial: an mTLS session carried OVER a relay byte tunnel presents
//! the SAME identity as a direct one. These live in-crate (not `tests/`) because they drive the
//! `#[cfg(test)]` loopback-relay harness ([`crate::relay::loopback_reservation_pair`]) + the private
//! tunnel routing, wiring two relay reservations to forward RLY-002 frames to each other with no
//! network. The security claim under test: a relayed [`crate::PeerConnection`] carries the identical
//! dig-tls mTLS — CA chain + `peer_id` pin + #1204 BLS binding — as a direct connection.

use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio_rustls::TlsAcceptor;

use crate::dialer::MtlsDialer;
use crate::method::relayed::ReservationRelayedTransport;
use crate::method::{MethodOutcome, TraversalKind};
use crate::mux::{AvailabilityAnswer, AvailabilityItem, AvailabilityRequest, AvailabilityResponse};
use crate::peer::PeerTarget;
use crate::relay::loopback_reservation_pair;
use crate::strategy::Dialer;
use crate::tunnel::RelayTunnelStream;
use crate::{BindingPolicy, NodeCert, PeerSession};
use dig_tls::bls::{public_key_bytes, SecretKey};
use tokio::io::AsyncWriteExt;

/// A deterministic BLS identity secret key from a label — derived (never an integer-literal secret,
/// so CodeQL does not flag a hard-coded crypto value).
fn test_bls_sk(label: &str) -> SecretKey {
    let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
    SecretKey::from_seed(&seed)
}

/// A CA-signed dig-tls [`NodeCert`] for `label`.
fn test_node(label: &str) -> Arc<NodeCert> {
    Arc::new(NodeCert::generate_signed(&test_bls_sk(label)).expect("generate node cert"))
}

const RELAY_ENDPOINT: &str = "127.0.0.1:3478";
const NET: &str = "DIG_MAINNET";

/// A full mTLS session over the relay tunnel verifies the peer's `peer_id` AND captures its #1204 BLS
/// binding — proving the relayed tier is NOT a weaker connection than a direct dial. The relay
/// forwards only ciphertext (it is wired as a dumb byte forwarder); identity is proven by the mTLS
/// layer, not the relay.
#[tokio::test]
async fn relayed_dial_preserves_mtls_peer_id_and_bls_binding() {
    let server = test_node("relayed/server");
    let client = test_node("relayed/client");
    let server_id = server.peer_id();
    let client_hex = client.peer_id().to_hex();
    let server_hex = server_id.to_hex();
    let expected_bls = public_key_bytes(&test_bls_sk("relayed/server"));

    // Two reservations forwarding RLY-002 frames to each other — a loopback relay, no network.
    let (client_status, server_status) = loopback_reservation_pair(&client_hex, &server_hex);

    // Server side: open its tunnel (registers inbound routing BEFORE the client sends ClientHello),
    // then run an mTLS server (Required binding) + yamux server answering one availability query.
    let server_tunnel = server_status.open_server_tunnel(&client_hex, NET);
    let server_tls = dig_tls::server_config(&server, BindingPolicy::Required)
        .expect("server config")
        .config;
    let acceptor = TlsAcceptor::from(server_tls);
    tokio::spawn(async move {
        let stream = RelayTunnelStream::new(server_tunnel);
        let tls = acceptor.accept(stream).await.expect("server mTLS accept");
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
                                total_length: Some(77),
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
    });

    // Client side: dial the relayed tier over its reservation. The dialer opens the tunnel to the
    // server and runs the SAME dig-tls client handshake (peer_id pin + binding capture) over it.
    let transport = Arc::new(ReservationRelayedTransport::new(
        Arc::clone(&client_status),
        RELAY_ENDPOINT.parse().unwrap(),
    ));
    let dialer = MtlsDialer::new(Arc::clone(&client))
        .with_binding_policy(BindingPolicy::Required)
        .with_relayed_dialer(transport);
    let peer = PeerTarget::relay_only(server_id, NET);
    let outcome = MethodOutcome::single(TraversalKind::Relayed, RELAY_ENDPOINT.parse().unwrap());

    let mut conn = tokio::time::timeout(Duration::from_secs(5), dialer.dial(&peer, &outcome))
        .await
        .expect("relayed dial completes")
        .expect("relayed dial succeeds");

    assert_eq!(conn.peer_id, server_id, "relayed peer_id == server cert id");
    assert_eq!(
        conn.method,
        TraversalKind::Relayed,
        "reports the relayed tier"
    );
    assert_eq!(
        conn.peer_bls_pub,
        Some(expected_bls),
        "relayed dial captured the server's #1204 BLS binding — same as a direct dial"
    );

    // The mux round-trips over the relay tunnel exactly like a direct connection.
    let resp = conn
        .query_availability(vec![AvailabilityItem {
            store_id: "bb".repeat(32),
            root: None,
            retrieval_key: None,
        }])
        .await
        .expect("availability over relayed mTLS");
    assert_eq!(resp.items.len(), 1);
    assert!(resp.items[0].available);
    assert_eq!(resp.items[0].total_length, Some(77));
}

/// REGRESSION (#1536): a relay circuit negotiates ROLES — the dialer is the mTLS client, the
/// reservation-holder that RECEIVES the introduced circuit is the mTLS server — and the handshake
/// completes. The holder does NOT pre-open a tunnel to the client (in production it cannot know who
/// will dial it); it only enables the RESPONDER path ([`RelayStatus::enable_accept`]) and serves
/// whatever introduced circuit surfaces via a [`RelayAcceptor`] (`PeerSession::server`).
///
/// Before the fix there was no responder path: the holder's `route_relayed` DROPPED a frame from a
/// peer with no open tunnel, so the dialer's ClientHello never reached a server-side accept — the
/// handshake deadlocked (`got ClientHello when expecting ServerHello`; both ends were TLS clients).
#[tokio::test]
async fn relayed_connect_negotiates_client_and_server_roles() {
    use crate::RelayAcceptor;

    let server = test_node("relayed/role-server");
    let client = test_node("relayed/role-client");
    let server_id = server.peer_id();
    let client_id = client.peer_id();
    let client_hex = client_id.to_hex();
    let server_hex = server_id.to_hex();

    let (client_status, server_status) = loopback_reservation_pair(&client_hex, &server_hex);

    // Server: enable the responder path (NO pre-opened tunnel), then serve the introduced circuit as
    // the mTLS SERVER. Report the peer_id it authenticated so the test proves exactly one client +
    // one server negotiated correctly.
    let mut inbound = server_status.enable_accept();
    let acceptor =
        RelayAcceptor::new(Arc::clone(&server)).with_binding_policy(BindingPolicy::Required);
    let (served_tx, served_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let tunnel = inbound
            .recv()
            .await
            .expect("introduced circuit surfaces to the acceptor");
        let mut conn = acceptor
            .accept(tunnel)
            .await
            .expect("server accepts + completes the mTLS handshake");
        let _ = served_tx.send(conn.peer_id);
        while let Some(mut s) = conn.session.accept_stream().await {
            tokio::spawn(async move {
                if let Ok(req) = AvailabilityRequest::decode(&mut s).await {
                    let resp = AvailabilityResponse {
                        items: req
                            .items
                            .iter()
                            .map(|_| AvailabilityAnswer {
                                available: true,
                                roots: None,
                                total_length: Some(42),
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
    });

    // Client: dial the relayed tier — runs the mTLS CLIENT (the initiator).
    let transport = Arc::new(ReservationRelayedTransport::new(
        Arc::clone(&client_status),
        RELAY_ENDPOINT.parse().unwrap(),
    ));
    let dialer = MtlsDialer::new(Arc::clone(&client))
        .with_binding_policy(BindingPolicy::Required)
        .with_relayed_dialer(transport);
    let peer = PeerTarget::relay_only(server_id, NET);
    let outcome = MethodOutcome::single(TraversalKind::Relayed, RELAY_ENDPOINT.parse().unwrap());

    let mut conn = tokio::time::timeout(Duration::from_secs(5), dialer.dial(&peer, &outcome))
        .await
        .expect("relayed dial completes (no double-ClientHello deadlock)")
        .expect("relayed dial succeeds");
    assert_eq!(
        conn.peer_id, server_id,
        "client verified the server's peer_id"
    );

    let served = tokio::time::timeout(Duration::from_secs(5), served_rx)
        .await
        .expect("server completed its accept")
        .expect("server reported the authenticated peer_id");
    assert_eq!(served, client_id, "server verified the client's peer_id");

    let resp = conn
        .query_availability(vec![AvailabilityItem {
            store_id: "cc".repeat(32),
            root: None,
            retrieval_key: None,
        }])
        .await
        .expect("availability round-trips over the role-negotiated relay mTLS");
    assert_eq!(resp.items.len(), 1);
    assert!(resp.items[0].available);
    assert_eq!(resp.items[0].total_length, Some(42));
}

/// A MALICIOUS relay that redirects the client to an IMPOSTOR (labelling the impostor with the honest
/// peer's routing id) is rejected by mTLS: the client pinned the honest `peer_id`, so the impostor's
/// cert derives a different id and the handshake fails. This is the security crux — the relay is an
/// untrusted forwarder and cannot substitute a peer, because identity is proven by the certificate,
/// not by the relay's routing.
#[tokio::test]
async fn relayed_dial_rejects_malicious_relay_redirect_to_impostor() {
    let honest = test_node("relayed/honest"); // the peer the client WANTS
    let impostor = test_node("relayed/impostor"); // who the malicious relay actually connects
    let client = test_node("relayed/client-b");
    let honest_id = honest.peer_id();
    let client_hex = client.peer_id().to_hex();
    let honest_hex = honest_id.to_hex();

    // The relay labels the impostor's leg with the HONEST peer's routing id (the redirect attack).
    let (client_status, impostor_status) = loopback_reservation_pair(&client_hex, &honest_hex);
    let imp_tunnel = impostor_status.open_server_tunnel(&client_hex, NET);
    let imp_tls = dig_tls::server_config(&impostor, BindingPolicy::Off)
        .unwrap()
        .config;
    let acceptor = TlsAcceptor::from(imp_tls);
    tokio::spawn(async move {
        let stream = RelayTunnelStream::new(imp_tunnel);
        let _ = acceptor.accept(stream).await; // client will reject the impostor's cert
    });

    let transport = Arc::new(ReservationRelayedTransport::new(
        Arc::clone(&client_status),
        RELAY_ENDPOINT.parse().unwrap(),
    ));
    let dialer = MtlsDialer::new(Arc::clone(&client)).with_relayed_dialer(transport);
    // Pin the HONEST peer — the relay tries to substitute the impostor.
    let peer = PeerTarget::relay_only(honest_id, NET);
    let outcome = MethodOutcome::single(TraversalKind::Relayed, RELAY_ENDPOINT.parse().unwrap());

    let err = tokio::time::timeout(Duration::from_secs(20), dialer.dial(&peer, &outcome))
        .await
        .expect("relayed dial completes")
        .unwrap_err();
    assert_eq!(err.kind, TraversalKind::Relayed);
    assert!(
        err.reason.contains("mtls handshake") || err.reason.contains("peer_id"),
        "relayed handshake rejects the impostor substituted by the relay, got: {}",
        err.reason
    );
}

/// REGRESSION (#1536 GLARE): two NAT'd peers that BOTH fall to the relay tier and dial EACH OTHER
/// simultaneously (neither pre-opens) — the common two-NAT'd-peer flywheel case. Without the
/// deterministic tie-break each side opens a CLIENT tunnel and each side's ClientHello routes into the
/// OTHER's client session → both ends are TLS clients → the #1536 double-ClientHello deadlock
/// re-manifests (the dial would hang; this test would time out).
///
/// With the tie-break (numerically-LOWER `peer_id` becomes SERVER) the crossed pair resolves to
/// exactly ONE client + ONE server under this dial ordering: the higher-id side's `dial` completes as
/// the mTLS client, the lower-id side's `dial` self-cancels and its `RelayAcceptor` serves the circuit
/// as the mTLS server. A yamux availability query then round-trips over the negotiated session.
#[tokio::test]
async fn mutual_simultaneous_relayed_dial_resolves_glare_to_one_client_one_server() {
    use crate::peer::PeerConnection;
    use crate::relay::RelayTunnel;
    use crate::RelayAcceptor;
    use tokio::sync::mpsc as tokio_mpsc;
    use tokio::sync::oneshot;

    let node_a = test_node("glare/a");
    let node_b = test_node("glare/b");
    let a_id = node_a.peer_id();
    let b_id = node_b.peer_id();
    let a_hex = a_id.to_hex();
    let b_hex = b_id.to_hex();

    let (a_status, b_status) = loopback_reservation_pair(&a_hex, &b_hex);

    // Each side enables the responder path — a real node both dials (the ladder) AND accepts
    // introduced circuits (a `RelayAcceptor`) at the same time. Whichever side yields to the server
    // role under the glare tie-break serves here; the other side's acceptor stays idle.
    let a_inbound = a_status.enable_accept();
    let b_inbound = b_status.enable_accept();

    // Serve one accepted circuit as the mTLS SERVER, reporting the authenticated client peer_id and
    // answering one availability query so the round-trip can be proven. Kept alive by the returned
    // JoinHandle; the loser-of-glare side's oneshot fires, the winner's never does.
    fn spawn_acceptor(
        node: Arc<NodeCert>,
        mut inbound: tokio_mpsc::Receiver<RelayTunnel>,
    ) -> (
        oneshot::Receiver<crate::PeerId>,
        tokio::task::JoinHandle<()>,
    ) {
        let (served_tx, served_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let acceptor = RelayAcceptor::new(node).with_binding_policy(BindingPolicy::Required);
            let Some(tunnel) = inbound.recv().await else {
                return;
            };
            let Ok(mut conn): Result<PeerConnection, _> = acceptor.accept(tunnel).await else {
                return;
            };
            let _ = served_tx.send(conn.peer_id);
            while let Some(mut s) = conn.session.accept_stream().await {
                tokio::spawn(async move {
                    if let Ok(req) = AvailabilityRequest::decode(&mut s).await {
                        let resp = AvailabilityResponse {
                            items: req
                                .items
                                .iter()
                                .map(|_| AvailabilityAnswer {
                                    available: true,
                                    roots: None,
                                    total_length: Some(99),
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
        });
        (served_rx, handle)
    }

    let (a_served_rx, _a_srv) = spawn_acceptor(Arc::clone(&node_a), a_inbound);
    let (b_served_rx, _b_srv) = spawn_acceptor(Arc::clone(&node_b), b_inbound);

    // Build each side's relayed dialer over its own reservation.
    let a_dialer = MtlsDialer::new(Arc::clone(&node_a))
        .with_binding_policy(BindingPolicy::Required)
        .with_relayed_dialer(Arc::new(ReservationRelayedTransport::new(
            Arc::clone(&a_status),
            RELAY_ENDPOINT.parse().unwrap(),
        )));
    let b_dialer = MtlsDialer::new(Arc::clone(&node_b))
        .with_binding_policy(BindingPolicy::Required)
        .with_relayed_dialer(Arc::new(ReservationRelayedTransport::new(
            Arc::clone(&b_status),
            RELAY_ENDPOINT.parse().unwrap(),
        )));
    let a_peer = PeerTarget::relay_only(b_id, NET); // A dials B
    let b_peer = PeerTarget::relay_only(a_id, NET); // B dials A — simultaneously
    let outcome = MethodOutcome::single(TraversalKind::Relayed, RELAY_ENDPOINT.parse().unwrap());

    // BOTH dial at once. A deadlock (the un-fixed behavior) would hang here → the timeout fails loudly.
    let (a_dial, b_dial) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            a_dialer.dial(&a_peer, &outcome),
            b_dialer.dial(&b_peer, &outcome),
        )
    })
    .await
    .expect("mutual relayed dial resolves (no glare deadlock)");

    // Exactly ONE side won the client role; the other yielded to server (its dial self-cancelled).
    let (mut client_conn, expect_client_id, served_rx) = match (a_dial, b_dial) {
        (Ok(c), Err(_)) => (c, a_id, b_served_rx), // A client, B server
        (Err(_), Ok(c)) => (c, b_id, a_served_rx), // B client, A server
        (Ok(_), Ok(_)) => panic!("glare must yield exactly one client, got two"),
        (Err(ea), Err(eb)) => panic!("both relayed dials failed: {ea:?} / {eb:?}"),
    };

    // The client verified the SERVER's identity, and the server verified the CLIENT's — one clean
    // mutually-authenticated mTLS session, not two deadlocked clients.
    let expect_server_id = if expect_client_id == a_id { b_id } else { a_id };
    assert_eq!(
        client_conn.peer_id, expect_server_id,
        "client verified the yielding peer's server identity"
    );
    let served = tokio::time::timeout(Duration::from_secs(5), served_rx)
        .await
        .expect("server side completed its accept")
        .expect("server reported the authenticated client peer_id");
    assert_eq!(
        served, expect_client_id,
        "server verified the winning peer's client identity"
    );

    // The mux round-trips over the glare-negotiated relay mTLS.
    let resp = client_conn
        .query_availability(vec![AvailabilityItem {
            store_id: "dd".repeat(32),
            root: None,
            retrieval_key: None,
        }])
        .await
        .expect("availability round-trips over the glare-resolved relay mTLS");
    assert_eq!(resp.items.len(), 1);
    assert!(resp.items[0].available);
    assert_eq!(resp.items[0].total_length, Some(99));
}

/// The [`RelayTunnelStream`] adapter round-trips bytes both directions over the loopback relay, and a
/// single inbound payload satisfies several small reads (the carry-over buffer) — the property TLS
/// relies on when it reads a record header then its body.
#[tokio::test]
async fn relay_tunnel_stream_round_trips_bytes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (a_status, b_status) = loopback_reservation_pair("aa", "bb");
    let a_tunnel = a_status.open_tunnel("bb", NET).unwrap();
    let b_tunnel = b_status.open_tunnel("aa", NET).unwrap();
    let mut a = RelayTunnelStream::new(a_tunnel);
    let mut b = RelayTunnelStream::new(b_tunnel);

    // A → B: one write, read back in two small chunks (exercises the carry-over buffer).
    a.write_all(b"hello world").await.unwrap();
    a.flush().await.unwrap();
    let mut first = [0u8; 5];
    b.read_exact(&mut first).await.unwrap();
    assert_eq!(&first, b"hello");
    let mut rest = [0u8; 6];
    b.read_exact(&mut rest).await.unwrap();
    assert_eq!(&rest, b" world");

    // B → A: the reverse direction works too.
    b.write_all(b"pong").await.unwrap();
    b.flush().await.unwrap();
    let mut back = [0u8; 4];
    a.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"pong");
}

/// With NO relay data-plane wired, a relayed outcome fails cleanly (never a silent broken dial).
#[tokio::test]
async fn relayed_dial_without_transport_is_clean_error() {
    let dialer = MtlsDialer::new(test_node("relayed/client-c"));
    let peer = PeerTarget::relay_only(crate::PeerId::from_bytes([1u8; 32]), NET);
    let outcome = MethodOutcome::single(TraversalKind::Relayed, RELAY_ENDPOINT.parse().unwrap());
    let err = dialer.dial(&peer, &outcome).await.unwrap_err();
    assert_eq!(err.kind, TraversalKind::Relayed);
    assert!(err.reason.contains("no relay data-plane"));
}
