//! mTLS identity tests — a real rustls handshake over loopback proves the pinning verifier derives
//! `peer_id = SHA-256(SPKI DER)` from the presented cert, ACCEPTS a matching pin, REJECTS a
//! mismatch, and always records who connected. No external network.

use std::sync::Arc;

use dig_nat::identity::peer_id_from_leaf_cert_der;
use dig_nat::mtls::{CapturedPeerId, PeerIdPinningVerifier};
use dig_nat::PeerId;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Generate a self-signed leaf cert + key (DER) and its derived peer_id.
fn gen_identity() -> (Vec<u8>, Vec<u8>, PeerId) {
    let c = rcgen::generate_simple_self_signed(vec!["peer.dig".into()]).unwrap();
    let cert_der = c.cert.der().to_vec();
    let key_der = c.key_pair.serialize_der();
    let id = peer_id_from_leaf_cert_der(&cert_der).unwrap();
    (cert_der, key_der, id)
}

/// Run one loopback TLS handshake: server presents `server_cert`; client verifies with a pinning
/// verifier pinned to `expected`. Returns the captured peer_id + whether the handshake succeeded.
async fn handshake(
    server_cert: Vec<u8>,
    server_key: Vec<u8>,
    expected: Option<PeerId>,
) -> (Option<PeerId>, bool) {
    // Server config (no client-auth required for this identity-of-server test).
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(server_cert)],
            PrivateKeyDer::try_from(server_key).unwrap(),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let captured = CapturedPeerId::default();
    let verifier = Arc::new(PeerIdPinningVerifier::new(expected, captured.clone()));
    let client_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        match acceptor.accept(tcp).await {
            Ok(mut tls) => {
                let _ = tls.write_all(b"ok").await;
                true
            }
            Err(_) => false,
        }
    });

    let client_ok = {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("peer.dig").unwrap();
        match connector.connect(name, tcp).await {
            Ok(mut tls) => {
                let mut buf = [0u8; 2];
                tls.read_exact(&mut buf).await.is_ok()
            }
            Err(_) => false,
        }
    };
    let _ = server.await;
    (captured.get(), client_ok)
}

#[tokio::test]
async fn accepts_and_captures_matching_peer_id() {
    let (cert, key, id) = gen_identity();
    let (captured, ok) = handshake(cert, key, Some(id)).await;
    assert!(ok, "handshake succeeds when the pinned peer_id matches");
    assert_eq!(captured, Some(id), "the derived peer_id is captured");
}

#[tokio::test]
async fn rejects_mismatched_peer_id() {
    let (cert, key, real_id) = gen_identity();
    // Pin to a DIFFERENT id than the cert derives.
    let wrong = PeerId::from_bytes([0xffu8; 32]);
    assert_ne!(wrong, real_id);
    let (captured, ok) = handshake(cert, key, Some(wrong)).await;
    assert!(
        !ok,
        "handshake fails when the pinned peer_id does not match"
    );
    // Even on rejection, the verifier recorded who actually presented (before rejecting).
    assert_eq!(captured, Some(real_id));
}

#[tokio::test]
async fn accepts_any_when_no_pin() {
    let (cert, key, id) = gen_identity();
    let (captured, ok) = handshake(cert, key, None).await;
    assert!(ok, "with no pin, any peer is accepted (record-only)");
    assert_eq!(captured, Some(id));
}
