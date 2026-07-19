//! mTLS identity tests — a real rustls handshake over loopback proves the pinning verifier derives
//! `peer_id = SHA-256(SPKI DER)` from the presented cert, ACCEPTS a matching pin, REJECTS a
//! mismatch, and always records who connected. No external network.

use std::sync::Arc;

use dig_nat::cert_binding::{build_bound_cert, BindingPolicy};
use dig_nat::identity::peer_id_from_leaf_cert_der;
use dig_nat::mtls::{CapturedBlsPub, CapturedPeerId, PeerIdPinningVerifier};
use dig_nat::PeerId;
use rcgen::KeyPair;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use sha2::{Digest, Sha256};
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

/// A deterministic node BLS identity key from a label (derived, never a literal secret).
fn node_bls_sk(label: &str) -> dig_identity::bls::SecretKey {
    let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
    dig_identity::derive_identity_sk(&dig_identity::master_secret_key_from_seed(&seed))
}

/// Generate a BLS-bound leaf cert + key (DER), its peer_id, and the bound BLS pubkey.
fn gen_bound_identity(label: &str) -> (Vec<u8>, Vec<u8>, PeerId, [u8; 48]) {
    let kp = KeyPair::generate().unwrap();
    let key_der = kp.serialize_der();
    let bls_sk = node_bls_sk(label);
    let cert_der = build_bound_cert(&kp, &bls_sk, vec!["peer.dig".into()]).unwrap();
    let id = peer_id_from_leaf_cert_der(&cert_der).unwrap();
    (
        cert_der,
        key_der,
        id,
        dig_identity::public_key_bytes(&bls_sk),
    )
}

/// Run one loopback TLS handshake: server presents `server_cert`; client verifies with a pinning
/// verifier pinned to `expected`. Returns the captured peer_id + whether the handshake succeeded.
async fn handshake(
    server_cert: Vec<u8>,
    server_key: Vec<u8>,
    expected: Option<PeerId>,
) -> (Option<PeerId>, bool) {
    let (captured, _bls, ok) =
        handshake_binding(server_cert, server_key, expected, BindingPolicy::Off).await;
    (captured, ok)
}

/// Like [`handshake`] but with an explicit BLS cert-binding policy; also returns the captured peer
/// BLS pubkey.
async fn handshake_binding(
    server_cert: Vec<u8>,
    server_key: Vec<u8>,
    expected: Option<PeerId>,
    policy: BindingPolicy,
) -> (Option<PeerId>, Option<[u8; 48]>, bool) {
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
    let captured_bls = CapturedBlsPub::default();
    let verifier = Arc::new(
        PeerIdPinningVerifier::new(expected, captured.clone())
            .with_binding(policy, captured_bls.clone()),
    );
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
    (captured.get(), captured_bls.get(), client_ok)
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

// --- BLS cert-binding enforcement over a real handshake (#1204) ---

#[tokio::test]
async fn required_policy_accepts_bound_cert_and_captures_bls_pub() {
    let (cert, key, id, bls_pub) = gen_bound_identity("mtls/bound-ok");
    let (captured, captured_bls, ok) =
        handshake_binding(cert, key, Some(id), BindingPolicy::Required).await;
    assert!(ok, "a valid BLS-bound cert is accepted under Required");
    assert_eq!(captured, Some(id));
    assert_eq!(
        captured_bls,
        Some(bls_pub),
        "the bound BLS pubkey is captured"
    );
}

#[tokio::test]
async fn required_policy_rejects_unbound_cert() {
    // A legacy cert with no binding extension must be REJECTED under Required (anti-downgrade).
    let (cert, key, id) = gen_identity();
    let (_captured, captured_bls, ok) =
        handshake_binding(cert, key, Some(id), BindingPolicy::Required).await;
    assert!(
        !ok,
        "an un-bound cert is rejected when a binding is Required"
    );
    assert_eq!(captured_bls, None);
}

#[tokio::test]
async fn opportunistic_policy_accepts_unbound_cert() {
    // The rollout default tolerates a legacy peer.
    let (cert, key, id) = gen_identity();
    let (captured, captured_bls, ok) =
        handshake_binding(cert, key, Some(id), BindingPolicy::Opportunistic).await;
    assert!(ok, "an un-bound cert is accepted under Opportunistic");
    assert_eq!(captured, Some(id));
    assert_eq!(captured_bls, None, "no binding → no captured pubkey");
}

#[tokio::test]
async fn opportunistic_policy_captures_bls_pub_when_present() {
    let (cert, key, id, bls_pub) = gen_bound_identity("mtls/opp-bound");
    let (_captured, captured_bls, ok) =
        handshake_binding(cert, key, Some(id), BindingPolicy::Opportunistic).await;
    assert!(ok);
    assert_eq!(captured_bls, Some(bls_pub));
}
