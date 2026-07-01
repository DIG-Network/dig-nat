//! Peer identity tests — `peer_id = SHA-256(TLS SPKI DER)`, hex round-trip, and cross-crate
//! conformance with dig-gossip's derivation (the two MUST produce byte-identical ids).

use dig_nat::{peer_id_from_leaf_cert_der, peer_id_from_tls_spki_der, PeerId};
use sha2::{Digest, Sha256};

/// The derivation is exactly SHA-256 of the SPKI DER — this pins the algorithm so it can never
/// silently diverge from dig-gossip's `peer_id_from_tls_spki_der`.
#[test]
fn peer_id_is_sha256_of_spki_der() {
    let spki = b"a fake SubjectPublicKeyInfo DER blob";
    let id = peer_id_from_tls_spki_der(spki);
    let expected: [u8; 32] = Sha256::digest(spki).into();
    assert_eq!(id.as_bytes(), &expected);
}

/// dig-gossip defines `peer_id_from_tls_spki_der(spki) = Sha256::digest(spki)`. dig-nat MUST match
/// byte-for-byte (recomputed here the same way dig-gossip does) so a node computes the same id for a
/// peer regardless of which crate does it.
#[test]
fn conformance_with_dig_gossip_derivation() {
    for sample in [&b""[..], &b"x"[..], &[0u8; 91][..], &[0xabu8; 256][..]] {
        let ours = peer_id_from_tls_spki_der(sample);
        // dig-gossip: `let digest = Sha256::digest(spki_der); PeerId::from(<[u8;32]>::from(digest))`.
        let gossip_bytes: [u8; 32] = Sha256::digest(sample).into();
        assert_eq!(
            ours.as_bytes(),
            &gossip_bytes,
            "dig-nat peer_id must equal dig-gossip's for the same SPKI"
        );
    }
}

#[test]
fn hex_round_trips() {
    let id = peer_id_from_tls_spki_der(b"round-trip");
    let hex = id.to_hex();
    assert_eq!(hex.len(), 64);
    assert_eq!(PeerId::from_hex(&hex), Some(id));
}

#[test]
fn from_hex_rejects_bad_input() {
    assert_eq!(PeerId::from_hex("too short"), None);
    assert_eq!(PeerId::from_hex(&"z".repeat(64)), None); // not hex
    assert_eq!(PeerId::from_hex(&"a".repeat(63)), None); // wrong length
}

/// A real (ephemeral, self-signed) certificate's SPKI must derive the SAME id whether taken from the
/// whole leaf cert or from the extracted SPKI — proves `peer_id_from_leaf_cert_der` lifts the right
/// bytes.
#[test]
fn leaf_cert_and_spki_agree() {
    let cert = rcgen::generate_simple_self_signed(vec!["node.dig".into()]).unwrap();
    let cert_der = cert.cert.der().to_vec();

    let from_leaf = peer_id_from_leaf_cert_der(&cert_der).expect("leaf parses");

    // Independently parse the SPKI out and hash it — must equal the leaf-derived id.
    let (_, x509) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
    let spki = x509.tbs_certificate.subject_pki.raw;
    let from_spki = peer_id_from_tls_spki_der(spki);

    assert_eq!(from_leaf, from_spki);
}

#[test]
fn leaf_cert_parse_failure_is_none() {
    assert_eq!(peer_id_from_leaf_cert_der(b"not a certificate"), None);
}
