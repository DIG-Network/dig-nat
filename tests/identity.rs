//! Peer identity + cross-crate BLS conformance.
//!
//! dig-nat now DELEGATES `peer_id` + the #1204 cert BLS-binding to `dig-tls` (re-exported here). Two
//! things must hold and are pinned below:
//!
//! 1. `peer_id = SHA-256(TLS SPKI DER)` — the derivation dig-nat re-exports must be exactly that (so
//!    it stays byte-identical to dig-gossip's).
//! 2. **The BLS conformance the whole extraction rests on:** dig-tls does its BLS G1/G2 work via
//!    `chia-bls`/`blst` on raw bytes, WITHOUT depending on `dig-identity` (a same-level L00 crate).
//!    dig-identity does the SAME work via its own `chia-bls`. dig-tls's `bls.rs` doc-comment
//!    explicitly defers the "the two agree byte-for-byte" check to this integration level, where both
//!    crates are in scope. If a future `chia-bls`/`blst` bump ever made the two diverge, the seal
//!    target a peer advertises via its dig-tls cert binding would not match what dig-identity signs/
//!    verifies — silently breaking the recipient-seal family. These tests FAIL if they ever diverge.

use dig_nat::{peer_id_from_leaf_cert_der, peer_id_from_tls_spki_der, NodeCert, PeerId};
use sha2::{Digest, Sha256};

/// A deterministic 32-byte secret scalar from a label (never an integer-literal secret).
fn test_bls_sk(label: &str) -> dig_tls::bls::SecretKey {
    let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
    dig_tls::bls::SecretKey::from_seed(&seed)
}

/// The derivation is exactly SHA-256 of the SPKI DER — pins the algorithm so it can never silently
/// diverge from dig-gossip's `peer_id_from_tls_spki_der`.
#[test]
fn peer_id_is_sha256_of_spki_der() {
    let spki = b"a fake SubjectPublicKeyInfo DER blob";
    let id = peer_id_from_tls_spki_der(spki);
    let expected: [u8; 32] = Sha256::digest(spki).into();
    assert_eq!(id.as_bytes(), &expected);
}

/// dig-gossip defines `peer_id_from_tls_spki_der(spki) = Sha256::digest(spki)`; dig-nat (via dig-tls)
/// MUST match byte-for-byte so a node computes the same id for a peer regardless of which crate does
/// it.
#[test]
fn conformance_with_dig_gossip_derivation() {
    for sample in [&b""[..], &b"x"[..], &[0u8; 91][..], &[0xabu8; 256][..]] {
        let ours = peer_id_from_tls_spki_der(sample);
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

/// A real CA-signed `NodeCert`'s SPKI derives the SAME id whether taken from the whole leaf cert or
/// from the extracted SPKI — proves `peer_id_from_leaf_cert_der` lifts the right bytes.
#[test]
fn leaf_cert_and_spki_agree() {
    let node = NodeCert::generate_signed(&test_bls_sk("identity/leaf")).unwrap();
    let from_leaf = peer_id_from_leaf_cert_der(node.cert_der()).expect("leaf parses");
    let from_spki = peer_id_from_tls_spki_der(node.spki_der());
    assert_eq!(from_leaf, from_spki);
    assert_eq!(from_leaf, node.peer_id());
}

#[test]
fn leaf_cert_parse_failure_is_none() {
    assert_eq!(peer_id_from_leaf_cert_der(b"not a certificate"), None);
}

// --- The cross-crate BLS conformance (the REQUIRED carry-forward from the adversarial gate) ---

/// The SAME 32-byte secret scalar, reconstructed in BOTH crates' `chia-bls`, MUST yield the SAME
/// 48-byte compressed G1 public key. This is the byte-level agreement the cert binding depends on:
/// dig-tls embeds `dig_tls::bls::public_key_bytes` in the cert; a peer resolves the seal target from
/// dig-identity — they must be identical.
#[test]
fn dig_tls_and_dig_identity_derive_the_same_g1_pubkey() {
    for label in ["conf/a", "conf/b", "conf/zeros"] {
        let tls_sk = test_bls_sk(label);
        let tls_pub = dig_tls::bls::public_key_bytes(&tls_sk);

        // dig-identity reconstructs the same scalar from its serialized bytes (bridging any chia-bls
        // version difference through the canonical 32-byte encoding).
        let id_sk = dig_identity::bls::SecretKey::from_bytes(&tls_sk.to_bytes())
            .expect("valid secret scalar");
        let id_pub = dig_identity::public_key_bytes(&id_sk);

        assert_eq!(
            tls_pub, id_pub,
            "dig-tls and dig-identity must derive byte-identical G1 pubkeys for {label}"
        );
    }
}

/// Signatures made under one crate's BLS backend MUST verify under the other's, both directions — so
/// a cert binding signed via dig-tls verifies with dig-identity (and vice-versa). A future
/// chia-bls/blst divergence would break exactly this.
#[test]
fn bls_signatures_cross_verify_between_crates() {
    let tls_sk = test_bls_sk("conf/xverify");
    let id_sk = dig_identity::bls::SecretKey::from_bytes(&tls_sk.to_bytes()).unwrap();

    let tls_pub = dig_tls::bls::public_key_bytes(&tls_sk);
    let id_pub = dig_identity::public_key_bytes(&id_sk);
    let msg = b"dig-nat cross-crate binding conformance";

    // dig-tls signs → dig-identity verifies.
    let sig_tls = dig_tls::bls::sign_message(&tls_sk, msg);
    assert!(
        dig_identity::verify_signature(&id_pub, msg, &sig_tls),
        "dig-identity must verify a signature dig-tls produced"
    );

    // dig-identity signs → dig-tls verifies.
    let sig_id = dig_identity::sign_message(&id_sk, msg);
    assert!(
        dig_tls::bls::verify_signature(&tls_pub, msg, &sig_id),
        "dig-tls must verify a signature dig-identity produced"
    );
}

/// End-to-end: the BLS pubkey dig-tls BINDS into a real `NodeCert` (and that
/// [`dig_nat::verify_binding_from_leaf_cert`] recovers) equals the one dig-identity derives for the
/// same secret — the anti-substitution seal target is consistent across the extraction boundary.
#[test]
fn cert_binding_pubkey_matches_dig_identity() {
    use dig_nat::{verify_binding_from_leaf_cert, BindingOutcome};

    let tls_sk = test_bls_sk("conf/cert-bind");
    let node = NodeCert::generate_signed(&tls_sk).unwrap();

    let id_sk = dig_identity::bls::SecretKey::from_bytes(&tls_sk.to_bytes()).unwrap();
    let id_pub = dig_identity::public_key_bytes(&id_sk);

    match verify_binding_from_leaf_cert(node.cert_der()) {
        BindingOutcome::Bound { bls_pub } => assert_eq!(
            bls_pub, id_pub,
            "the cert-bound seal target equals dig-identity's derived pubkey"
        ),
        other => panic!("expected a valid Bound binding, got {other:?}"),
    }
}
