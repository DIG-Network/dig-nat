//! Frozen BLS byte vectors — the drift detector a cross-crate agreement test cannot be.
//!
//! `tests/identity.rs` proves dig-tls and dig-identity AGREE with each other. That is necessary and
//! not sufficient: if a `chia-bls`/`blst` uplift changed the derivation on BOTH sides at once, every
//! agreement assertion would stay green while every deployed peer's cert binding and relay-descriptor
//! signature silently stopped verifying. Agreement is relative; these vectors are absolute.
//!
//! The constants below were captured on `chia-bls 0.26` (dig-tls 0.3.0 / dig-identity 0.6.0) and MUST
//! survive every future dependency uplift byte-for-byte. A change here is NOT a value to re-bless —
//! it is a wire-compatibility break with peers already running, and the uplift must stop.
//!
//! Secrets are derived from labels (never integer literals), so a second implementation can
//! reproduce every vector from this file alone.

use sha2::{Digest, Sha256};

/// The same label→scalar derivation `tests/identity.rs` uses, so the two suites pin one key set.
fn seed(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `(label, EIP-2333 secret scalar, compressed-G1-pubkey, G2-signature-over-MSG)`.
///
/// The SCALAR is pinned as well as the derived values: `SecretKey::from_seed` runs the EIP-2333 key
/// derivation, so pinning only the pubkey would leave a keygen change indistinguishable from a
/// curve-arithmetic change. Pinning the scalar also lets dig-identity reconstruct the key from this
/// file alone rather than from dig-tls — otherwise the dig-identity vectors would merely re-assert
/// the agreement `tests/identity.rs` already covers.
const VECTORS: &[(&str, &str, &str, &str)] = &[
    ("golden/a", "430846ca4c99c1ce5c2fdb103c1f113047b4197bbb713ed4261e2b218b3d5b2c", "b9a7ee8da67289fac94fea932839f2fc8b4d94591c0a6d7c67dc18f7c62da7cee6d761b108062e1f7ef62c0b2749e95d", "b199150e4c92badc84d848ed02be3cc53068ee3513bd2a88afe68fa1140034b54d9b1148e0e898dc268692c7c1ee2463093ab95828f8ba7f23e8541f695cde8870a772e149366ae289acfc8048b6978d6ad68f825e55e92887245f0f60c92639"),
    ("golden/b", "0944f13d9a4cc4a7cb31ca5dd7fc730df8c123eb37c0971c17c9ec5291d62c1f", "b4032594ff272b27fa0dc3305ed40cbdc61ded3f4476ad347e57db6b9524da289dede1c7f496f4a6896356e1bbdf5555", "a515b240b491407b66568e30bfb33e08dcb1e99a4b5609f548ab4c0f4e27080a0862b32708200e47f3c46c41440efa5417def7959104c2356ef883793e2bf895e76ad55e311657d0eb1dcfa81a10ec3146e5a75adfd49dbf8ae80b28eade20dd"),
    ("golden/zeros", "18bec3f816d796cc0697cce6412c7c124e4de42d47c0f329ee74a6ba44106d49", "95994ec450cad5d2c850b9d2df76cf0d1318db0551ee7bd06d95169567c3e4af59cfe89465003587ff8b3e8dc3b82af7", "a765d42e738d1abde4a64e60ef697916a0c821646119da749239c05ce0e7969d0959712ece2a2e157b6cd34787c7c8b402b45e6d604f7f06946542b23e45970179a87de579e2435a436e4fba93a51f3f124863b203c2c838afd52689d4900fe4"),
];

/// Pinned so the signed bytes are part of the vector, not an incidental of the test.
const MSG: &[u8] = b"dig-nat frozen BLS vector v1";

/// dig-tls derives the exact G1 public keys it derived on chia-bls 0.26.
#[test]
fn dig_tls_g1_pubkeys_are_unchanged() {
    for (label, want_sk, want_pub, _) in VECTORS {
        let sk = dig_tls::bls::SecretKey::from_seed(&seed(label));
        assert_eq!(
            hex(&sk.to_bytes()),
            *want_sk,
            "dig-tls EIP-2333 keygen drifted for {label} — the node identity itself would change"
        );
        assert_eq!(
            hex(&dig_tls::bls::public_key_bytes(&sk)),
            *want_pub,
            "dig-tls G1 pubkey drifted for {label} — deployed cert bindings would stop matching"
        );
    }
}

/// dig-identity derives the same frozen G1 public keys.
#[test]
fn dig_identity_g1_pubkeys_are_unchanged() {
    for (label, want_sk, want_pub, _) in VECTORS {
        let sk =
            dig_identity::bls::SecretKey::from_bytes(&decode::<32>(want_sk)).expect("valid scalar");
        assert_eq!(
            hex(&dig_identity::public_key_bytes(&sk)),
            *want_pub,
            "dig-identity G1 pubkey drifted for {label}"
        );
    }
}

/// BLS AugScheme signing is deterministic, so the signature bytes are a vector too — this is what a
/// `RelayDescriptor.signature` contains and what every existing signed descriptor must still verify as.
#[test]
fn dig_tls_g2_signatures_are_unchanged() {
    for (label, _, _, want_sig) in VECTORS {
        let sk = dig_tls::bls::SecretKey::from_seed(&seed(label));
        assert_eq!(
            hex(&dig_tls::bls::sign_message(&sk, MSG)),
            *want_sig,
            "dig-tls G2 signature drifted for {label} — already-published descriptors would fail"
        );
    }
}

/// The same signature bytes from dig-identity, whose `verify_signature` gates `verify_relay_descriptor`.
#[test]
fn dig_identity_g2_signatures_are_unchanged() {
    for (label, want_sk, _, want_sig) in VECTORS {
        let sk =
            dig_identity::bls::SecretKey::from_bytes(&decode::<32>(want_sk)).expect("valid scalar");
        assert_eq!(
            hex(&dig_identity::sign_message(&sk, MSG)),
            *want_sig,
            "dig-identity G2 signature drifted for {label}"
        );
    }
}

/// A frozen public key still verifies its frozen signature — proves the vectors are a consistent
/// triple rather than three independently-drifting strings.
#[test]
fn frozen_pubkey_verifies_frozen_signature() {
    for (label, _, want_pub, want_sig) in VECTORS {
        let pk: [u8; 48] = decode(want_pub);
        let sig: [u8; 96] = decode96(want_sig);
        assert!(
            dig_identity::verify_signature(&pk, MSG, &sig),
            "frozen vector for {label} must verify under dig-identity"
        );
        assert!(
            dig_tls::bls::verify_signature(&pk, MSG, &sig),
            "frozen vector for {label} must verify under dig-tls"
        );
    }
}

fn decode<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex vector");
    }
    out
}

fn decode96(s: &str) -> [u8; 96] {
    decode::<96>(s)
}
