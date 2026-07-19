//! Cert BLS-binding — the anti-substitution ROOT of the DIG recipient-seal family (#1204).
//!
//! A DIG peer's transport identity is `peer_id = SHA-256(TLS SPKI DER)` ([`crate::identity`]). The
//! recipient-seal family (#1075 node↔node, #1199 relay) needs to seal a payload to a peer's **BLS
//! G1 identity key** so a misdelivery cannot be opened by the wrong node. That is only safe if
//! `peer_id ↔ BLS_pub` is cryptographically BOUND — otherwise a man-in-the-middle could advertise a
//! victim's `peer_id` with its OWN BLS key and read the seal. This module is that binding.
//!
//! ## The binding
//!
//! The node/relay embeds its 48-byte compressed **BLS G1 public key** in its self-signed mTLS leaf
//! certificate as a custom X.509 extension ([`DIG_BLS_BINDING_OID`]), self-attested by a 96-byte
//! **BLS G2 signature over the leaf's SPKI DER**. Because `peer_id = SHA-256(SPKI)`, signing the
//! SPKI commits the holder's BLS key to exactly that `peer_id`:
//!
//! - An attacker cannot present a victim's `peer_id` without the victim's exact SPKI (else the hash
//!   differs) — and presenting that SPKI needs the victim's TLS private key (rustls proves cert-key
//!   possession during the handshake).
//! - An attacker cannot claim a victim's `peer_id` under their OWN BLS key: the self-attestation is
//!   an AugScheme signature (which itself covers the signing pubkey) verified against the *embedded*
//!   pubkey over the *presented* SPKI, so a forged pair fails.
//! - An attacker cannot replay the victim's (pubkey, sig) with a different cert: the signature
//!   covers the victim's SPKI, not the attacker's.
//!
//! ## Rollout policy (capability-negotiated, fail-closed for the strict mode)
//!
//! Existing peers have un-bound (no-extension) certs, so the binding is **additive** — the extension
//! is a non-critical, unknown-to-old-verifiers X.509 extension (§5.1 spirit: old readers ignore it).
//! Verification is governed by a LOCAL [`BindingPolicy`] (NOT wire-negotiated, so it cannot be
//! downgraded by a peer):
//!
//! - [`BindingPolicy::Off`] — do not verify (pre-adoption / opt-out).
//! - [`BindingPolicy::Opportunistic`] — **the rollout default**: verify a binding when present,
//!   reject a present-but-INVALID one, accept an ABSENT one. Verifies without breaking legacy peers.
//! - [`BindingPolicy::Required`] — strict: a valid binding is mandatory; ABSENT and INVALID are both
//!   rejected. A downgrade that strips the extension is therefore rejected — it can never silently
//!   disable a required-mode session.

use rcgen::{CertificateParams, CustomExtension, KeyPair};

use dig_identity::bls::SecretKey;
use dig_identity::{g1_subgroup_check, public_key_bytes, sign_message, verify_signature};

/// The DIG BLS-binding X.509 extension OID (dotted-decimal arc form used by `rcgen`).
///
/// A DIG **provisional private-use** OID under the `1.3.6.1.4.1` (IANA private enterprise) arc. It
/// is not a registered PEN assignment; it is a stable, ecosystem-canonical identifier for the DIG
/// BLS peer_id-binding extension. Recorded in the `canonical` skill + dig-nat `SPEC.md` so no second
/// implementation invents a different arc. [`DIG_BLS_BINDING_OID_STR`] is the same OID in the
/// dotted-decimal string form used to match a parsed certificate's extensions.
pub const DIG_BLS_BINDING_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 58968, 1, 1];

/// The [`DIG_BLS_BINDING_OID`] in dotted-decimal string form (for matching parsed cert extensions).
/// A unit test asserts it equals the arc form so the two can never drift.
pub const DIG_BLS_BINDING_OID_STR: &str = "1.3.6.1.4.1.58968.1.1";

/// Version byte of the binding extension value (v1). Newer writers MAY bump this; verifiers dispatch
/// on it and MUST keep accepting every version they understand (§5.1 additive-forever).
pub const BINDING_VERSION_V1: u8 = 1;

/// Length of the v1 extension value: `version(1) || bls_pub(48) || bls_sig(96)`.
const BINDING_V1_LEN: usize = 1 + 48 + 96;

/// Domain-separation context prefixed to the SPKI DER before the BLS-G2 self-attestation is signed /
/// verified. Binds the signature to *this* purpose (a DIG cert peer_id-binding, v1) so it can never
/// be cross-protocol-replayed as some other DIG BLS signature.
const BINDING_SIG_CONTEXT: &[u8] = b"dig-nat/cert-bls-binding/v1";

/// The exact byte string the BLS-G2 self-attestation covers: [`BINDING_SIG_CONTEXT`] then the leaf's
/// SPKI DER. Used identically when signing (attest) and verifying.
pub fn binding_message(spki_der: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(BINDING_SIG_CONTEXT.len() + spki_der.len());
    msg.extend_from_slice(BINDING_SIG_CONTEXT);
    msg.extend_from_slice(spki_der);
    msg
}

/// Encode the v1 extension value from a BLS G1 pubkey + its G2 self-attestation signature.
pub fn encode_binding_extension_value(bls_pub: &[u8; 48], bls_sig: &[u8; 96]) -> Vec<u8> {
    let mut value = Vec::with_capacity(BINDING_V1_LEN);
    value.push(BINDING_VERSION_V1);
    value.extend_from_slice(bls_pub);
    value.extend_from_slice(bls_sig);
    value
}

/// The raw contents of a parsed (not-yet-verified) binding extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertBlsBinding {
    /// The claimed 48-byte compressed BLS G1 public key.
    pub bls_pub: [u8; 48],
    /// The 96-byte BLS G2 self-attestation over [`binding_message`] of the leaf SPKI.
    pub bls_sig: [u8; 96],
}

/// Parse a v1 extension value into its fields. Returns `None` for a wrong length or an unrecognised
/// version — an unknown version is treated as "no binding this verifier understands" (additive
/// forward-compat), NOT as tampering.
pub fn parse_binding_extension_value(value: &[u8]) -> Option<CertBlsBinding> {
    if value.first().copied()? != BINDING_VERSION_V1 || value.len() != BINDING_V1_LEN {
        return None;
    }
    let mut bls_pub = [0u8; 48];
    let mut bls_sig = [0u8; 96];
    bls_pub.copy_from_slice(&value[1..49]);
    bls_sig.copy_from_slice(&value[49..145]);
    Some(CertBlsBinding { bls_pub, bls_sig })
}

/// The result of checking a leaf certificate for a valid BLS binding, BEFORE the policy is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingOutcome {
    /// A cryptographically valid binding: `peer_id ↔ bls_pub` is proven. Carries the verified pubkey.
    Bound {
        /// The verified 48-byte BLS G1 public key the `peer_id` is bound to.
        bls_pub: [u8; 48],
    },
    /// No DIG BLS-binding extension is present (a legacy / un-bound peer).
    Absent,
    /// A binding extension IS present but did not verify — malformed, bad subgroup point, or the
    /// self-attestation signature did not check out. Carries a static reason for logging.
    Invalid(&'static str),
}

/// The verification stance for a peer's cert binding — a LOCAL decision (never wire-negotiated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BindingPolicy {
    /// Do not verify the binding at all (pre-adoption / explicit opt-out).
    Off,
    /// The rollout default: verify-if-present, reject-if-present-but-invalid, accept-if-absent.
    #[default]
    Opportunistic,
    /// Strict: a valid binding is mandatory; both ABSENT and INVALID are rejected (anti-downgrade).
    Required,
}

/// Apply a [`BindingPolicy`] to a [`BindingOutcome`], deciding whether the handshake may proceed.
///
/// Returns `Ok(Some(bls_pub))` when a binding was verified, `Ok(None)` when the connection is
/// permitted without a verified binding (Off, or Opportunistic-and-absent), and `Err(reason)` when
/// the policy REJECTS the peer (fail-closed).
pub fn evaluate(
    outcome: &BindingOutcome,
    policy: BindingPolicy,
) -> Result<Option<[u8; 48]>, &'static str> {
    match (policy, outcome) {
        // Off never verifies and never rejects on binding grounds.
        (BindingPolicy::Off, _) => Ok(None),

        // A valid binding is always accepted (any non-Off policy).
        (_, BindingOutcome::Bound { bls_pub }) => Ok(Some(*bls_pub)),

        // Opportunistic tolerates a legacy peer but never a tampered binding.
        (BindingPolicy::Opportunistic, BindingOutcome::Absent) => Ok(None),
        (BindingPolicy::Opportunistic, BindingOutcome::Invalid(reason)) => Err(reason),

        // Required rejects both absence (anti-downgrade) and invalidity.
        (BindingPolicy::Required, BindingOutcome::Absent) => {
            Err("cert BLS binding required but absent (possible downgrade)")
        }
        (BindingPolicy::Required, BindingOutcome::Invalid(reason)) => Err(reason),
    }
}

/// Verify the BLS binding carried by a DER-encoded leaf certificate.
///
/// Extracts the [`DIG_BLS_BINDING_OID`] extension, and — when present — recomputes the binding
/// message from the cert's own SPKI, subgroup-checks the embedded G1 pubkey, and verifies the BLS-G2
/// self-attestation against it. The returned [`BindingOutcome`] is then fed to [`evaluate`] with the
/// verifier's [`BindingPolicy`].
///
/// A certificate that cannot be parsed as X.509 returns [`BindingOutcome::Invalid`] (a peer that
/// reached cert verification presented SOMETHING; an unparseable leaf is a hard reject regardless of
/// policy in Opportunistic/Required — the mTLS layer would fail on it anyway).
pub fn verify_binding_from_leaf_cert(cert_der: &[u8]) -> BindingOutcome {
    let Ok((_, x509)) = x509_parser::parse_x509_certificate(cert_der) else {
        return BindingOutcome::Invalid("leaf certificate could not be parsed as X.509");
    };
    let spki_der = x509.tbs_certificate.subject_pki.raw;

    let mut binding_value: Option<&[u8]> = None;
    for ext in x509.extensions() {
        if ext.oid.to_id_string() == DIG_BLS_BINDING_OID_STR {
            binding_value = Some(ext.value);
            break;
        }
    }
    let Some(value) = binding_value else {
        return BindingOutcome::Absent;
    };

    let Some(binding) = parse_binding_extension_value(value) else {
        return BindingOutcome::Invalid("binding extension malformed or unknown version");
    };
    // Reject a small-subgroup / identity / non-canonical G1 point BEFORE trusting it as a seal target.
    if !g1_subgroup_check(&binding.bls_pub) {
        return BindingOutcome::Invalid("binding BLS pubkey failed the G1 subgroup check");
    }
    // The self-attestation must be over THIS leaf's SPKI (which fixes peer_id = SHA-256(SPKI)).
    if !verify_signature(
        &binding.bls_pub,
        &binding_message(spki_der),
        &binding.bls_sig,
    ) {
        return BindingOutcome::Invalid(
            "binding BLS self-attestation did not verify over the SPKI",
        );
    }
    BindingOutcome::Bound {
        bls_pub: binding.bls_pub,
    }
}

/// Errors from building a BLS-bound leaf certificate.
#[derive(Debug, thiserror::Error)]
pub enum CertBindingError {
    /// The underlying `rcgen` certificate build failed.
    #[error("certificate build failed: {0}")]
    Rcgen(#[from] rcgen::Error),
}

/// Build a self-signed mTLS leaf certificate (DER) that CARRIES the BLS peer_id-binding extension.
///
/// `key_pair` is the node/relay TLS key pair (its public key becomes the cert SPKI, hence `peer_id`);
/// `bls_sk` is the node/relay BLS G1 identity secret key (dig-identity slot 0x0010). The returned
/// certificate embeds `bls_sk`'s public key + a BLS-G2 self-attestation over the SPKI, so any peer
/// can verify `peer_id ↔ bls_pub` via [`verify_binding_from_leaf_cert`].
///
/// dig-node / dig-relay call this to mint their bound identity certs (the transport keygen stays in
/// those repos; this is the one place the binding is assembled so it can never drift).
pub fn build_bound_cert(
    key_pair: &KeyPair,
    bls_sk: &SecretKey,
    subject_alt_names: Vec<String>,
) -> Result<Vec<u8>, CertBindingError> {
    // The SPKI DER the cert will carry — signing it commits the BLS key to this exact peer_id.
    let spki_der = key_pair.public_key_der();
    let bls_pub = public_key_bytes(bls_sk);
    let bls_sig = sign_message(bls_sk, &binding_message(&spki_der));
    let ext_value = encode_binding_extension_value(&bls_pub, &bls_sig);

    let mut params = CertificateParams::new(subject_alt_names)?;
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            DIG_BLS_BINDING_OID,
            ext_value,
        ));
    let cert = params.self_signed(key_pair)?;
    Ok(cert.der().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_identity::{derive_identity_sk, master_secret_key_from_seed};
    use sha2::{Digest, Sha256};

    /// A deterministic node BLS identity key from a label (test-only; mirrors dig-identity's KAT
    /// helper). Derived — never an integer-literal secret (CodeQL "hard-coded crypto value").
    fn node_bls_sk(label: &str) -> SecretKey {
        let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        derive_identity_sk(&master_secret_key_from_seed(&seed))
    }

    fn tls_key_pair() -> KeyPair {
        KeyPair::generate().expect("generate TLS key pair")
    }

    #[test]
    fn oid_arc_and_string_forms_agree() {
        let dotted = DIG_BLS_BINDING_OID
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(".");
        assert_eq!(dotted, DIG_BLS_BINDING_OID_STR);
    }

    #[test]
    fn extension_value_round_trips() {
        let bls_pub = [7u8; 48];
        let bls_sig = [9u8; 96];
        let value = encode_binding_extension_value(&bls_pub, &bls_sig);
        assert_eq!(value.len(), BINDING_V1_LEN);
        let parsed = parse_binding_extension_value(&value).expect("parses");
        assert_eq!(parsed.bls_pub, bls_pub);
        assert_eq!(parsed.bls_sig, bls_sig);
    }

    #[test]
    fn parse_rejects_bad_length_and_unknown_version() {
        assert_eq!(parse_binding_extension_value(&[]), None);
        assert_eq!(
            parse_binding_extension_value(&[BINDING_VERSION_V1; 10]),
            None
        );
        // Right length, wrong version byte.
        let mut wrong = vec![0u8; BINDING_V1_LEN];
        wrong[0] = 0xFE;
        assert_eq!(parse_binding_extension_value(&wrong), None);
    }

    // --- The anti-substitution property: a valid bound cert verifies ---
    #[test]
    fn valid_bound_cert_verifies() {
        let kp = tls_key_pair();
        let bls_sk = node_bls_sk("cert-binding/valid");
        let cert = build_bound_cert(&kp, &bls_sk, vec!["peer.dig".into()]).unwrap();
        match verify_binding_from_leaf_cert(&cert) {
            BindingOutcome::Bound { bls_pub } => {
                assert_eq!(
                    bls_pub,
                    public_key_bytes(&bls_sk),
                    "verified pubkey is the signer's"
                );
            }
            other => panic!("expected Bound, got {other:?}"),
        }
    }

    #[test]
    fn cert_without_extension_is_absent() {
        let c = rcgen::generate_simple_self_signed(vec!["peer.dig".into()]).unwrap();
        assert_eq!(
            verify_binding_from_leaf_cert(c.cert.der()),
            BindingOutcome::Absent
        );
    }

    // --- ANTI-SUBSTITUTION: attacker's BLS key under a cert it did not sign for ---
    #[test]
    fn anti_substitution_wrong_bls_key_rejected() {
        // Attacker builds a cert binding with a sig from key A but embeds key B's pubkey.
        let kp = tls_key_pair();
        let victim_sk = node_bls_sk("cert-binding/victim");
        let attacker_sk = node_bls_sk("cert-binding/attacker");
        let spki = kp.public_key_der();
        // Sign with the victim key, but claim the attacker's pubkey (a substitution attempt).
        let sig = sign_message(&victim_sk, &binding_message(&spki));
        let ext = encode_binding_extension_value(&public_key_bytes(&attacker_sk), &sig);
        let mut params = CertificateParams::new(vec!["peer.dig".into()]).unwrap();
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(DIG_BLS_BINDING_OID, ext));
        let cert = params.self_signed(&kp).unwrap().der().to_vec();
        assert!(
            matches!(
                verify_binding_from_leaf_cert(&cert),
                BindingOutcome::Invalid(_)
            ),
            "a sig that does not verify under the embedded pubkey must be rejected"
        );
    }

    // --- ANTI-SUBSTITUTION: replaying a valid binding under a DIFFERENT SPKI (different peer_id) ---
    #[test]
    fn anti_substitution_binding_replayed_on_other_cert_rejected() {
        let kp_a = tls_key_pair();
        let bls_sk = node_bls_sk("cert-binding/replay");
        // Build a valid binding for cert A.
        let sig = sign_message(&bls_sk, &binding_message(&kp_a.public_key_der()));
        let ext = encode_binding_extension_value(&public_key_bytes(&bls_sk), &sig);
        // Graft that exact extension onto a DIFFERENT cert (kp_b → different SPKI → different peer_id).
        let kp_b = tls_key_pair();
        let mut params = CertificateParams::new(vec!["peer.dig".into()]).unwrap();
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(DIG_BLS_BINDING_OID, ext));
        let cert_b = params.self_signed(&kp_b).unwrap().der().to_vec();
        assert!(
            matches!(
                verify_binding_from_leaf_cert(&cert_b),
                BindingOutcome::Invalid(_)
            ),
            "a binding signed over cert A's SPKI must not verify inside cert B"
        );
    }

    // --- Subgroup check rejects a bad G1 point in the extension ---
    #[test]
    fn subgroup_check_rejects_bad_g1_point() {
        let kp = tls_key_pair();
        let bls_sk = node_bls_sk("cert-binding/subgroup");
        // A sig valid in shape but the embedded pubkey is a non-subgroup point (all-0xFF).
        let sig = sign_message(&bls_sk, &binding_message(&kp.public_key_der()));
        let ext = encode_binding_extension_value(&[0xFFu8; 48], &sig);
        let mut params = CertificateParams::new(vec!["peer.dig".into()]).unwrap();
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(DIG_BLS_BINDING_OID, ext));
        let cert = params.self_signed(&kp).unwrap().der().to_vec();
        assert!(matches!(
            verify_binding_from_leaf_cert(&cert),
            BindingOutcome::Invalid(_)
        ));
    }

    // --- Policy matrix ---
    #[test]
    fn policy_off_accepts_everything() {
        let pk = [1u8; 48];
        assert_eq!(
            evaluate(&BindingOutcome::Absent, BindingPolicy::Off),
            Ok(None)
        );
        assert_eq!(
            evaluate(&BindingOutcome::Invalid("x"), BindingPolicy::Off),
            Ok(None)
        );
        assert_eq!(
            evaluate(&BindingOutcome::Bound { bls_pub: pk }, BindingPolicy::Off),
            Ok(None)
        );
    }

    #[test]
    fn policy_opportunistic_accepts_absent_rejects_invalid() {
        let pk = [2u8; 48];
        assert_eq!(
            evaluate(&BindingOutcome::Absent, BindingPolicy::Opportunistic),
            Ok(None)
        );
        assert!(evaluate(
            &BindingOutcome::Invalid("bad"),
            BindingPolicy::Opportunistic
        )
        .is_err());
        assert_eq!(
            evaluate(
                &BindingOutcome::Bound { bls_pub: pk },
                BindingPolicy::Opportunistic
            ),
            Ok(Some(pk))
        );
    }

    #[test]
    fn policy_required_rejects_absent_and_invalid() {
        let pk = [3u8; 48];
        assert!(
            evaluate(&BindingOutcome::Absent, BindingPolicy::Required).is_err(),
            "anti-downgrade: a stripped extension is rejected in Required mode"
        );
        assert!(evaluate(&BindingOutcome::Invalid("bad"), BindingPolicy::Required).is_err());
        assert_eq!(
            evaluate(
                &BindingOutcome::Bound { bls_pub: pk },
                BindingPolicy::Required
            ),
            Ok(Some(pk))
        );
    }

    #[test]
    fn default_policy_is_opportunistic() {
        assert_eq!(BindingPolicy::default(), BindingPolicy::Opportunistic);
    }
}
