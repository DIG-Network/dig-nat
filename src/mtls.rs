//! mTLS layer — every peer connection is a **mutually-authenticated TLS** stream whose remote
//! `peer_id` is verified against the one the caller asked to reach.
//!
//! All DIG node-to-node comms are mutual TLS: both sides present a certificate, and each derives the
//! other's identity as `peer_id = SHA-256(TLS SubjectPublicKeyInfo DER)` (see [`crate::identity`],
//! matching dig-gossip). dig-nat establishes the transport AND wraps it in this mTLS session, so the
//! resulting [`crate::PeerConnection`] is always mutually authenticated with the peer_id verified.
//!
//! ## Verification model
//!
//! DIG peers use **self-signed** certificates whose *public key* IS the identity — there is no CA.
//! So the rustls verifier here does NOT check a chain of trust; instead it:
//!
//! 1. captures the peer's leaf certificate,
//! 2. derives its `peer_id` via [`crate::identity::peer_id_from_leaf_cert_der`], and
//! 3. **pins** it: if the caller supplied an expected `peer_id`, the handshake is rejected unless it
//!    matches; the derived id is always recorded so the caller learns exactly who it connected to.
//!
//! This is the standard "trust-on-first-use / key-is-identity" model for a self-authenticating P2P
//! overlay, and it is what makes `peer_id` a meaningful authentication (not just a label).

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

use crate::cert_binding::{evaluate, verify_binding_from_leaf_cert, BindingPolicy};
use crate::identity::{peer_id_from_leaf_cert_der, PeerId};

/// The outcome of verifying a peer's certificate: the `peer_id` it presented, captured for the
/// caller. Shared via `Arc<Mutex<_>>` because rustls verifiers are `Sync` and run inside the
/// handshake.
#[derive(Debug, Default, Clone)]
pub struct CapturedPeerId(pub Arc<Mutex<Option<PeerId>>>);

impl CapturedPeerId {
    /// The `peer_id` derived from the certificate the peer presented, if the handshake reached cert
    /// verification.
    pub fn get(&self) -> Option<PeerId> {
        *self.0.lock().unwrap()
    }
}

/// The peer's verified BLS G1 identity pubkey, captured from the cert binding (#1204) when the
/// handshake carried a valid one. `None` means the peer presented no valid binding (a legacy peer
/// under [`BindingPolicy::Opportunistic`], or binding verification was [`BindingPolicy::Off`]). The
/// sealing layer (S2) seals to this key so a misdelivery cannot be opened by the wrong node.
#[derive(Debug, Default, Clone)]
pub struct CapturedBlsPub(pub Arc<Mutex<Option<[u8; 48]>>>);

impl CapturedBlsPub {
    /// The verified BLS G1 pubkey the peer's `peer_id` is bound to, if a valid binding was presented.
    pub fn get(&self) -> Option<[u8; 48]> {
        *self.0.lock().unwrap()
    }
}

/// A rustls [`ServerCertVerifier`] for the DIG self-authenticating overlay.
///
/// It does not validate a CA chain (DIG certs are self-signed and the *key* is the identity). It
/// derives `peer_id = SHA-256(SPKI DER)` from the presented leaf, records it into [`Self::captured`]
/// for the caller, and — when [`Self::expected`] is set — REJECTS the handshake unless the derived
/// id matches. Signature checks (that the peer actually holds the private key for the presented key)
/// are delegated to ring's default crypto provider via [`Self::defaults`].
#[derive(Debug)]
pub struct PeerIdPinningVerifier {
    /// The peer_id the caller wants to reach; `None` = accept any (record-only, e.g. inbound).
    expected: Option<PeerId>,
    /// Where the derived peer_id is written so the caller can read who connected.
    captured: CapturedPeerId,
    /// The BLS peer_id-binding stance (#1204). [`BindingPolicy::Off`] = do not verify the binding.
    binding_policy: BindingPolicy,
    /// Where the verified peer BLS pubkey is written (when a valid binding was presented).
    captured_bls: CapturedBlsPub,
    /// Supported signature schemes, from the process crypto provider.
    defaults: Vec<SignatureScheme>,
}

impl PeerIdPinningVerifier {
    /// Build a verifier that pins `expected` (or accepts any peer when `None`) and writes the
    /// derived id into `captured`. The BLS cert binding is NOT verified ([`BindingPolicy::Off`]) —
    /// use [`PeerIdPinningVerifier::with_binding`] to enable + capture it.
    pub fn new(expected: Option<PeerId>, captured: CapturedPeerId) -> Self {
        PeerIdPinningVerifier {
            expected,
            captured,
            binding_policy: BindingPolicy::Off,
            captured_bls: CapturedBlsPub::default(),
            defaults: default_signature_schemes(),
        }
    }

    /// Enable BLS cert-binding verification (#1204) under `policy`, writing the verified peer BLS
    /// pubkey into `captured_bls`. Under [`BindingPolicy::Required`] a missing/invalid binding
    /// REJECTS the handshake (fail-closed, anti-downgrade); under [`BindingPolicy::Opportunistic`] a
    /// present-but-invalid binding is rejected while an absent one is tolerated (legacy peers).
    pub fn with_binding(mut self, policy: BindingPolicy, captured_bls: CapturedBlsPub) -> Self {
        self.binding_policy = policy;
        self.captured_bls = captured_bls;
        self
    }
}

impl ServerCertVerifier for PeerIdPinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let derived = peer_id_from_leaf_cert_der(end_entity.as_ref()).ok_or_else(|| {
            TlsError::General("peer leaf certificate could not be parsed as X.509".to_string())
        })?;
        // Record who we connected to regardless of the pin outcome.
        *self.captured.0.lock().unwrap() = Some(derived);
        if let Some(expected) = self.expected {
            if derived != expected {
                return Err(TlsError::General(format!(
                    "peer_id mismatch: expected {expected}, got {derived}"
                )));
            }
        }

        // Verify the BLS peer_id↔pubkey binding (#1204) per the configured policy. `Off` short-circuits
        // (no crypto); otherwise a present-but-invalid binding always rejects, and `Required` also
        // rejects an absent binding (fail-closed / anti-downgrade). A verified binding's pubkey is
        // captured for the sealing layer to seal to.
        if self.binding_policy != BindingPolicy::Off {
            let outcome = verify_binding_from_leaf_cert(end_entity.as_ref());
            match evaluate(&outcome, self.binding_policy) {
                Ok(bls_pub) => *self.captured_bls.0.lock().unwrap() = bls_pub,
                Err(reason) => {
                    return Err(TlsError::General(format!(
                        "peer {derived} rejected by cert BLS binding policy: {reason}"
                    )))
                }
            }
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.defaults.clone()
    }
}

/// The signature schemes ring's provider supports — used for [`ServerCertVerifier::supported_verify_schemes`].
fn default_signature_schemes() -> Vec<SignatureScheme> {
    rustls::crypto::ring::default_provider()
        .signature_verification_algorithms
        .supported_schemes()
}
