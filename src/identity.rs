//! Peer identity — `peer_id = SHA-256(TLS SubjectPublicKeyInfo DER)`.
//!
//! This matches `dig-gossip`'s [`peer_id_from_tls_spki_der`] exactly: the identifier is the
//! SHA-256 digest of the ASN.1 `SubjectPublicKeyInfo` sequence (algorithm id + subjectPublicKey
//! bit string) lifted from the peer's leaf X.509 certificate. Every node-to-node connection is
//! mutually-authenticated TLS, so each side derives the other's `PeerId` from the certificate
//! presented during the TLS handshake.
//!
//! `dig-nat` deliberately **re-implements** this (rather than depending on the `dig-gossip` crate)
//! because `dig-nat` is a foundational transport crate and `dig-gossip` pulls the entire L2
//! gossip/consensus/Chia TLS stack. The digest is trivial and pinned by a cross-crate conformance
//! test (`tests/identity.rs`) so the two never drift. The superproject `SYSTEM.md` records the
//! change-impact edge.
//!
//! [`peer_id_from_tls_spki_der`]: https://github.com/DIG-Network/dig-gossip

use std::fmt;

use sha2::{Digest, Sha256};

/// A peer's stable network identity: the 32-byte SHA-256 of its TLS SPKI DER.
///
/// Byte-for-byte equal to `dig-gossip`'s `PeerId` value (there it is a `chia-protocol::Bytes32`).
/// `dig-nat` keeps its own thin newtype so it does not depend on the Chia crate stack, but the
/// underlying 32 bytes and the derivation are identical.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// Construct from raw 32 bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        PeerId(bytes)
    }

    /// The raw 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex encoding (the canonical string form used in the relay wire's `peer_id` field
    /// and in `control.relayStatus`).
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
        }
        s
    }

    /// Parse a 64-char lowercase/uppercase hex string. Returns `None` if the length or alphabet is
    /// wrong — callers map that to [`crate::NatError::InvalidConfig`].
    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        let bytes = hex.as_bytes();
        for (i, chunk) in bytes.chunks(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16)?;
            let lo = (chunk[1] as char).to_digit(16)?;
            out[i] = ((hi << 4) | lo) as u8;
        }
        Some(PeerId(out))
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", self.to_hex())
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Derive a [`PeerId`] from a TLS **SubjectPublicKeyInfo** block in PKIX DER form.
///
/// `spki_der` must be the full ASN.1 `SubjectPublicKeyInfo` sequence (algorithm id + subjectPublicKey
/// bit string) — **not** the bare public-key bit string. This is the same input `dig-gossip` uses;
/// [`peer_id_from_leaf_cert_der`] extracts it from a whole leaf certificate for you.
pub fn peer_id_from_tls_spki_der(spki_der: &[u8]) -> PeerId {
    let digest = Sha256::digest(spki_der);
    let bytes: [u8; 32] = digest.into();
    PeerId(bytes)
}

/// Extract the SubjectPublicKeyInfo DER from a leaf X.509 certificate (DER-encoded) and derive the
/// [`PeerId`]. This is what the mTLS layer calls on the certificate the peer presents.
///
/// Returns `None` if the certificate cannot be parsed as X.509.
pub fn peer_id_from_leaf_cert_der(cert_der: &[u8]) -> Option<PeerId> {
    let (_, x509) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    let spki_der = x509.tbs_certificate.subject_pki.raw;
    Some(peer_id_from_tls_spki_der(spki_der))
}
