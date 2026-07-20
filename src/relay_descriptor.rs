//! Relay descriptor verification (#1199) — a self-authenticating (peer_id, addrs, BLS_pub) record.
//!
//! On a DIRECT connection the `dig-tls` cert BLS-binding extension is the authoritative,
//! tamper-proof `peer_id ↔ BLS_pub` binding. But a node also learns of relays/peers BEFORE dialing —
//! from PEX/DHT/relay registration records — and #1199's relay store-and-forward routes past a relay
//! with no direct handshake. Those discovery records must be self-authenticating so a MITM cannot
//! swap the advertised BLS key and read the seal.
//!
//! A [`RelayDescriptor`] carries the relay's `peer_id` (as the SHA-256 of its TLS SPKI DER), its BLS
//! G1 pubkey, dialable addresses, its network id, and an optional DID, all covered by a **BLS G2
//! signature** made with the relay's own BLS key. [`verify_relay_descriptor`] proves the record was
//! authored by the holder of that BLS key, that the key is a valid G1 point, that (on a live dial)
//! the `peer_id_spki_hash` matches the presented cert's SPKI, and — where a DID + a resolver are
//! available — that the DID resolves to the same BLS key on chain.

use std::net::SocketAddr;

use sha2::{Digest, Sha256};

use dig_identity::{g1_subgroup_check, verify_signature};

/// Domain-separation context for the descriptor signature (distinct from the cert-binding context so
/// a signature over one can never be replayed as the other).
const DESCRIPTOR_SIG_CONTEXT: &[u8] = b"dig-nat/relay-descriptor/v1";

/// Resolves a DID string to its on-chain BLS G1 identity pubkey (dig-identity's
/// `resolve_bls_public_key`), injected by the caller so dig-nat needs no chain access. Returns `None`
/// when the DID cannot be resolved (tolerated — best-effort).
pub type DidResolver<'a> = dyn Fn(&str) -> Option<[u8; 48]> + 'a;

/// A self-authenticating relay/peer discovery record: the advertised identity + reachability, signed
/// by the relay's own BLS G1 key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayDescriptor {
    /// The relay's `peer_id` as `SHA-256(TLS SPKI DER)` — must match the cert presented on a dial.
    pub peer_id_spki_hash: [u8; 32],
    /// The relay's 48-byte compressed BLS G1 identity public key (the seal target).
    pub bls_pub: [u8; 48],
    /// Dialable candidate addresses, IPv6-first (§5.2). Advisory; the cert binding is authoritative.
    pub addresses: Vec<SocketAddr>,
    /// The network id the relay serves (e.g. `DIG_MAINNET`).
    pub network_id: String,
    /// An optional DID the relay claims. When present AND a resolver is supplied, the DID MUST
    /// resolve to [`Self::bls_pub`] (nodes/relays are normally DID-less — this is best-effort).
    pub did: Option<String>,
    /// The 96-byte BLS G2 signature over [`RelayDescriptor::signing_bytes`], made with the BLS key
    /// whose public half is [`Self::bls_pub`].
    pub signature: [u8; 96],
}

/// Why a [`RelayDescriptor`] failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RelayDescriptorError {
    /// The advertised BLS pubkey is not a canonical, non-identity G1 subgroup point.
    #[error("relay descriptor BLS pubkey failed the G1 subgroup check")]
    BadBlsPubkey,
    /// The BLS signature did not verify under the advertised pubkey (forged / tampered record).
    #[error("relay descriptor signature did not verify")]
    BadSignature,
    /// The descriptor's `peer_id_spki_hash` does not match the SPKI presented on the live handshake.
    #[error("relay descriptor peer_id does not match the presented certificate")]
    PeerIdMismatch,
    /// A DID was present and resolvable, but it resolves to a DIFFERENT BLS key (substitution).
    #[error("relay descriptor DID resolves to a different BLS key")]
    DidMismatch,
}

impl RelayDescriptor {
    /// The canonical, length-prefixed byte string the [`RelayDescriptor::signature`] covers.
    ///
    /// Built by hand (not serde) so the signed bytes are deterministic and independent of any
    /// serialization framework — every field except the signature, each length-prefixed, in a fixed
    /// order, behind [`DESCRIPTOR_SIG_CONTEXT`].
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(DESCRIPTOR_SIG_CONTEXT);
        out.extend_from_slice(&self.peer_id_spki_hash);
        out.extend_from_slice(&self.bls_pub);

        out.extend_from_slice(&(self.addresses.len() as u32).to_le_bytes());
        for addr in &self.addresses {
            let s = addr.to_string();
            out.extend_from_slice(&(s.len() as u32).to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        }

        out.extend_from_slice(&(self.network_id.len() as u32).to_le_bytes());
        out.extend_from_slice(self.network_id.as_bytes());

        match &self.did {
            None => out.push(0),
            Some(did) => {
                out.push(1);
                out.extend_from_slice(&(did.len() as u32).to_le_bytes());
                out.extend_from_slice(did.as_bytes());
            }
        }
        out
    }
}

/// Verify a [`RelayDescriptor`] is authentic and (optionally) bound to a live cert + a resolvable DID.
///
/// - `presented_spki_der`: `Some(spki)` on a live dial — the descriptor's `peer_id_spki_hash` MUST
///   equal `SHA-256(spki)`. `None` for a pre-dial / store-and-forward check with no handshake yet.
/// - `did_resolver`: `Some(f)` to resolve a claimed DID to its on-chain BLS G1 key (dig-identity's
///   `resolve_bls_public_key`, injected by the caller so dig-nat needs no chain access). A DID that
///   resolves to a DIFFERENT key is rejected; a DID the resolver cannot resolve (`None`) is
///   tolerated (best-effort — nodes/relays are normally DID-less).
pub fn verify_relay_descriptor(
    descriptor: &RelayDescriptor,
    presented_spki_der: Option<&[u8]>,
    did_resolver: Option<&DidResolver<'_>>,
) -> Result<(), RelayDescriptorError> {
    // 1. The advertised seal target must be a valid G1 point before anything trusts it.
    if !g1_subgroup_check(&descriptor.bls_pub) {
        return Err(RelayDescriptorError::BadBlsPubkey);
    }
    // 2. The record must be self-signed by the holder of that BLS key.
    if !verify_signature(
        &descriptor.bls_pub,
        &descriptor.signing_bytes(),
        &descriptor.signature,
    ) {
        return Err(RelayDescriptorError::BadSignature);
    }
    // 3. On a live dial, the advertised peer_id must match the cert actually presented.
    if let Some(spki) = presented_spki_der {
        let hash: [u8; 32] = Sha256::digest(spki).into();
        if hash != descriptor.peer_id_spki_hash {
            return Err(RelayDescriptorError::PeerIdMismatch);
        }
    }
    // 4. Where a DID + resolver are available, a resolvable DID must agree with the advertised key.
    if let (Some(did), Some(resolve)) = (&descriptor.did, did_resolver) {
        if let Some(resolved) = resolve(did) {
            if resolved != descriptor.bls_pub {
                return Err(RelayDescriptorError::DidMismatch);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_identity::{
        bls::SecretKey, derive_identity_sk, master_secret_key_from_seed, public_key_bytes,
        sign_message,
    };

    fn node_bls_sk(label: &str) -> SecretKey {
        let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        derive_identity_sk(&master_secret_key_from_seed(&seed))
    }

    /// Build a validly-signed descriptor for a relay whose SPKI is `spki`.
    fn signed_descriptor(bls_sk: &SecretKey, spki: &[u8], did: Option<String>) -> RelayDescriptor {
        let peer_id_spki_hash: [u8; 32] = Sha256::digest(spki).into();
        let mut d = RelayDescriptor {
            peer_id_spki_hash,
            bls_pub: public_key_bytes(bls_sk),
            addresses: vec![
                "[::1]:9450".parse().unwrap(),
                "127.0.0.1:9450".parse().unwrap(),
            ],
            network_id: "DIG_MAINNET".to_string(),
            did,
            signature: [0u8; 96],
        };
        d.signature = sign_message(bls_sk, &d.signing_bytes());
        d
    }

    #[test]
    fn valid_descriptor_verifies() {
        let sk = node_bls_sk("relay-desc/valid");
        let spki = b"fake-spki-der-bytes";
        let d = signed_descriptor(&sk, spki, None);
        assert!(verify_relay_descriptor(&d, Some(spki), None).is_ok());
        // And without a live cert (pre-dial hint).
        assert!(verify_relay_descriptor(&d, None, None).is_ok());
    }

    #[test]
    fn tampered_signature_rejected() {
        let sk = node_bls_sk("relay-desc/tamper");
        let spki = b"fake-spki";
        let mut d = signed_descriptor(&sk, spki, None);
        d.addresses.push("10.0.0.1:1".parse().unwrap()); // change a signed field
        assert_eq!(
            verify_relay_descriptor(&d, Some(spki), None),
            Err(RelayDescriptorError::BadSignature)
        );
    }

    #[test]
    fn peer_id_spki_mismatch_rejected() {
        let sk = node_bls_sk("relay-desc/peerid");
        let d = signed_descriptor(&sk, b"spki-A", None);
        // Present a DIFFERENT cert SPKI than the descriptor committed to.
        assert_eq!(
            verify_relay_descriptor(&d, Some(b"spki-B"), None),
            Err(RelayDescriptorError::PeerIdMismatch)
        );
    }

    #[test]
    fn substituted_bls_pubkey_rejected() {
        // A MITM swaps the advertised BLS key; the signature no longer verifies under it.
        let sk = node_bls_sk("relay-desc/sub");
        let attacker = node_bls_sk("relay-desc/sub-attacker");
        let spki = b"spki";
        let mut d = signed_descriptor(&sk, spki, None);
        d.bls_pub = public_key_bytes(&attacker);
        assert_eq!(
            verify_relay_descriptor(&d, Some(spki), None),
            Err(RelayDescriptorError::BadSignature)
        );
    }

    #[test]
    fn bad_g1_point_rejected() {
        let sk = node_bls_sk("relay-desc/g1");
        let spki = b"spki";
        let mut d = signed_descriptor(&sk, spki, None);
        d.bls_pub = [0xFFu8; 48];
        assert_eq!(
            verify_relay_descriptor(&d, Some(spki), None),
            Err(RelayDescriptorError::BadBlsPubkey)
        );
    }

    #[test]
    fn did_resolving_to_other_key_rejected() {
        let sk = node_bls_sk("relay-desc/did");
        let spki = b"spki";
        let d = signed_descriptor(&sk, spki, Some("did:dig:relayX".to_string()));
        let other = public_key_bytes(&node_bls_sk("relay-desc/did-other"));
        let resolver = |_did: &str| -> Option<[u8; 48]> { Some(other) };
        assert_eq!(
            verify_relay_descriptor(&d, Some(spki), Some(&resolver)),
            Err(RelayDescriptorError::DidMismatch)
        );
    }

    #[test]
    fn did_resolving_to_same_key_accepted() {
        let sk = node_bls_sk("relay-desc/did-ok");
        let spki = b"spki";
        let d = signed_descriptor(&sk, spki, Some("did:dig:relayY".to_string()));
        let pk = public_key_bytes(&sk);
        let resolver = |_did: &str| -> Option<[u8; 48]> { Some(pk) };
        assert!(verify_relay_descriptor(&d, Some(spki), Some(&resolver)).is_ok());
    }

    #[test]
    fn unresolvable_did_tolerated() {
        let sk = node_bls_sk("relay-desc/did-none");
        let spki = b"spki";
        let d = signed_descriptor(&sk, spki, Some("did:dig:unknown".to_string()));
        let resolver = |_did: &str| -> Option<[u8; 48]> { None };
        assert!(verify_relay_descriptor(&d, Some(spki), Some(&resolver)).is_ok());
    }
}
