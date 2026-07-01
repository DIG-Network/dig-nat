//! The production [`Dialer`] — performs the real rustls **mTLS** dial to a reachable address and
//! returns a [`PeerConnection`] whose remote `peer_id` has been verified.
//!
//! This is the single place transport detail lives: TCP connect → rustls client handshake
//! presenting THIS node's certificate (mutual TLS) → the [`PeerIdPinningVerifier`] captures the
//! peer's leaf cert, derives `peer_id = SHA-256(SPKI DER)`, and rejects the handshake unless it
//! matches the [`PeerTarget::peer_id`] the caller asked for. On success the caller gets an
//! authenticated, encrypted [`tokio_rustls::client::TlsStream`].

use std::sync::Arc;

use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::LocalIdentity;
use crate::error::MethodError;
use crate::method::{MethodOutcome, TraversalKind};
use crate::mtls::{CapturedPeerId, PeerIdPinningVerifier};
use crate::peer::{PeerConnection, PeerTarget};
use crate::strategy::Dialer;

/// The production mTLS dialer. Holds this node's [`LocalIdentity`] (its client certificate for
/// mutual TLS) and builds a fresh pinning verifier per dial.
#[derive(Debug, Clone)]
pub struct MtlsDialer {
    identity: LocalIdentity,
}

impl MtlsDialer {
    /// Build a dialer that authenticates as `identity` (presents its cert as the mTLS client cert).
    pub fn new(identity: LocalIdentity) -> Self {
        MtlsDialer { identity }
    }

    /// Construct the rustls [`ClientConfig`] for one dial: present our client cert, and verify the
    /// server (peer) via the [`PeerIdPinningVerifier`] pinned to `expected` (the peer we want).
    fn client_config(
        &self,
        expected: crate::identity::PeerId,
        captured: CapturedPeerId,
    ) -> Result<ClientConfig, String> {
        let cert = CertificateDer::from(self.identity.cert_der.clone());
        let key = PrivateKeyDer::try_from(self.identity.key_der.clone())
            .map_err(|e| format!("invalid private key: {e}"))?;

        let verifier = Arc::new(PeerIdPinningVerifier::new(Some(expected), captured));
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(vec![cert], key)
            .map_err(|e| format!("client cert config: {e}"))
    }
}

#[async_trait]
impl Dialer for MtlsDialer {
    async fn dial(
        &self,
        peer: &PeerTarget,
        outcome: &MethodOutcome,
    ) -> Result<PeerConnection, MethodError> {
        let kind = outcome.kind;
        let addr = outcome.dial_addr;

        let captured = CapturedPeerId::default();
        let config = self
            .client_config(peer.peer_id, captured.clone())
            .map_err(|e| MethodError::failed(kind, e))?;
        let connector = TlsConnector::from(Arc::new(config));

        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| MethodError::failed(kind, format!("tcp connect {addr}: {e}")))?;

        // The server name is irrelevant to identity here (we verify by peer_id via the pinning
        // verifier, not by hostname/CA), but rustls requires a syntactically valid SNI. A peer_id
        // hex (64 chars) is not a valid DNS label (>63), so we use a fixed, well-formed placeholder.
        let server_name = ServerName::try_from("peer.dig.invalid")
            .map_err(|e| MethodError::failed(kind, format!("server name: {e}")))?;

        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| classify_tls_error(kind, &e))?;

        // The pinning verifier already rejected a mismatch; this is the authenticated identity.
        let verified = captured
            .get()
            .ok_or_else(|| MethodError::failed(kind, "peer presented no certificate"))?;

        // Wrap the single mTLS byte stream in yamux so the caller can open many concurrent
        // (range-)streams over it — the streaming-first, multiplexed transport is uniform across
        // every traversal tier.
        let session = crate::mux::PeerSession::client(tls);

        Ok(PeerConnection {
            peer_id: verified,
            method: kind,
            remote_addr: addr,
            session,
        })
    }
}

/// Map a rustls handshake error to a [`MethodError`], surfacing a peer_id mismatch clearly (it
/// arrives as a general error from the verifier).
fn classify_tls_error(kind: TraversalKind, e: &std::io::Error) -> MethodError {
    let msg = e.to_string();
    MethodError::failed(kind, format!("mtls handshake: {msg}"))
}
