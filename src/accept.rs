//! The RESPONDER side of a relayed connection — run the server half of the mTLS handshake over an
//! INTRODUCED relay circuit.
//!
//! A relay circuit needs exactly one mTLS **client** and one mTLS **server**. The [`crate::dialer`]
//! ([`MtlsDialer::dial`](crate::dialer::MtlsDialer)) is the client: it opens a tunnel to the peer and
//! runs [`PeerSession::client`]. This module is the missing counterpart: the reservation-HOLDER that
//! RECEIVES an introduced circuit ([`RelayStatus::enable_accept`](crate::relay::RelayStatus::enable_accept)
//! surfaces it as a [`RelayTunnel`]) accepts it here and runs [`PeerSession::server`] behind a
//! [`TlsAcceptor`]. Without this, both ends of a relay circuit acted as TLS client and the handshake
//! deadlocked (`got ClientHello when expecting ServerHello`, #1536).
//!
//! The accepted connection carries the IDENTICAL dig-tls mTLS as a direct one — the server verifies
//! the client's `peer_id = SHA-256(SPKI DER)` + rustls proof-of-possession + the #1204 BLS binding.
//! A server does NOT pin a specific caller (it accepts any authenticated DIG peer); the caller's
//! verified identity is read from the handshake and reported on the returned [`PeerConnection`].

use std::net::SocketAddr;
use std::sync::Arc;

use dig_tls::{BindingPolicy, NodeCert};
use tokio_rustls::TlsAcceptor;

use crate::error::MethodError;
use crate::method::TraversalKind;
use crate::mux::PeerSession;
use crate::peer::PeerConnection;
use crate::relay::RelayTunnel;
use crate::tunnel::RelayTunnelStream;

/// The unspecified address recorded as [`PeerConnection::remote_addr`] for an accepted relayed
/// circuit when no relay endpoint was supplied — the byte path is the relay tunnel, not an IP the
/// responder dialed, so the address is observability-only. Set a real relay endpoint with
/// [`RelayAcceptor::with_relay_endpoint`] when one is known.
fn unspecified_addr() -> SocketAddr {
    SocketAddr::from(([0u8; 16], 0))
}

/// Accepts INTRODUCED relay circuits: turns a server-role [`RelayTunnel`] (delivered by
/// [`RelayStatus::enable_accept`](crate::relay::RelayStatus::enable_accept)) into an authenticated
/// [`PeerConnection`] by running the SERVER half of the dig-tls mTLS handshake over it.
///
/// Holds this node's [`NodeCert`] (presented as the server cert) and the [`BindingPolicy`] applied
/// to the connecting peer's #1204 cert binding — the mirror image of
/// [`MtlsDialer`](crate::dialer::MtlsDialer). The [`NodeCert`] is shared behind an [`Arc`] (its
/// private key is held in a scrubbing wrapper), so cloning the acceptor never copies key material.
#[derive(Clone)]
pub struct RelayAcceptor {
    node: Arc<NodeCert>,
    binding_policy: BindingPolicy,
    relay_endpoint: SocketAddr,
}

impl RelayAcceptor {
    /// Build an acceptor that authenticates as `node` (presents its dig-tls cert as the mTLS server
    /// cert) with the default [`BindingPolicy::Opportunistic`] cert-binding stance. The recorded
    /// remote address defaults to unspecified (set one with [`with_relay_endpoint`](Self::with_relay_endpoint)).
    pub fn new(node: Arc<NodeCert>) -> Self {
        RelayAcceptor {
            node,
            binding_policy: BindingPolicy::default(),
            relay_endpoint: unspecified_addr(),
        }
    }

    /// Set the BLS cert-binding verification stance (#1204) for peer certs this acceptor verifies.
    pub fn with_binding_policy(mut self, policy: BindingPolicy) -> Self {
        self.binding_policy = policy;
        self
    }

    /// Record the relay endpoint the accepted circuits are forwarded through — used only as
    /// [`PeerConnection::remote_addr`] (observability); it never affects the mTLS identity check.
    pub fn with_relay_endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.relay_endpoint = endpoint;
        self
    }

    /// Accept one introduced relay circuit: run the dig-tls mTLS SERVER handshake over `tunnel`,
    /// then wrap the authenticated byte stream in a yamux [`PeerSession::server`] so the caller can
    /// accept the peer's inbound streams (availability + range fetches). The returned
    /// [`PeerConnection`] reports the connecting peer's VERIFIED `peer_id` (from the client cert) and
    /// its #1204 BLS binding — the same authentication a direct inbound connection gets.
    ///
    /// Uses [`dig_tls::server_config_spki_pinned`] so a live §5.2 self-signed peer leaf is accepted
    /// (the #1378 CA-everywhere migration is deferred) — mirroring the dialer's
    /// [`client_config_spki_pinned`](dig_tls::client_config_spki_pinned).
    pub async fn accept(&self, tunnel: RelayTunnel) -> Result<PeerConnection, MethodError> {
        let kind = TraversalKind::Relayed;
        let server_tls = dig_tls::server_config_spki_pinned(&self.node, self.binding_policy)
            .map_err(|e| MethodError::failed(kind, format!("server cert config: {e}")))?;
        let captured = server_tls.captured_peer_id;
        let captured_bls = server_tls.captured_bls;
        let acceptor = TlsAcceptor::from(server_tls.config);

        let stream = RelayTunnelStream::new(tunnel);
        let tls = acceptor
            .accept(stream)
            .await
            .map_err(|e| MethodError::failed(kind, format!("mtls accept: {e}")))?;

        // The client-cert verifier populated the connecting peer's identity during the handshake.
        let verified = captured
            .get()
            .ok_or_else(|| MethodError::failed(kind, "peer presented no certificate"))?;

        let session = PeerSession::server(tls);
        Ok(PeerConnection {
            peer_id: verified,
            method: kind,
            remote_addr: self.relay_endpoint,
            peer_bls_pub: captured_bls.get(),
            session,
        })
    }
}

impl std::fmt::Debug for RelayAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayAcceptor")
            .field("binding_policy", &self.binding_policy)
            .field("relay_endpoint", &self.relay_endpoint)
            .finish_non_exhaustive()
    }
}
