//! Shared test harness: build a real, connected [`PeerSession`] pair over an in-memory duplex.
//!
//! The strategy tests only need a *valid* [`PeerConnection`] to assert ordering/first-success — not
//! a real TLS handshake (mTLS identity is covered separately in `tests/mtls.rs`). So this produces a
//! genuine yamux [`PeerSession`] over a `tokio::io::duplex` pipe: cheap, in-process, no certs, no
//! network — while still exercising the real multiplexing code path.

#![allow(dead_code)]

use std::sync::Arc;

use dig_nat::mux::PeerSession;
use dig_nat::NodeCert;
use dig_tls::bls::SecretKey;
use sha2::{Digest, Sha256};

/// A deterministic BLS identity secret key from a label — derived, never an integer-literal secret
/// (so a second implementation reproduces the same vector and CodeQL does not flag a hard-coded key).
pub fn test_bls_sk(label: &str) -> SecretKey {
    let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
    SecretKey::from_seed(&seed)
}

/// A CA-signed dig-tls [`NodeCert`] (signed by the shipped embedded DigNetwork CA) for `label`,
/// shared behind an [`Arc`] the way `MtlsDialer` holds it. This is the identity a peer presents in
/// the mTLS handshake.
pub fn test_node(label: &str) -> Arc<NodeCert> {
    Arc::new(NodeCert::generate_signed(&test_bls_sk(label)).expect("generate node cert"))
}

/// A connected pair of multiplexed sessions over an in-memory duplex: `(client, server)`. The client
/// opens streams; the server accepts them. Real yamux, no network.
pub fn loopback_session_pair() -> (PeerSession, PeerSession) {
    let (a, b) = tokio::io::duplex(256 * 1024);
    (PeerSession::client(a), PeerSession::server(b))
}

/// Just the client half of a loopback session pair (the server half is kept alive by leaking it into
/// a background task so the connection stays open for the lifetime of the test). Used where a test
/// only needs a client-side [`PeerSession`] to place inside a fabricated [`PeerConnection`].
pub fn loopback_client_session() -> PeerSession {
    let (client, mut server) = loopback_session_pair();
    // Keep the server side alive + draining so the client's driver doesn't see an immediate close.
    tokio::spawn(async move { while server.accept_stream().await.is_some() {} });
    client
}
