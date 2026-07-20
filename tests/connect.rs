//! Public `connect` + config tests — the top-level surface: config defaults/builder, the
//! `NodeCert`-based identity, and that `connect` degrades gracefully (no panic/hang) when no method
//! can reach a peer with no address. No network.

mod tls_harness;

use std::time::Duration;

use dig_nat::{connect, BindingPolicy, NatConfig, NatError, PeerId, PeerTarget, TraversalKind};

use tls_harness::test_node;

#[test]
fn config_default_enables_all_methods_in_order() {
    let cfg = NatConfig::default();
    for k in [
        TraversalKind::Direct,
        TraversalKind::Upnp,
        TraversalKind::NatPmp,
        TraversalKind::Pcp,
        TraversalKind::HolePunch,
        TraversalKind::Relayed,
    ] {
        assert!(cfg.is_enabled(k), "{k:?} enabled by default");
    }
    assert_eq!(cfg.relay_endpoint, dig_constants::DIG_RELAY_URL);
    assert_eq!(
        cfg.binding_policy,
        BindingPolicy::Opportunistic,
        "the rollout default cert-binding stance is Opportunistic"
    );
}

#[test]
fn config_builder_disables_and_overrides() {
    let cfg = NatConfig::builder()
        .disable(TraversalKind::Relayed)
        .per_method_timeout(Duration::from_millis(250))
        .relay_endpoint("ws://custom:1")
        .binding_policy(BindingPolicy::Required)
        .build();
    assert!(
        !cfg.is_enabled(TraversalKind::Relayed),
        "relay fallback opt-out"
    );
    assert!(cfg.is_enabled(TraversalKind::Direct));
    assert_eq!(cfg.per_method_timeout, Duration::from_millis(250));
    assert_eq!(cfg.relay_endpoint, "ws://custom:1");
    assert_eq!(cfg.binding_policy, BindingPolicy::Required);
}

/// A `NodeCert`'s `peer_id` is the SHA-256 of its own SPKI DER — the identity a remote independently
/// derives from the presented cert.
#[test]
fn node_cert_peer_id_matches_its_leaf() {
    let node = test_node("connect/identity");
    let recomputed = dig_nat::peer_id_from_leaf_cert_der(node.cert_der()).unwrap();
    assert_eq!(node.peer_id(), recomputed);
}

/// With no enabled methods, connect returns NoMethodsEnabled (never panics).
#[tokio::test]
async fn connect_no_methods_enabled() {
    let cfg = NatConfig::builder().enabled_methods(vec![]).build();
    let peer = PeerTarget::relay_only(PeerId::from_bytes([0u8; 32]), "DIG_MAINNET");
    let res = connect(&peer, &test_node("connect/none"), &cfg).await;
    assert!(matches!(res, Err(NatError::NoMethodsEnabled)));
}

/// A peer with NO direct address, with only the Direct method enabled → the direct method has
/// nothing to try → AllMethodsFailed. Proves graceful degradation to a clear error, no hang/panic.
#[tokio::test]
async fn connect_all_methods_fail_is_clear_error() {
    let cfg = NatConfig::builder()
        .enabled_methods(vec![TraversalKind::Direct])
        .per_method_timeout(Duration::from_millis(200))
        .build();
    let peer = PeerTarget::relay_only(PeerId::from_bytes([9u8; 32]), "DIG_MAINNET");
    match connect(&peer, &test_node("connect/fail"), &cfg).await {
        Err(NatError::AllMethodsFailed(failures)) => {
            assert_eq!(failures.len(), 1);
            assert_eq!(failures[0].kind, TraversalKind::Direct);
        }
        other => panic!("expected AllMethodsFailed, got {other:?}"),
    }
}
