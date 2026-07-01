//! Public `connect` + config tests — the top-level surface: config defaults/builder, LocalIdentity
//! derivation, and that `connect` degrades gracefully (no panic/hang) when no method can reach a
//! peer with no address. No network.

use std::time::Duration;

use dig_nat::{connect, LocalIdentity, NatConfig, NatError, PeerId, PeerTarget, TraversalKind};

/// Build a real self-signed LocalIdentity (its peer_id is derived from the cert SPKI).
fn local_identity() -> LocalIdentity {
    let c = rcgen::generate_simple_self_signed(vec!["me.dig".into()]).unwrap();
    LocalIdentity::from_der(c.cert.der().to_vec(), c.key_pair.serialize_der()).expect("cert parses")
}

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
}

#[test]
fn config_builder_disables_and_overrides() {
    let cfg = NatConfig::builder()
        .disable(TraversalKind::Relayed)
        .per_method_timeout(Duration::from_millis(250))
        .relay_endpoint("ws://custom:1")
        .build();
    assert!(
        !cfg.is_enabled(TraversalKind::Relayed),
        "relay fallback opt-out"
    );
    assert!(cfg.is_enabled(TraversalKind::Direct));
    assert_eq!(cfg.per_method_timeout, Duration::from_millis(250));
    assert_eq!(cfg.relay_endpoint, "ws://custom:1");
}

#[test]
fn local_identity_derives_peer_id_from_cert() {
    let id = local_identity();
    let recomputed = dig_nat::peer_id_from_leaf_cert_der(&id.cert_der).unwrap();
    assert_eq!(id.peer_id, recomputed);
}

#[test]
fn local_identity_rejects_bad_cert() {
    assert!(LocalIdentity::from_der(b"not a cert".to_vec(), b"key".to_vec()).is_none());
}

/// With no enabled methods, connect returns NoMethodsEnabled (never panics).
#[tokio::test]
async fn connect_no_methods_enabled() {
    let cfg = NatConfig::builder().enabled_methods(vec![]).build();
    let peer = PeerTarget::relay_only(PeerId::from_bytes([0u8; 32]), "DIG_MAINNET");
    let res = connect(&peer, &local_identity(), &cfg).await;
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
    match connect(&peer, &local_identity(), &cfg).await {
        Err(NatError::AllMethodsFailed(failures)) => {
            assert_eq!(failures.len(), 1);
            assert_eq!(failures[0].kind, TraversalKind::Direct);
        }
        other => panic!("expected AllMethodsFailed, got {other:?}"),
    }
}
