//! Full-ladder auto-composition tests for [`connect_with_runtime`]: each tier is composed ONLY when
//! its runtime inputs are present, the tiers are attempted in rank order, and a tier with no inputs is
//! silently omitted (never a phantom or silently-broken dial). Black-box via the ordered
//! [`NatError::AllMethodsFailed`] reason list — no network (mock IGD / coordinator / relay dialer).

mod tls_harness;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use dig_nat::method::relayed::RelayedDialer;
use dig_nat::relay::RelayTunnel;
use dig_nat::{
    connect_with_runtime, HolePunchCoordinator, IgdGateway, NatConfig, NatError, NatRuntime,
    PeerId, PeerTarget, TraversalKind,
};

use tls_harness::test_node;

const NET: &str = "DIG_MAINNET";

/// A UPnP gateway that always "maps" successfully — no SSDP/network.
struct FakeIgd;
#[async_trait]
impl IgdGateway for FakeIgd {
    async fn add_port_mapping(&self, port: u16, _lifetime: u32) -> Result<u16, String> {
        Ok(port)
    }
}

/// A hole-punch coordinator that returns a fixed (unreachable) peer address — the attempt succeeds,
/// the subsequent TCP dial fails, proving the hole-punch tier is composed + dials like a direct tier.
struct FakeCoordinator(SocketAddr);
#[async_trait]
impl HolePunchCoordinator for FakeCoordinator {
    async fn coordinate(
        &self,
        _peer: &str,
        _net: &str,
        _mine: SocketAddr,
    ) -> Result<SocketAddr, String> {
        Ok(self.0)
    }
}

/// A relay data-plane that is never ready — the relayed tier is composed but its attempt fails
/// cleanly (no live reservation), never a silent broken dial.
struct UnavailableRelay(SocketAddr);
#[async_trait]
impl RelayedDialer for UnavailableRelay {
    fn relay_endpoint(&self) -> SocketAddr {
        self.0
    }
    fn is_ready(&self) -> bool {
        false
    }
    async fn open_dial_tunnel(&self, _peer: &str, _net: &str) -> Result<RelayTunnel, String> {
        Err("no reservation".into())
    }
}

fn kinds(failures: &[dig_nat::MethodError]) -> Vec<TraversalKind> {
    failures.iter().map(|f| f.kind).collect()
}

/// With an EMPTY runtime, only the Direct tier is composed even though every tier is enabled — the
/// mapping/hole-punch/relayed tiers are honestly omitted for lack of their runtime inputs.
#[tokio::test]
async fn empty_runtime_composes_direct_only() {
    let cfg = NatConfig::builder()
        .per_method_timeout(Duration::from_millis(200))
        .build();
    let peer = PeerTarget::relay_only(PeerId::from_bytes([1u8; 32]), NET);
    match connect_with_runtime(&peer, &test_node("ladder/a"), &cfg, &NatRuntime::default()).await {
        Err(NatError::AllMethodsFailed(f)) => assert_eq!(kinds(&f), vec![TraversalKind::Direct]),
        other => panic!("expected AllMethodsFailed[Direct], got {other:?}"),
    }
}

/// A runtime that supplies the UPnP + hole-punch + relayed handles composes exactly those tiers (plus
/// Direct), attempted in rank order: Direct → Upnp → HolePunch → Relayed. Proves auto-composition
/// wires the full ladder from the runtime carrier, ordered correctly, with each tier failing cleanly.
#[tokio::test]
async fn runtime_handles_compose_the_full_ladder_in_order() {
    let cfg = NatConfig::builder()
        .enabled_methods(vec![
            TraversalKind::Direct,
            TraversalKind::Upnp,
            TraversalKind::HolePunch,
            TraversalKind::Relayed,
        ])
        .per_method_timeout(Duration::from_millis(300))
        .build();

    let runtime = NatRuntime::builder()
        .local_port(6060)
        .igd(Arc::new(FakeIgd))
        .my_external_addr("127.0.0.1:1".parse().unwrap())
        .hole_punch(Arc::new(FakeCoordinator("127.0.0.1:9".parse().unwrap())))
        .relayed(Arc::new(UnavailableRelay(
            "127.0.0.1:3478".parse().unwrap(),
        )))
        .build();

    // A peer with NO direct address: Direct + Upnp have nothing to dial, HolePunch dials the
    // (unreachable) coordinated addr, Relayed is not ready — all fail, but each tier IS attempted.
    let peer = PeerTarget::relay_only(PeerId::from_bytes([2u8; 32]), NET);
    match connect_with_runtime(&peer, &test_node("ladder/b"), &cfg, &runtime).await {
        Err(NatError::AllMethodsFailed(f)) => assert_eq!(
            kinds(&f),
            vec![
                TraversalKind::Direct,
                TraversalKind::Upnp,
                TraversalKind::HolePunch,
                TraversalKind::Relayed,
            ],
            "composed + attempted every tier whose runtime inputs were supplied, in rank order"
        ),
        other => panic!("expected AllMethodsFailed for the full ladder, got {other:?}"),
    }
}

/// A disabled tier is not composed even when its runtime handle is present — `enabled_methods` gates
/// composition alongside the runtime inputs.
#[tokio::test]
async fn disabled_tier_is_not_composed_despite_handle() {
    let cfg = NatConfig::builder()
        .enabled_methods(vec![TraversalKind::Direct]) // relayed disabled
        .per_method_timeout(Duration::from_millis(200))
        .build();
    let runtime = NatRuntime::builder()
        .relayed(Arc::new(UnavailableRelay(
            "127.0.0.1:3478".parse().unwrap(),
        )))
        .build();
    let peer = PeerTarget::relay_only(PeerId::from_bytes([3u8; 32]), NET);
    match connect_with_runtime(&peer, &test_node("ladder/c"), &cfg, &runtime).await {
        Err(NatError::AllMethodsFailed(f)) => assert_eq!(kinds(&f), vec![TraversalKind::Direct]),
        other => panic!("expected Direct only, got {other:?}"),
    }
}

/// Supplying the port-mapping inputs (`local_port` + `gateway_v4` + `client_ip`) composes the NAT-PMP
/// and PCP tiers; against a TEST-NET-unreachable gateway they time out cleanly within the bound. This
/// covers the NAT-PMP/PCP composition branches + the gateway/client-ip runtime builders.
#[tokio::test]
async fn port_mapping_inputs_compose_natpmp_and_pcp() {
    use std::net::{IpAddr, Ipv4Addr};

    let cfg = NatConfig::builder()
        .enabled_methods(vec![TraversalKind::NatPmp, TraversalKind::Pcp])
        .per_method_timeout(Duration::from_millis(300))
        .build();
    // 192.0.2.0/24 is TEST-NET-1 (RFC 5737) — never routed, so the mapping requests get no reply and
    // time out within the bound (hermetic; no real gateway touched).
    let runtime = NatRuntime::builder()
        .local_port(7070)
        .gateway_v4(Ipv4Addr::new(192, 0, 2, 1))
        .client_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)))
        .build();
    let peer = PeerTarget::relay_only(PeerId::from_bytes([4u8; 32]), NET);
    match connect_with_runtime(&peer, &test_node("ladder/d"), &cfg, &runtime).await {
        Err(NatError::AllMethodsFailed(f)) => assert_eq!(
            kinds(&f),
            vec![TraversalKind::NatPmp, TraversalKind::Pcp],
            "both port-mapping tiers were composed from the runtime inputs"
        ),
        other => panic!("expected NatPmp + Pcp composed, got {other:?}"),
    }
}
