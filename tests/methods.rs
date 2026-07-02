//! Per-method tests with mocked seams — a fake IGD gateway, mock hole-punch coordinator, mock
//! relayed transport — plus the direct method and the TraversalKind rank ordering. No network.

use std::net::SocketAddr;

use async_trait::async_trait;

use dig_nat::method::direct::DirectMethod;
use dig_nat::method::hole_punch::{HolePunchCoordinator, HolePunchMethod};
use dig_nat::method::relayed::{RelayedTransport, RelayedTransportMethod};
use dig_nat::method::upnp::{IgdGateway, UpnpMethod};
use dig_nat::method::{TraversalKind, TraversalMethod};
use dig_nat::{PeerId, PeerTarget};

fn peer_with_addr(addr: &str) -> PeerTarget {
    PeerTarget::with_addr(
        PeerId::from_bytes([1u8; 32]),
        addr.parse().unwrap(),
        "DIG_MAINNET",
    )
}
fn peer_no_addr() -> PeerTarget {
    PeerTarget::relay_only(PeerId::from_bytes([2u8; 32]), "DIG_MAINNET")
}

/// TraversalKind ranks enforce direct-first, relay-last (the ordering contract).
#[test]
fn ranks_are_ordered_direct_first_relay_last() {
    let mut kinds = [
        TraversalKind::Relayed,
        TraversalKind::HolePunch,
        TraversalKind::Direct,
        TraversalKind::Pcp,
        TraversalKind::NatPmp,
        TraversalKind::Upnp,
    ];
    kinds.sort_by_key(|k| k.rank());
    assert_eq!(
        kinds,
        [
            TraversalKind::Direct,
            TraversalKind::Upnp,
            TraversalKind::NatPmp,
            TraversalKind::Pcp,
            TraversalKind::HolePunch,
            TraversalKind::Relayed,
        ]
    );
    // Relay tiers are strictly the last two, punch (5) before relayed (6).
    assert!(TraversalKind::HolePunch.rank() < TraversalKind::Relayed.rank());
}

#[tokio::test]
async fn direct_yields_known_address() {
    let m = DirectMethod;
    let out = m
        .attempt(&peer_with_addr("203.0.113.5:4444"))
        .await
        .unwrap();
    assert_eq!(out.kind, TraversalKind::Direct);
    assert_eq!(
        out.dial_addr(),
        Some("203.0.113.5:4444".parse::<SocketAddr>().unwrap())
    );
    assert_eq!(
        out.dial_addrs,
        vec!["203.0.113.5:4444".parse::<SocketAddr>().unwrap()]
    );
}

#[tokio::test]
async fn direct_fails_without_address() {
    let m = DirectMethod;
    assert!(m.attempt(&peer_no_addr()).await.is_err());
}

// ---- UPnP with a fake gateway ----

struct FakeIgd {
    ok: bool,
}
#[async_trait]
impl IgdGateway for FakeIgd {
    async fn add_port_mapping(&self, internal_port: u16, _lifetime: u32) -> Result<u16, String> {
        if self.ok {
            Ok(internal_port)
        } else {
            Err("no IGD on LAN".into())
        }
    }
}

#[tokio::test]
async fn upnp_maps_then_yields_dial_addr() {
    let m = UpnpMethod::new(FakeIgd { ok: true }, 4444);
    let out = m
        .attempt(&peer_with_addr("198.51.100.9:4444"))
        .await
        .unwrap();
    assert_eq!(out.kind, TraversalKind::Upnp);
    assert_eq!(
        out.dial_addr(),
        Some("198.51.100.9:4444".parse::<SocketAddr>().unwrap())
    );
}

#[tokio::test]
async fn upnp_fails_when_gateway_refuses() {
    let m = UpnpMethod::new(FakeIgd { ok: false }, 4444);
    let err = m
        .attempt(&peer_with_addr("198.51.100.9:4444"))
        .await
        .unwrap_err();
    assert_eq!(err.kind, TraversalKind::Upnp);
    assert!(err.reason.contains("no IGD"));
}

// ---- Hole punch (tier 5) with a mock coordinator: signaling only, yields a DIRECT peer address ----

struct MockCoordinator {
    peer_external: Option<SocketAddr>,
}
#[async_trait]
impl HolePunchCoordinator for MockCoordinator {
    async fn coordinate(
        &self,
        _target: &str,
        _network_id: &str,
        _my_external: SocketAddr,
    ) -> Result<SocketAddr, String> {
        self.peer_external.ok_or_else(|| "peer offline".into())
    }
}

#[tokio::test]
async fn hole_punch_yields_peers_direct_external_address() {
    let peer_ext: SocketAddr = "203.0.113.77:5555".parse().unwrap();
    let m = HolePunchMethod::new(
        MockCoordinator {
            peer_external: Some(peer_ext),
        },
        "192.0.2.1:4444".parse().unwrap(),
    );
    let out = m.attempt(&peer_no_addr()).await.unwrap();
    assert_eq!(out.kind, TraversalKind::HolePunch);
    // The dial address is the PEER's external address — a DIRECT p2p path, not the relay.
    assert_eq!(out.dial_addr(), Some(peer_ext));
}

#[tokio::test]
async fn hole_punch_fails_when_coordination_fails() {
    let m = HolePunchMethod::new(
        MockCoordinator {
            peer_external: None,
        },
        "192.0.2.1:4444".parse().unwrap(),
    );
    let err = m.attempt(&peer_no_addr()).await.unwrap_err();
    assert_eq!(err.kind, TraversalKind::HolePunch);
}

// ---- Relayed transport (tier 6) with a mock: relay is the data path ----

struct MockRelayed {
    relay_addr: Option<SocketAddr>,
}
#[async_trait]
impl RelayedTransport for MockRelayed {
    async fn open_relayed(&self, _target: &str, _network_id: &str) -> Result<SocketAddr, String> {
        self.relay_addr.ok_or_else(|| "relay down".into())
    }
}

#[tokio::test]
async fn relayed_yields_relay_as_data_path() {
    let relay: SocketAddr = "203.0.113.1:9450".parse().unwrap();
    let m = RelayedTransportMethod::new(MockRelayed {
        relay_addr: Some(relay),
    });
    let out = m.attempt(&peer_no_addr()).await.unwrap();
    assert_eq!(out.kind, TraversalKind::Relayed);
    // For the relayed tier the "dial address" is the RELAY — all data flows through it.
    assert_eq!(out.dial_addr(), Some(relay));
}

#[tokio::test]
async fn relayed_fails_when_relay_down() {
    let m = RelayedTransportMethod::new(MockRelayed { relay_addr: None });
    let err = m.attempt(&peer_no_addr()).await.unwrap_err();
    assert_eq!(err.kind, TraversalKind::Relayed);
}
