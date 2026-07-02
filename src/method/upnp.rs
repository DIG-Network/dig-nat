//! UPnP/IGD method — ask the local Internet Gateway Device (via UPnP SSDP discovery + SOAP) to add
//! a port mapping so inbound peer dials reach this node.
//!
//! Unlike NAT-PMP/PCP, UPnP/IGD is a large protocol (SSDP multicast discovery + SOAP over HTTP), so
//! we do NOT hand-roll it — we use the maintained [`igd-next`](https://docs.rs/igd-next) crate for
//! the live gateway call. It sits behind the same [`TraversalMethod`] trait as the other methods, so
//! the ordering/fallback strategy is exercised with mock methods in tests and the live IGD call is
//! covered only by an opt-in integration test (it needs a real UPnP gateway on the LAN).
//!
//! Testability: the gateway interaction is abstracted behind the [`IgdGateway`] trait so the
//! method's own logic (map → yield dial address, or fail → fall through) is unit-tested with a fake
//! gateway. [`RealIgd`] is the production implementation delegating to `igd-next`.

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;

use crate::error::MethodError;
use crate::method::{MethodOutcome, TraversalKind, TraversalMethod};
use crate::peer::PeerTarget;

/// Abstraction over "add a port mapping on the local IGD". Real impl talks to `igd-next`; tests use
/// a fake so the method logic is verified with no network + no gateway.
#[async_trait]
pub trait IgdGateway: Send + Sync {
    /// Add a UDP port mapping `external_port → (this host):internal_port` for `lifetime_secs`.
    /// Returns the external port actually assigned. Err = the gateway refused / is absent.
    async fn add_port_mapping(&self, internal_port: u16, lifetime_secs: u32)
        -> Result<u16, String>;
}

/// Production [`IgdGateway`] backed by `igd-next` (async tokio). Discovers the gateway via SSDP and
/// adds a UDP mapping. Kept thin so the one real network call is isolated.
#[derive(Debug, Clone)]
pub struct RealIgd {
    /// SSDP discovery timeout.
    pub discovery_timeout: Duration,
}

impl Default for RealIgd {
    fn default() -> Self {
        RealIgd {
            discovery_timeout: Duration::from_secs(2),
        }
    }
}

#[async_trait]
impl IgdGateway for RealIgd {
    async fn add_port_mapping(
        &self,
        internal_port: u16,
        lifetime_secs: u32,
    ) -> Result<u16, String> {
        use igd_next::aio::tokio as igd_tokio;
        use igd_next::{PortMappingProtocol, SearchOptions};

        let opts = SearchOptions {
            timeout: Some(self.discovery_timeout),
            ..Default::default()
        };
        let gateway = igd_tokio::search_gateway(opts)
            .await
            .map_err(|e| format!("igd discovery: {e}"))?;
        let local_ip = local_ipv4().ok_or_else(|| "no local IPv4 to map".to_string())?;
        let local = SocketAddr::new(local_ip, internal_port);
        gateway
            .add_port(
                PortMappingProtocol::UDP,
                internal_port,
                local,
                lifetime_secs,
                "dig-nat",
            )
            .await
            .map_err(|e| format!("igd add_port: {e}"))?;
        Ok(internal_port)
    }
}

/// The UPnP/IGD traversal method. Adds a mapping via [`IgdGateway`], then yields a dial address for
/// the peer. Generic over the gateway so tests inject a fake.
pub struct UpnpMethod<G: IgdGateway> {
    gateway: G,
    /// The local port to map.
    pub local_port: u16,
    /// Requested mapping lifetime (seconds).
    pub lifetime_secs: u32,
}

impl<G: IgdGateway> UpnpMethod<G> {
    /// Build a UPnP method over `gateway` for `local_port`.
    pub fn new(gateway: G, local_port: u16) -> Self {
        UpnpMethod {
            gateway,
            local_port,
            lifetime_secs: 7200,
        }
    }
}

/// The production UPnP method (real IGD discovery).
pub type RealUpnpMethod = UpnpMethod<RealIgd>;

impl RealUpnpMethod {
    /// Convenience constructor for the production method.
    pub fn real(local_port: u16) -> Self {
        UpnpMethod::new(RealIgd::default(), local_port)
    }
}

#[async_trait]
impl<G: IgdGateway> TraversalMethod for UpnpMethod<G> {
    fn kind(&self) -> TraversalKind {
        TraversalKind::Upnp
    }

    async fn attempt(&self, peer: &PeerTarget) -> Result<MethodOutcome, MethodError> {
        // Carry the peer's whole IPv6-first candidate list so the post-mapping dial keeps the
        // IPv6-first / IPv4-fallback order across families.
        let dial_addrs = peer.direct_addrs();
        if dial_addrs.is_empty() {
            return Err(MethodError::failed(
                TraversalKind::Upnp,
                "peer has no address to dial after mapping",
            ));
        }
        self.gateway
            .add_port_mapping(self.local_port, self.lifetime_secs)
            .await
            .map_err(|e| MethodError::failed(TraversalKind::Upnp, e))?;
        Ok(MethodOutcome::candidates(
            TraversalKind::Upnp,
            dial_addrs.to_vec(),
        ))
    }
}

/// Best-effort local IPv4 for the mapping target: open a UDP socket "to" a public address (no
/// packet is sent) and read the OS-selected source address. Returns `None` if unavailable.
///
/// UPnP/IGD is IPv4-inherent — it maps an inbound IPv4 pinhole on the gateway — so this IPv4 probe is
/// the correct local-IP source for the *mapping*. A routable IPv6 candidate (which needs no mapping)
/// is discovered separately via [`local_ipv6`] and advertised alongside, ordered first.
fn local_ipv4() -> Option<std::net::IpAddr> {
    let sock = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    sock.connect((std::net::Ipv4Addr::new(1, 1, 1, 1), 80))
        .ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

/// Best-effort GLOBAL (routable) local IPv6 address of this host, if any.
///
/// A global-unicast IPv6 address is directly dialable by peers with NO NAT mapping (unlike the
/// IPv4 path, which needs the UPnP pinhole), so it is a first-class candidate the node should
/// advertise **first** (IPv6-first rule). We ask the OS for the source address it would use to reach
/// a public IPv6 (a UDP `connect` sends no packet), then keep it only if it is a routable
/// global-unicast address (never link-local/ULA/loopback — those are not peer-reachable across the
/// internet). Returns `None` when the host has no global IPv6.
pub fn local_ipv6() -> Option<std::net::IpAddr> {
    let sock = std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0)).ok()?;
    // Cloudflare's public IPv6 resolver — no packet is sent by `connect`, it only selects a route.
    sock.connect((
        std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
        80,
    ))
    .ok()?;
    let ip = sock.local_addr().ok()?.ip();
    select_global_ipv6(&[ip])
}

/// Select the best IPv6 address to ADVERTISE from a set of the host's candidate addresses: a
/// global-unicast address is preferred; link-local (`fe80::/10`), ULA (`fc00::/7`), loopback, and
/// unspecified addresses are rejected because they are not reachable by peers across the internet.
/// IPv4 candidates are ignored. Returns the first global-unicast IPv6 candidate, or `None`.
pub fn select_global_ipv6(candidates: &[std::net::IpAddr]) -> Option<std::net::IpAddr> {
    candidates
        .iter()
        .copied()
        .find(|ip| matches!(ip, std::net::IpAddr::V6(v6) if is_global_unicast_v6(v6)))
}

/// Whether an IPv6 address is a routable global-unicast address (excludes loopback, unspecified,
/// link-local `fe80::/10`, and unique-local/ULA `fc00::/7`). Multicast is not unicast, so excluded.
fn is_global_unicast_v6(v6: &std::net::Ipv6Addr) -> bool {
    if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
        return false;
    }
    let seg0 = v6.segments()[0];
    let is_link_local = (seg0 & 0xffc0) == 0xfe80; // fe80::/10
    let is_unique_local = (seg0 & 0xfe00) == 0xfc00; // fc00::/7 (ULA)
    !is_link_local && !is_unique_local
}
