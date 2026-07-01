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
        let dial_addr = peer.direct_addr.ok_or_else(|| {
            MethodError::failed(
                TraversalKind::Upnp,
                "peer has no address to dial after mapping",
            )
        })?;
        self.gateway
            .add_port_mapping(self.local_port, self.lifetime_secs)
            .await
            .map_err(|e| MethodError::failed(TraversalKind::Upnp, e))?;
        Ok(MethodOutcome {
            kind: TraversalKind::Upnp,
            dial_addr,
        })
    }
}

/// Best-effort local IPv4 for the mapping target: open a UDP socket "to" a public address (no
/// packet is sent) and read the OS-selected source address. Returns `None` if unavailable.
fn local_ipv4() -> Option<std::net::IpAddr> {
    let sock = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    sock.connect((std::net::Ipv4Addr::new(1, 1, 1, 1), 80))
        .ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}
