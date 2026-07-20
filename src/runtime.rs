//! The runtime-handle carrier — the LIVE transport handles + discovery inputs the data-only
//! [`NatConfig`](crate::NatConfig) deliberately cannot hold.
//!
//! [`NatConfig`] is `Clone + Debug` DATA (which methods are enabled, timeouts, endpoints, the binding
//! policy). The relay-dependent + port-mapping tiers additionally need LIVE, non-cloneable things — a
//! relay coordinator, a relay data-plane, an IGD gateway handle, this node's discovered addresses. Jam
//! them into `NatConfig` and it could no longer be cheap cloneable data. So they live here, in a
//! separate [`NatRuntime`] carrier that is intentionally **neither `Clone` nor `Debug`** (it holds
//! `Arc<dyn …>` trait objects + live sockets). [`connect_with_runtime`](crate::connect_with_runtime)
//! takes both — the config for the data, the runtime for the handles — and composes the FULL ladder.
//!
//! Every field is OPTIONAL: a tier whose inputs are absent is simply NOT composed. This keeps the
//! composition honest — `connect` never claims a tier it cannot actually run, and never produces a
//! silently-broken dial. A node supplies exactly the handles it has (a NAT'd node with a relay
//! reservation supplies the hole-punch + relayed handles; a node with a mappable gateway supplies the
//! port + gateway; a fully-public node supplies none and gets Direct only).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crate::method::hole_punch::HolePunchCoordinator;
use crate::method::relayed::RelayedDialer;
use crate::method::upnp::IgdGateway;

/// Live transport handles + discovery inputs for the non-Direct traversal tiers. Built with a fluent
/// builder; passed to [`connect_with_runtime`](crate::connect_with_runtime) alongside the
/// [`NatConfig`](crate::NatConfig). Deliberately NOT `Clone`/`Debug` — it carries live `Arc<dyn …>`
/// handles, unlike the data-only config.
#[derive(Default)]
pub struct NatRuntime {
    /// This node's local listen port — mapped + advertised by the port-mapping tiers (UPnP/NAT-PMP/
    /// PCP). Absent → those tiers are not composed.
    pub(crate) local_port: Option<u16>,
    /// The local IPv4 default-gateway address for the NAT-PMP + PCP mapping tiers.
    pub(crate) gateway_v4: Option<Ipv4Addr>,
    /// This node's client IP as the gateway sees it — required in the PCP MAP request (RFC 6887).
    pub(crate) client_ip: Option<IpAddr>,
    /// UPnP/IGD gateway handle; `None` uses the real SSDP-discovered gateway when a `local_port` is
    /// set (a test injects a fake here).
    pub(crate) igd: Option<Arc<dyn IgdGateway>>,
    /// This node's STUN-discovered reflexive address, advertised in the RLY-007 hole-punch exchange.
    pub(crate) my_external_addr: Option<SocketAddr>,
    /// The relay hole-punch coordinator (RLY-007 signaling) — enables the hole-punch tier.
    pub(crate) hole_punch: Option<Arc<dyn HolePunchCoordinator>>,
    /// The relay data-plane tunnel dialer (RLY-002) — enables the relayed (TURN-last) tier, carrying
    /// mTLS over the relay so a relayed connection is not weaker than a direct one.
    pub(crate) relayed: Option<Arc<dyn RelayedDialer>>,
}

impl NatRuntime {
    /// An empty runtime — no handles wired, so only the Direct tier is composable. Equivalent to
    /// [`NatRuntime::default`]; the starting point for the builder.
    pub fn builder() -> NatRuntimeBuilder {
        NatRuntimeBuilder {
            rt: NatRuntime::default(),
        }
    }
}

/// Fluent builder for [`NatRuntime`]. Set only the handles this node actually has; the rest stay
/// `None` and their tiers are not composed.
#[derive(Default)]
pub struct NatRuntimeBuilder {
    rt: NatRuntime,
}

impl NatRuntimeBuilder {
    /// Set this node's local listen port (enables the port-mapping tiers, given their gateway inputs).
    pub fn local_port(mut self, port: u16) -> Self {
        self.rt.local_port = Some(port);
        self
    }

    /// Set the local IPv4 default-gateway for the NAT-PMP + PCP tiers.
    pub fn gateway_v4(mut self, gateway: Ipv4Addr) -> Self {
        self.rt.gateway_v4 = Some(gateway);
        self
    }

    /// Set this node's client IP for the PCP MAP request.
    pub fn client_ip(mut self, ip: IpAddr) -> Self {
        self.rt.client_ip = Some(ip);
        self
    }

    /// Inject a UPnP/IGD gateway handle (a test fake, or a pre-built real gateway). Absent → the real
    /// SSDP-discovered gateway is used when a `local_port` is set.
    pub fn igd(mut self, igd: Arc<dyn IgdGateway>) -> Self {
        self.rt.igd = Some(igd);
        self
    }

    /// Set this node's STUN-discovered reflexive address for the hole-punch exchange.
    pub fn my_external_addr(mut self, addr: SocketAddr) -> Self {
        self.rt.my_external_addr = Some(addr);
        self
    }

    /// Wire the relay hole-punch coordinator (enables the hole-punch tier; also needs
    /// [`my_external_addr`](Self::my_external_addr)).
    pub fn hole_punch(mut self, coordinator: Arc<dyn HolePunchCoordinator>) -> Self {
        self.rt.hole_punch = Some(coordinator);
        self
    }

    /// Wire the relay data-plane tunnel dialer (enables the relayed / TURN-last tier).
    pub fn relayed(mut self, relayed: Arc<dyn RelayedDialer>) -> Self {
        self.rt.relayed = Some(relayed);
        self
    }

    /// Finalize the runtime carrier.
    pub fn build(self) -> NatRuntime {
        self.rt
    }
}
