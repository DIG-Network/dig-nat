//! NAT-PMP method (RFC 6886) — ask the local NAT gateway for a port mapping so inbound peer dials
//! reach this node, and learn the gateway's external IP.
//!
//! NAT-PMP is a tiny fixed-layout UDP protocol spoken to the default gateway on port 5351. We
//! implement the two datagrams we need directly (RFC 6886 §3.2 external-address request, §3.3
//! map-port request): the packets are a handful of big-endian fields, so encode/parse is fully
//! unit-testable against the RFC byte layout with NO real network. The live `attempt` sends them to
//! the gateway; when there is no NAT-PMP gateway the request times out and the strategy falls
//! through to the next method.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::error::MethodError;
use crate::method::{MethodOutcome, TraversalKind, TraversalMethod};
use crate::peer::PeerTarget;

/// The well-known NAT-PMP / PCP server port on the gateway (RFC 6886 §3).
pub const NATPMP_PORT: u16 = 5351;
/// NAT-PMP version byte (RFC 6886 — version 0).
pub const NATPMP_VERSION: u8 = 0;
/// Opcode: request external address (RFC 6886 §3.2).
pub const OP_EXTERNAL_ADDRESS: u8 = 0;
/// Opcode: map UDP port (RFC 6886 §3.3). (TCP would be opcode 2.)
pub const OP_MAP_UDP: u8 = 1;
/// Opcode: map TCP port (RFC 6886 §3.3).
pub const OP_MAP_TCP: u8 = 2;
/// Response opcodes have the high bit set (opcode + 128, RFC 6886 §3.2/§3.3).
pub const RESPONSE_FLAG: u8 = 0x80;

/// Result code 0 = Success (RFC 6886 §3.5).
pub const RESULT_SUCCESS: u16 = 0;

/// Encode a NAT-PMP **external-address request** (RFC 6886 §3.2): `[version=0][opcode=0]`.
pub fn encode_external_address_request() -> [u8; 2] {
    [NATPMP_VERSION, OP_EXTERNAL_ADDRESS]
}

/// Encode a NAT-PMP **map-port request** (RFC 6886 §3.3):
/// `[version][opcode][reserved:2][internal_port:2][suggested_external_port:2][lifetime_secs:4]`.
pub fn encode_map_request(
    tcp: bool,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
) -> [u8; 12] {
    let opcode = if tcp { OP_MAP_TCP } else { OP_MAP_UDP };
    let mut buf = [0u8; 12];
    buf[0] = NATPMP_VERSION;
    buf[1] = opcode;
    // buf[2..4] reserved = 0
    buf[4..6].copy_from_slice(&internal_port.to_be_bytes());
    buf[6..8].copy_from_slice(&suggested_external_port.to_be_bytes());
    buf[8..12].copy_from_slice(&lifetime_secs.to_be_bytes());
    buf
}

/// Parsed NAT-PMP external-address response (RFC 6886 §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAddressResponse {
    /// Seconds since the gateway's port-mapping table was initialised.
    pub seconds_since_epoch: u32,
    /// The gateway's external IPv4 address.
    pub external_ip: Ipv4Addr,
}

/// Parse a NAT-PMP external-address response:
/// `[version][opcode=128][result_code:2][seconds:4][external_ipv4:4]`.
pub fn parse_external_address_response(msg: &[u8]) -> Result<ExternalAddressResponse, NatPmpError> {
    if msg.len() < 12 {
        return Err(NatPmpError::Truncated);
    }
    if msg[1] != OP_EXTERNAL_ADDRESS + RESPONSE_FLAG {
        return Err(NatPmpError::UnexpectedOpcode(msg[1]));
    }
    let result = u16::from_be_bytes([msg[2], msg[3]]);
    if result != RESULT_SUCCESS {
        return Err(NatPmpError::ResultCode(result));
    }
    let seconds = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
    let ip = Ipv4Addr::new(msg[8], msg[9], msg[10], msg[11]);
    Ok(ExternalAddressResponse {
        seconds_since_epoch: seconds,
        external_ip: ip,
    })
}

/// Parsed NAT-PMP map-port response (RFC 6886 §3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapResponse {
    /// The internal port that was mapped.
    pub internal_port: u16,
    /// The external port the gateway assigned (may differ from the suggestion).
    pub external_port: u16,
    /// The lifetime the gateway granted, in seconds.
    pub lifetime_secs: u32,
}

/// Parse a NAT-PMP map-port response:
/// `[version][opcode=128+op][result:2][seconds:4][internal_port:2][external_port:2][lifetime:4]`.
pub fn parse_map_response(msg: &[u8], tcp: bool) -> Result<MapResponse, NatPmpError> {
    if msg.len() < 16 {
        return Err(NatPmpError::Truncated);
    }
    let expected_op = if tcp { OP_MAP_TCP } else { OP_MAP_UDP } + RESPONSE_FLAG;
    if msg[1] != expected_op {
        return Err(NatPmpError::UnexpectedOpcode(msg[1]));
    }
    let result = u16::from_be_bytes([msg[2], msg[3]]);
    if result != RESULT_SUCCESS {
        return Err(NatPmpError::ResultCode(result));
    }
    let internal_port = u16::from_be_bytes([msg[8], msg[9]]);
    let external_port = u16::from_be_bytes([msg[10], msg[11]]);
    let lifetime = u32::from_be_bytes([msg[12], msg[13], msg[14], msg[15]]);
    Ok(MapResponse {
        internal_port,
        external_port,
        lifetime_secs: lifetime,
    })
}

/// NAT-PMP protocol / transaction errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NatPmpError {
    /// The datagram was shorter than a valid NAT-PMP response.
    #[error("NAT-PMP response truncated")]
    Truncated,
    /// The response opcode did not match the request.
    #[error("unexpected NAT-PMP opcode: {0}")]
    UnexpectedOpcode(u8),
    /// The gateway returned a non-success result code (RFC 6886 §3.5).
    #[error("NAT-PMP result code {0}")]
    ResultCode(u16),
    /// Socket I/O error (stringified so the error stays `Clone`/`Eq`).
    #[error("NAT-PMP io: {0}")]
    Io(String),
    /// No response within the deadline (likely no NAT-PMP gateway present).
    #[error("NAT-PMP request timed out")]
    Timeout,
}

/// The NAT-PMP traversal method.
///
/// Discovers the gateway's external IPv4, then requests a UDP mapping from `local_port` so the peer
/// can reach this node, and yields a dial address for the peer. When no NAT-PMP gateway is present,
/// the request times out and the method fails (strategy falls through).
#[derive(Debug, Clone)]
pub struct NatPmpMethod {
    /// The gateway address (usually the default route, port [`NATPMP_PORT`]).
    pub gateway: SocketAddrV4,
    /// The local UDP port this node listens on and wants mapped.
    pub local_port: u16,
    /// Requested mapping lifetime (seconds).
    pub lifetime_secs: u32,
    /// Per-request deadline.
    pub timeout: Duration,
}

impl NatPmpMethod {
    /// Build a NAT-PMP method for the given gateway + local port with sensible defaults
    /// (2h lifetime, 1s timeout — a present gateway answers in milliseconds).
    pub fn new(gateway: Ipv4Addr, local_port: u16) -> Self {
        NatPmpMethod {
            gateway: SocketAddrV4::new(gateway, NATPMP_PORT),
            local_port,
            lifetime_secs: 7200,
            timeout: Duration::from_secs(1),
        }
    }

    /// Send `payload` to the gateway and read one response datagram, bounded by [`Self::timeout`].
    async fn transact(&self, payload: &[u8]) -> Result<Vec<u8>, NatPmpError> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(|e| NatPmpError::Io(e.to_string()))?;
        socket
            .send_to(payload, self.gateway)
            .await
            .map_err(|e| NatPmpError::Io(e.to_string()))?;
        let mut buf = [0u8; 32];
        match tokio::time::timeout(self.timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => Ok(buf[..n].to_vec()),
            Ok(Err(e)) => Err(NatPmpError::Io(e.to_string())),
            Err(_) => Err(NatPmpError::Timeout),
        }
    }
}

#[async_trait]
impl TraversalMethod for NatPmpMethod {
    fn kind(&self) -> TraversalKind {
        TraversalKind::NatPmp
    }

    async fn attempt(&self, peer: &PeerTarget) -> Result<MethodOutcome, MethodError> {
        // NAT-PMP opens OUR pinhole; we still need the peer's address to dial afterwards.
        let dial_addr = peer.direct_addr.ok_or_else(|| {
            MethodError::failed(
                TraversalKind::NatPmp,
                "peer has no address to dial after mapping",
            )
        })?;

        // 1) Confirm a NAT-PMP gateway exists (external-address request).
        let resp = self
            .transact(&encode_external_address_request())
            .await
            .map_err(|e| to_method_error(&e))?;
        parse_external_address_response(&resp).map_err(|e| to_method_error(&e))?;

        // 2) Request a UDP mapping so inbound reaches us.
        let map = encode_map_request(false, self.local_port, self.local_port, self.lifetime_secs);
        let resp = self.transact(&map).await.map_err(|e| to_method_error(&e))?;
        parse_map_response(&resp, false).map_err(|e| to_method_error(&e))?;

        Ok(MethodOutcome {
            kind: TraversalKind::NatPmp,
            dial_addr,
        })
    }
}

/// Map a [`NatPmpError`] to the shared [`MethodError`], preserving the timeout flag.
fn to_method_error(e: &NatPmpError) -> MethodError {
    match e {
        NatPmpError::Timeout => MethodError::timeout(TraversalKind::NatPmp),
        other => MethodError::failed(TraversalKind::NatPmp, other.to_string()),
    }
}

/// Turn a [`SocketAddr`] hint into an IPv4 gateway if possible (NAT-PMP is IPv4-only).
pub fn ipv4_gateway(addr: SocketAddr) -> Option<Ipv4Addr> {
    match addr {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        SocketAddr::V6(_) => None,
    }
}
