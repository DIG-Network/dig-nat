//! PCP method (RFC 6887) — the successor to NAT-PMP. Same goal (open an inbound pinhole on the
//! gateway) with a richer, IPv6-capable datagram.
//!
//! PCP is spoken to the gateway on the same port as NAT-PMP (5351). We implement the MAP request /
//! response directly (RFC 6887 §11.1 common header, §11.2 MAP opcode): a 24-byte common header plus
//! a 36-byte MAP body. As with NAT-PMP, the fixed byte layout means encode/parse is fully
//! unit-testable against the RFC with no network; the live `attempt` sends it and, absent a PCP
//! gateway, times out so the strategy falls through.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::error::MethodError;
use crate::method::natpmp::NATPMP_PORT;
use crate::method::{MethodOutcome, TraversalKind, TraversalMethod};
use crate::peer::PeerTarget;

/// PCP version (RFC 6887 — version 2).
pub const PCP_VERSION: u8 = 2;
/// MAP opcode (RFC 6887 §11.2).
pub const OP_MAP: u8 = 1;
/// The `R` (response) bit in the opcode byte of a PCP response.
pub const RESPONSE_BIT: u8 = 0x80;
/// Result code SUCCESS (RFC 6887 §7.4).
pub const RESULT_SUCCESS: u8 = 0;
/// IANA protocol number for UDP (used in the MAP body's protocol field).
pub const PROTO_UDP: u8 = 17;
/// IANA protocol number for TCP.
pub const PROTO_TCP: u8 = 6;

/// A 96-bit MAP nonce (RFC 6887 §11.1) matching a response to a request.
pub type MapNonce = [u8; 12];

/// Encode a PCP **MAP request** (RFC 6887 §11.1 header + §11.2 body).
///
/// Header (24 bytes): `[version][opcode][reserved:2][lifetime:4][client_ip:16]`.
/// MAP body (36 bytes): `[nonce:12][protocol][reserved:3][internal_port:2][suggested_ext_port:2]
/// [suggested_ext_ip:16]`.
///
/// `client_ip` is this node's address as the gateway sees it, encoded as an IPv4-mapped IPv6 when
/// IPv4 (RFC 6887 uses 128-bit address fields throughout).
pub fn encode_map_request(
    nonce: &MapNonce,
    tcp: bool,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
    client_ip: IpAddr,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(60);
    buf.push(PCP_VERSION);
    buf.push(OP_MAP); // request: R bit clear
    buf.extend_from_slice(&[0, 0]); // reserved
    buf.extend_from_slice(&lifetime_secs.to_be_bytes());
    buf.extend_from_slice(&ip_to_16(client_ip));
    // MAP body.
    buf.extend_from_slice(nonce);
    buf.push(if tcp { PROTO_TCP } else { PROTO_UDP });
    buf.extend_from_slice(&[0, 0, 0]); // reserved
    buf.extend_from_slice(&internal_port.to_be_bytes());
    buf.extend_from_slice(&suggested_external_port.to_be_bytes());
    buf.extend_from_slice(&ip_to_16(IpAddr::V4(Ipv4Addr::UNSPECIFIED))); // suggest any external ip
    debug_assert_eq!(buf.len(), 60);
    buf
}

/// Parsed PCP MAP response (the fields dig-nat needs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapResponse {
    /// The lifetime the gateway granted (seconds).
    pub lifetime_secs: u32,
    /// The MAP nonce echoed back (must match the request).
    pub nonce: MapNonce,
    /// The external port assigned.
    pub external_port: u16,
    /// The external IP assigned.
    pub external_ip: IpAddr,
}

/// Parse a PCP MAP response, validating version, the MAP-response opcode, the result code, and the
/// echoed nonce.
///
/// Response header (24 bytes): `[version][opcode|R][reserved][result_code][lifetime:4]
/// [epoch:4][reserved:12]`. MAP body (36 bytes): `[nonce:12][protocol][reserved:3][internal_port:2]
/// [assigned_ext_port:2][assigned_ext_ip:16]`.
pub fn parse_map_response(msg: &[u8], expected_nonce: &MapNonce) -> Result<MapResponse, PcpError> {
    if msg.len() < 60 {
        return Err(PcpError::Truncated);
    }
    if msg[0] != PCP_VERSION {
        return Err(PcpError::BadVersion(msg[0]));
    }
    if msg[1] != (OP_MAP | RESPONSE_BIT) {
        return Err(PcpError::UnexpectedOpcode(msg[1]));
    }
    let result = msg[3];
    if result != RESULT_SUCCESS {
        return Err(PcpError::ResultCode(result));
    }
    let lifetime = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
    // MAP body starts at byte 24.
    let nonce: MapNonce = msg[24..36].try_into().map_err(|_| PcpError::Truncated)?;
    if &nonce != expected_nonce {
        return Err(PcpError::NonceMismatch);
    }
    let external_port = u16::from_be_bytes([msg[42], msg[43]]);
    let ext_ip_bytes: [u8; 16] = msg[44..60].try_into().map_err(|_| PcpError::Truncated)?;
    Ok(MapResponse {
        lifetime_secs: lifetime,
        nonce,
        external_port,
        external_ip: ip_from_16(ext_ip_bytes),
    })
}

/// PCP protocol / transaction errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PcpError {
    /// The datagram was shorter than a valid PCP MAP response.
    #[error("PCP response truncated")]
    Truncated,
    /// Unexpected PCP version byte.
    #[error("unexpected PCP version: {0}")]
    BadVersion(u8),
    /// The response opcode was not the MAP response.
    #[error("unexpected PCP opcode: {0}")]
    UnexpectedOpcode(u8),
    /// The gateway returned a non-success result code (RFC 6887 §7.4).
    #[error("PCP result code {0}")]
    ResultCode(u8),
    /// The echoed nonce did not match the request (possible spoof / stale reply).
    #[error("PCP MAP nonce mismatch")]
    NonceMismatch,
    /// Socket I/O error (stringified so the error stays `Clone`/`Eq`).
    #[error("PCP io: {0}")]
    Io(String),
    /// No response within the deadline (likely no PCP gateway present).
    #[error("PCP request timed out")]
    Timeout,
}

/// The PCP traversal method — requests a MAP mapping from the gateway so inbound peer dials reach
/// this node, then yields a dial address for the peer.
#[derive(Debug, Clone)]
pub struct PcpMethod {
    /// The gateway address (usually the default route, port [`NATPMP_PORT`] = 5351).
    pub gateway: SocketAddrV4,
    /// The local port this node listens on and wants mapped.
    pub local_port: u16,
    /// This node's client IP as the gateway sees it (goes in the PCP header).
    pub client_ip: IpAddr,
    /// Requested mapping lifetime (seconds).
    pub lifetime_secs: u32,
    /// Per-request deadline.
    pub timeout: Duration,
}

impl PcpMethod {
    /// Build a PCP method for the given gateway + local port with sensible defaults.
    pub fn new(gateway: Ipv4Addr, local_port: u16, client_ip: IpAddr) -> Self {
        PcpMethod {
            gateway: SocketAddrV4::new(gateway, NATPMP_PORT),
            local_port,
            client_ip,
            lifetime_secs: 7200,
            timeout: Duration::from_secs(1),
        }
    }

    /// Send a PCP request and read one response datagram, bounded by [`Self::timeout`].
    async fn transact(&self, payload: &[u8]) -> Result<Vec<u8>, PcpError> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(|e| PcpError::Io(e.to_string()))?;
        socket
            .send_to(payload, self.gateway)
            .await
            .map_err(|e| PcpError::Io(e.to_string()))?;
        let mut buf = [0u8; 128];
        match tokio::time::timeout(self.timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => Ok(buf[..n].to_vec()),
            Ok(Err(e)) => Err(PcpError::Io(e.to_string())),
            Err(_) => Err(PcpError::Timeout),
        }
    }
}

#[async_trait]
impl TraversalMethod for PcpMethod {
    fn kind(&self) -> TraversalKind {
        TraversalKind::Pcp
    }

    async fn attempt(&self, peer: &PeerTarget) -> Result<MethodOutcome, MethodError> {
        // Carry the peer's whole IPv6-first candidate list so the post-mapping dial keeps the
        // fallback across families.
        let dial_addrs = peer.direct_addrs();
        if dial_addrs.is_empty() {
            return Err(MethodError::failed(
                TraversalKind::Pcp,
                "peer has no address to dial after mapping",
            ));
        }
        let nonce = new_nonce();
        let req = encode_map_request(
            &nonce,
            false,
            self.local_port,
            self.local_port,
            self.lifetime_secs,
            self.client_ip,
        );
        let resp = self.transact(&req).await.map_err(|e| to_method_error(&e))?;
        parse_map_response(&resp, &nonce).map_err(|e| to_method_error(&e))?;
        Ok(MethodOutcome::candidates(
            TraversalKind::Pcp,
            dial_addrs.to_vec(),
        ))
    }
}

/// Map a [`PcpError`] to the shared [`MethodError`], preserving the timeout flag.
fn to_method_error(e: &PcpError) -> MethodError {
    match e {
        PcpError::Timeout => MethodError::timeout(TraversalKind::Pcp),
        other => MethodError::failed(TraversalKind::Pcp, other.to_string()),
    }
}

/// Encode an [`IpAddr`] as a 16-byte field (IPv4 → IPv4-mapped IPv6, per RFC 6887).
fn ip_to_16(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Decode a 16-byte PCP address field back to an [`IpAddr`], unmapping IPv4-mapped IPv6.
fn ip_from_16(bytes: [u8; 16]) -> IpAddr {
    let v6 = Ipv6Addr::from(bytes);
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

/// Generate a MAP nonce (RFC 6887 only needs it unpredictable enough to match req↔resp).
fn new_nonce() -> MapNonce {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut n = [0u8; 12];
    n.copy_from_slice(&now.to_le_bytes()[..12]);
    n
}

/// Turn a [`SocketAddr`] hint into an IPv4 gateway if possible.
pub fn ipv4_gateway(addr: SocketAddr) -> Option<Ipv4Addr> {
    match addr {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        SocketAddr::V6(_) => None,
    }
}
