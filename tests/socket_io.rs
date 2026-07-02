//! Socket-driven method tests over LOOPBACK UDP responders (in-process, no external network).
//!
//! These exercise the real `transact` / `query_reflexive_address` I/O paths of NAT-PMP, PCP, and
//! STUN by standing up a tiny UDP server on `127.0.0.1` that replies with a canned datagram — the
//! "mocked socket" the task calls for. Covers the success paths (a present gateway/STUN server) and
//! the timeout paths (nothing listening) that the pure encode/parse tests can't reach.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use dig_nat::method::natpmp::{
    encode_map_request, NatPmpMethod, OP_EXTERNAL_ADDRESS, OP_MAP_UDP, RESPONSE_FLAG,
};
use dig_nat::method::pcp::{MapNonce, PcpMethod, OP_MAP, PCP_VERSION, PROTO_UDP, RESPONSE_BIT};
use dig_nat::method::{TraversalKind, TraversalMethod};
use dig_nat::stun::{query_reflexive_address, StunError, BINDING_SUCCESS, MAGIC_COOKIE};
use dig_nat::{PeerId, PeerTarget};
use tokio::net::UdpSocket;

fn peer(addr: &str) -> PeerTarget {
    PeerTarget::with_addr(
        PeerId::from_bytes([1u8; 32]),
        addr.parse().unwrap(),
        "DIG_MAINNET",
    )
}

/// A loopback NAT-PMP gateway: answers the external-address request then the map request.
#[tokio::test]
async fn natpmp_attempt_succeeds_against_loopback_gateway() {
    let gw = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let gw_addr = gw.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = [0u8; 32];
        // 1) external-address request → success response with an external IP.
        let (_, from) = gw.recv_from(&mut buf).await.unwrap();
        let mut ext = vec![0u8; 12];
        ext[1] = OP_EXTERNAL_ADDRESS + RESPONSE_FLAG;
        ext[8..12].copy_from_slice(&[203, 0, 113, 9]);
        gw.send_to(&ext, from).await.unwrap();
        // 2) map request → success response.
        let (n, from) = gw.recv_from(&mut buf).await.unwrap();
        assert_eq!(buf[1], OP_MAP_UDP, "second request is a map");
        let _ = n;
        let mut map = vec![0u8; 16];
        map[1] = OP_MAP_UDP + RESPONSE_FLAG;
        map[8..10].copy_from_slice(&4444u16.to_be_bytes());
        map[10..12].copy_from_slice(&4444u16.to_be_bytes());
        map[12..16].copy_from_slice(&7200u32.to_be_bytes());
        gw.send_to(&map, from).await.unwrap();
    });

    let mut m = NatPmpMethod::new(*ipv4(gw_addr), 4444);
    m.gateway = to_v4(gw_addr);
    m.timeout = Duration::from_secs(2);
    let out = m.attempt(&peer("198.51.100.7:4444")).await.unwrap();
    assert_eq!(out.kind, TraversalKind::NatPmp);
    assert_eq!(out.dial_addr(), Some("198.51.100.7:4444".parse().unwrap()));
}

/// No gateway listening → the NAT-PMP method times out (and reports a timeout MethodError).
#[tokio::test]
async fn natpmp_times_out_when_no_gateway() {
    let mut m = NatPmpMethod::new(Ipv4Addr::LOCALHOST, 4444);
    // Point at a port with nothing listening.
    m.gateway = "127.0.0.1:9".parse().unwrap();
    m.timeout = Duration::from_millis(150);
    let err = m.attempt(&peer("198.51.100.7:4444")).await.unwrap_err();
    assert_eq!(err.kind, TraversalKind::NatPmp);
    // No gateway → the method fails gracefully: a timeout (no reply) OR a socket error (an OS that
    // returns port-unreachable, e.g. Windows ICMP → WSAECONNRESET). Either way, never a panic.
    assert!(
        err.timeout || err.reason.contains("io"),
        "graceful failure, got: {}",
        err.reason
    );
}

/// A loopback PCP gateway: answers a MAP request with a MAP success echoing the nonce.
#[tokio::test]
async fn pcp_attempt_succeeds_against_loopback_gateway() {
    let gw = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let gw_addr = gw.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = [0u8; 128];
        let (n, from) = gw.recv_from(&mut buf).await.unwrap();
        assert!(n >= 60, "a PCP MAP request is 60 bytes");
        // Echo the nonce from the request's MAP body (offset 24..36).
        let nonce: MapNonce = buf[24..36].try_into().unwrap();
        let mut resp = vec![0u8; 60];
        resp[0] = PCP_VERSION;
        resp[1] = OP_MAP | RESPONSE_BIT;
        resp[3] = 0; // success
        resp[4..8].copy_from_slice(&7200u32.to_be_bytes());
        resp[24..36].copy_from_slice(&nonce);
        resp[36] = PROTO_UDP;
        resp[42..44].copy_from_slice(&5555u16.to_be_bytes());
        let mapped = Ipv4Addr::new(203, 0, 113, 9).to_ipv6_mapped().octets();
        resp[44..60].copy_from_slice(&mapped);
        gw.send_to(&resp, from).await.unwrap();
    });

    let mut m = PcpMethod::new(
        *ipv4(gw_addr),
        4444,
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
    );
    m.gateway = to_v4(gw_addr);
    m.timeout = Duration::from_secs(2);
    let out = m.attempt(&peer("198.51.100.7:4444")).await.unwrap();
    assert_eq!(out.kind, TraversalKind::Pcp);
    assert_eq!(out.dial_addr(), Some("198.51.100.7:4444".parse().unwrap()));
}

#[tokio::test]
async fn pcp_times_out_when_no_gateway() {
    let mut m = PcpMethod::new(Ipv4Addr::LOCALHOST, 4444, IpAddr::V4(Ipv4Addr::LOCALHOST));
    m.gateway = "127.0.0.1:9".parse().unwrap();
    m.timeout = Duration::from_millis(150);
    let err = m.attempt(&peer("198.51.100.7:4444")).await.unwrap_err();
    assert_eq!(err.kind, TraversalKind::Pcp);
    // Timeout (no reply) or a socket error (OS port-unreachable) — either is graceful, never a panic.
    assert!(
        err.timeout || err.reason.contains("io"),
        "graceful failure, got: {}",
        err.reason
    );
}

/// A loopback STUN server: replies to a Binding request with a Binding success carrying an
/// XOR-MAPPED-ADDRESS. Proves the real `query_reflexive_address` round-trip.
#[tokio::test]
async fn stun_query_reflexive_address_against_loopback_server() {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server_addr = server.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (_, from) = server.recv_from(&mut buf).await.unwrap();
        // Echo the transaction id from the request (bytes 8..20).
        let txid: [u8; 12] = buf[8..20].try_into().unwrap();
        let reflexive = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 55)), 41234);
        let resp = build_xor_mapped_response(&txid, reflexive);
        server.send_to(&resp, from).await.unwrap();
    });

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let got = query_reflexive_address(&client, server_addr, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(got.port(), 41234);
    assert_eq!(got.ip(), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 55)));
}

#[tokio::test]
async fn stun_query_times_out_when_no_server() {
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let err = query_reflexive_address(
        &client,
        "127.0.0.1:9".parse().unwrap(),
        Duration::from_millis(150),
    )
    .await
    .unwrap_err();
    // No STUN server → Timeout (no reply) or Io (OS port-unreachable). Either is a graceful failure.
    assert!(
        matches!(err, StunError::Timeout | StunError::Io(_)),
        "graceful failure, got: {err:?}"
    );
}

/// Encode-map-request helper is reachable from an integration test (belt-and-suspenders on the
/// public encoder alongside the datagram unit tests).
#[test]
fn natpmp_map_encoder_public() {
    let req = encode_map_request(true, 1, 2, 3);
    assert_eq!(req.len(), 12);
}

// ---- helpers ----

fn ipv4(addr: SocketAddr) -> &'static Ipv4Addr {
    // Leak a small Ipv4Addr for the &'static return used only in test setup.
    match addr {
        SocketAddr::V4(v4) => Box::leak(Box::new(*v4.ip())),
        SocketAddr::V6(_) => Box::leak(Box::new(Ipv4Addr::LOCALHOST)),
    }
}

fn to_v4(addr: SocketAddr) -> std::net::SocketAddrV4 {
    match addr {
        SocketAddr::V4(v4) => v4,
        SocketAddr::V6(_) => std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, addr.port()),
    }
}

/// Build a STUN Binding success response with an XOR-MAPPED-ADDRESS (IPv4).
fn build_xor_mapped_response(txid: &[u8; 12], addr: SocketAddr) -> Vec<u8> {
    let cookie_be = MAGIC_COOKIE.to_be_bytes();
    let mut value = vec![0u8]; // reserved
    value.push(0x01); // IPv4
    let port = addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
    value.extend_from_slice(&port.to_be_bytes());
    let IpAddr::V4(v4) = addr.ip() else {
        unreachable!()
    };
    let mut octets = v4.octets();
    for (i, o) in octets.iter_mut().enumerate() {
        *o ^= cookie_be[i];
    }
    value.extend_from_slice(&octets);

    let mut attr = Vec::new();
    attr.extend_from_slice(&0x0020u16.to_be_bytes()); // XOR-MAPPED-ADDRESS
    attr.extend_from_slice(&(value.len() as u16).to_be_bytes());
    attr.extend_from_slice(&value);

    let mut msg = Vec::new();
    msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    msg.extend_from_slice(&(attr.len() as u16).to_be_bytes());
    msg.extend_from_slice(&cookie_be);
    msg.extend_from_slice(txid);
    msg.extend_from_slice(&attr);
    msg
}
