//! Happy-eyeballs STUN reflexive-address discovery (CLAUDE.md §5.2, #1385 / #1062).
//!
//! These tests drive [`dig_nat::stun::discover_reflexive_address`] entirely over real in-process
//! loopback UDP sockets (no external network). The scenario under test is the exact #1062 regression:
//! an IPv4-only EC2 host that used to null its reflexive address because it picked the (unreachable)
//! IPv6 STUN server and did NOT fall back to the reachable IPv4 one. The discovery function must
//! race BOTH families IPv6-first with IPv4 fallback via `dig_ip::connect`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use dig_ip::LocalStack;
use dig_nat::stun::{discover_reflexive_address, BINDING_SUCCESS, MAGIC_COOKIE};
use tokio::net::UdpSocket;

/// Build a STUN Binding success response carrying `addr` in an XOR-MAPPED-ADDRESS attribute
/// (RFC 5389 §15.2), echoing the request's transaction id so it passes the client's txid check.
fn build_xor_response(addr: SocketAddr, txid: &[u8; 12]) -> Vec<u8> {
    let cookie_be = MAGIC_COOKIE.to_be_bytes();
    let mut value = vec![0u8]; // reserved
    let port = addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
    match addr.ip() {
        IpAddr::V4(v4) => {
            value.push(0x01); // family IPv4
            value.extend_from_slice(&port.to_be_bytes());
            let mut octets = v4.octets();
            for (i, o) in octets.iter_mut().enumerate() {
                *o ^= cookie_be[i];
            }
            value.extend_from_slice(&octets);
        }
        IpAddr::V6(v6) => {
            value.push(0x02); // family IPv6
            value.extend_from_slice(&port.to_be_bytes());
            let mut octets = v6.octets();
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&cookie_be);
            key[4..].copy_from_slice(txid);
            for (o, k) in octets.iter_mut().zip(key.iter()) {
                *o ^= *k;
            }
            value.extend_from_slice(&octets);
        }
    }

    let mut attr = 0x0020u16.to_be_bytes().to_vec(); // ATTR_XOR_MAPPED_ADDRESS
    attr.extend_from_slice(&(value.len() as u16).to_be_bytes());
    attr.extend_from_slice(&value);
    while attr.len() % 4 != 0 {
        attr.push(0);
    }

    let mut msg = BINDING_SUCCESS.to_be_bytes().to_vec();
    msg.extend_from_slice(&(attr.len() as u16).to_be_bytes());
    msg.extend_from_slice(&cookie_be);
    msg.extend_from_slice(txid);
    msg.extend_from_slice(&attr);
    msg
}

/// Spawn a loopback STUN server bound on `bind_ip:0` that answers every Binding request with a
/// success response carrying `reflexive`. Returns the address it is listening on (with the OS-chosen
/// port) so the test can hand it to the discovery function as a candidate.
async fn spawn_responder(bind_ip: IpAddr, reflexive: SocketAddr) -> SocketAddr {
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .expect("bind loopback STUN responder");
    let addr = socket.local_addr().expect("responder local addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                return;
            };
            if n < 20 {
                continue;
            }
            let txid: [u8; 12] = buf[8..20].try_into().unwrap();
            let resp = build_xor_response(reflexive, &txid);
            let _ = socket.send_to(&resp, from).await;
        }
    });
    addr
}

/// An IPv6 loopback address with a port that has NO responder — dialing it can only time out.
fn dead_v6() -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1)
}

const SHORT: Duration = Duration::from_millis(300);

/// The #1062 regression guard: a dual-stack host whose IPv6 STUN server is unreachable MUST fall
/// back to the reachable IPv4 STUN server and return its reflexive address — never null it out.
#[tokio::test]
async fn falls_back_to_ipv4_when_ipv6_stun_is_dead() {
    // A genuinely-global reflexive address (1.1.1.1). Documentation ranges (203.0.113.x) are now
    // rejected by the #1387 usability guard, so the reflexive must be a real global address here.
    let reflexive = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 1234);
    let v4 = spawn_responder(IpAddr::V4(Ipv4Addr::LOCALHOST), reflexive).await;

    // IPv6 candidate listed FIRST (dead), live IPv4 second. Dual-stack local host.
    let servers = [dead_v6(), v4];
    let got = discover_reflexive_address(&servers, LocalStack::from_flags(true, true), SHORT).await;

    assert_eq!(
        got,
        Some(reflexive),
        "must fall back to the reachable IPv4 STUN, not null out"
    );
}

/// An IPv4-only host must never strand: `dig_ip`'s intersection filter drops the IPv6 candidate
/// entirely (it is never even attempted) and the IPv4 reflexive is returned.
#[tokio::test]
async fn ipv4_only_host_uses_ipv4_stun() {
    let reflexive = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 9000);
    let v4 = spawn_responder(IpAddr::V4(Ipv4Addr::LOCALHOST), reflexive).await;

    let servers = [dead_v6(), v4];
    let got =
        discover_reflexive_address(&servers, LocalStack::from_flags(false, true), SHORT).await;

    assert_eq!(got, Some(reflexive));
}

/// When IPv6 STUN answers, IPv6 is preferred (attempted first) even though a live IPv4 STUN exists.
#[tokio::test]
async fn prefers_ipv6_when_it_answers() {
    // Global v6 (Cloudflare 2606:4700:4700::1111); 2001:db8::/32 is a rejected documentation range.
    let v6_reflexive = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
        4321,
    );
    let v4_reflexive = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 5555);
    let v6 = spawn_responder(IpAddr::V6(Ipv6Addr::LOCALHOST), v6_reflexive).await;
    let v4 = spawn_responder(IpAddr::V4(Ipv4Addr::LOCALHOST), v4_reflexive).await;

    let servers = [v6, v4];
    let got = discover_reflexive_address(&servers, LocalStack::from_flags(true, true), SHORT).await;

    assert_eq!(
        got,
        Some(v6_reflexive),
        "IPv6 must win when its STUN server answers"
    );
}

/// Empty candidate list → `None` (nothing to query), returns immediately.
#[tokio::test]
async fn empty_input_returns_none() {
    let got = discover_reflexive_address(&[], LocalStack::from_flags(true, true), SHORT).await;
    assert_eq!(got, None);
}

/// All candidates dead → `None`, bounded by the timeout (does not hang).
#[tokio::test]
async fn all_dead_returns_none() {
    let servers = [
        dead_v6(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
    ];
    let got = discover_reflexive_address(&servers, LocalStack::from_flags(true, true), SHORT).await;
    assert_eq!(got, None);
}
