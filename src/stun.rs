//! Minimal STUN (RFC 5389) client — discover this node's *reflexive* (public) transport address.
//!
//! A NAT'd node cannot see the `ip:port` the outside world dials it on. STUN answers that: the node
//! sends a **Binding request** to a STUN server (the DIG relay runs one; any RFC-5389 STUN server
//! also works) and the server replies with a **Binding success response** carrying the node's
//! reflexive address in an `XOR-MAPPED-ADDRESS` attribute. That reflexive `ip:port` is the
//! **server-reflexive candidate** dig-nat advertises so a remote peer can attempt a direct dial or
//! a coordinated hole-punch.
//!
//! We implement the small datagram directly (RFC 5389 §6, §15.2) rather than pulling a STUN crate:
//! it is a fixed 20-byte header + TLV attributes, so encoding/parsing is tiny and every branch is
//! unit-testable against the RFC byte layout with no network. The relay's STUN server is expected
//! to speak this exact wire; if the sibling agent's dig-relay STUN implementation diverges, this is
//! the module to reconcile (see the crate-level reconciliation note).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

/// STUN magic cookie (RFC 5389 §6). Always the first 4 bytes after the message type + length.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Binding request message type (RFC 5389 §6 — method Binding = 0x001, class Request = 0b00).
pub const BINDING_REQUEST: u16 = 0x0001;
/// Binding success response message type (method Binding, class Success = 0b10).
pub const BINDING_SUCCESS: u16 = 0x0101;

/// `XOR-MAPPED-ADDRESS` attribute type (RFC 5389 §15.2).
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// Legacy `MAPPED-ADDRESS` attribute type (RFC 5389 §15.1) — some servers still emit it.
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

/// Address family markers inside a (XOR-)MAPPED-ADDRESS attribute.
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

/// Errors decoding a STUN response or performing a Binding transaction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StunError {
    /// The datagram was shorter than a valid STUN message / attribute.
    #[error("STUN message truncated")]
    Truncated,
    /// The magic cookie did not match — not a STUN (RFC 5389) message.
    #[error("bad STUN magic cookie")]
    BadMagicCookie,
    /// The transaction id in the response did not match the request (possible spoof / stale reply).
    #[error("STUN transaction id mismatch")]
    TransactionIdMismatch,
    /// The message parsed but carried no usable mapped address: either no (XOR-)MAPPED-ADDRESS
    /// attribute at all, OR a parsed address that failed the reflexive-usability guard
    /// ([`is_usable_reflexive_addr`] — e.g. a non-global/reserved address such as loopback,
    /// link-local, multicast, a documentation range, or `port == 0`).
    #[error("no usable mapped address in STUN response")]
    NoMappedAddress,
    /// The message type was not a Binding success response.
    #[error("unexpected STUN message type: {0:#06x}")]
    UnexpectedType(u16),
    /// Underlying socket I/O error (stringified so [`StunError`] stays `Clone`/`Eq`).
    #[error("STUN io: {0}")]
    Io(String),
    /// The transaction did not complete within the deadline.
    #[error("STUN request timed out")]
    Timeout,
}

/// A STUN Binding request: 20-byte header (type, length=0, cookie, 96-bit transaction id) and no
/// attributes. `transaction_id` is caller-supplied so the response can be matched to the request.
pub fn encode_binding_request(transaction_id: &[u8; 12]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);
    msg.extend_from_slice(&BINDING_REQUEST.to_be_bytes()); // message type
    msg.extend_from_slice(&0u16.to_be_bytes()); // message length (no attributes)
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes()); // magic cookie
    msg.extend_from_slice(transaction_id); // 96-bit transaction id
    msg
}

/// Whether a parsed reflexive [`SocketAddr`] is usable as a server-reflexive candidate — a
/// defense-in-depth guard against a malicious or misconfigured STUN server (the relay runs one)
/// returning a bogus address that a consumer would then advertise (#1387).
///
/// Returns `false` (reject) for addresses that can never be a legitimate reflexive candidate,
/// across BOTH families: unspecified, loopback, link-local, multicast, the RFC-5737/3849
/// documentation ranges, the IPv4 limited-broadcast address, the never-dialable IPv4 ranges
/// (`0.0.0.0/8` "this-network", `192.88.99.0/24` 6to4-relay anycast, `198.18.0.0/15` benchmarking,
/// `240.0.0.0/4` reserved/class-E), and `port == 0`.
///
/// # IPv4-mapped / -compatible IPv6 cannot smuggle a rejected IPv4 range
///
/// The address is folded to IPv4 BEFORE classification, so an IPv4-mapped (`::ffff:a.b.c.d`) or
/// deprecated IPv4-compatible (`::a.b.c.d`) form is evaluated as the IPv4 address it represents and
/// hits the IPv4 predicate. Without this, a malicious STUN server (which fully controls the 16
/// decoded bytes) could smuggle e.g. `::ffff:127.0.0.1` or the compat form `::7f00:1` past a V6-only
/// classifier and induce a peer to self-dial loopback / the same LAN. [`Ipv6Addr::to_ipv4`] folds
/// BOTH forms (stable since Rust 1.0), unlike `to_canonical` which folds only the mapped form.
///
/// # Why this is NOT a blanket `is_global`
///
/// PRIVATE (RFC 1918 `10/8`, `172.16/12`, `192.168/16`), CGNAT (RFC 6598 `100.64/10`), and IPv6
/// ULA (`fc00::/7`) addresses are deliberately ACCEPTED. They are genuinely valid reflexive
/// addresses on a LAN or behind carrier-grade NAT — a peer on the same LAN/CGNAT region reaches
/// them directly. Rejecting them would break LAN and test-network reflexive discovery, including
/// the #1062 EC2 e2e where nodes learn a private VPC reflexive address. This guard removes only
/// the addresses that are *never* a valid dial target, not merely non-public ones.
fn is_usable_reflexive_addr(addr: &SocketAddr) -> bool {
    if addr.port() == 0 {
        return false;
    }
    // Fold IPv4-mapped/-compatible IPv6 to V4 first so those forms cannot bypass the V4 predicate
    // (an on-path STUN server controls every decoded byte — see the doc-comment). `to_ipv4` folds
    // both `::ffff:a.b.c.d` and the deprecated `::a.b.c.d`; a genuine native V6 yields `None`.
    match addr.ip() {
        IpAddr::V4(v4) => is_usable_reflexive_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4() {
            Some(v4) => is_usable_reflexive_v4(v4),
            None => is_usable_reflexive_v6(v6),
        },
    }
}

/// The IPv4 reflexive predicate: reject only the ranges that are *never* a valid dial target,
/// keeping private/CGNAT accepted (see [`is_usable_reflexive_addr`]).
fn is_usable_reflexive_v4(v4: Ipv4Addr) -> bool {
    let [a, b, _, _] = v4.octets();
    // `0.0.0.0/8` "this-network" (RFC 1122) — non-zero hosts here are not dialable either.
    let is_this_network = a == 0;
    // `192.88.99.0/24` — 6to4 relay anycast (RFC 7526), not a unicast dial target.
    let is_6to4_relay_anycast = v4.octets()[..3] == [192, 88, 99];
    // `198.18.0.0/15` — benchmarking (RFC 2544).
    let is_benchmarking = a == 198 && (b & 0xfe) == 18;
    // `240.0.0.0/4` — reserved / class-E (RFC 1112), incl. the 255.255.255.255 broadcast.
    let is_reserved_class_e = a >= 240;
    !v4.is_unspecified()
        && !v4.is_loopback()
        && !v4.is_link_local()
        && !v4.is_multicast()
        && !v4.is_broadcast()
        && !v4.is_documentation()
        && !is_this_network
        && !is_6to4_relay_anycast
        && !is_benchmarking
        && !is_reserved_class_e
}

/// The genuine-native-IPv6 reflexive predicate. Only ever sees real V6 addresses — mapped/compat
/// forms are folded to V4 by [`is_usable_reflexive_addr`] before this is reached.
fn is_usable_reflexive_v6(v6: Ipv6Addr) -> bool {
    let seg = v6.segments();
    // fe80::/10 — link-local unicast (`is_unicast_link_local` is unstable, check manually).
    let is_link_local = (seg[0] & 0xffc0) == 0xfe80;
    // 2001:db8::/32 — documentation (`is_documentation` is unstable, check manually).
    let is_documentation = seg[0] == 0x2001 && seg[1] == 0x0db8;
    !v6.is_unspecified()
        && !v6.is_loopback()
        && !v6.is_multicast()
        && !is_link_local
        && !is_documentation
}

/// Parse a STUN **Binding success response**, returning the reflexive [`SocketAddr`] from its
/// `XOR-MAPPED-ADDRESS` (preferred) or legacy `MAPPED-ADDRESS` attribute.
///
/// Validates the magic cookie and (when `expected_txid` is `Some`) the transaction id, so a stale
/// or spoofed datagram is rejected. Implements the XOR de-obfuscation of RFC 5389 §15.2.
///
/// This is a PURE parser: it does NOT check whether the returned address is a usable
/// (non-reserved, globally/LAN-dialable) reflexive candidate. A caller wanting a usable
/// server-reflexive candidate should use [`query_reflexive_address`], which applies the
/// [`is_usable_reflexive_addr`] guard on top of parsing.
pub fn parse_binding_response(
    msg: &[u8],
    expected_txid: Option<&[u8; 12]>,
) -> Result<SocketAddr, StunError> {
    if msg.len() < 20 {
        return Err(StunError::Truncated);
    }
    let msg_type = u16::from_be_bytes([msg[0], msg[1]]);
    let msg_len = u16::from_be_bytes([msg[2], msg[3]]) as usize;
    let cookie = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(StunError::BadMagicCookie);
    }
    if msg_type != BINDING_SUCCESS {
        return Err(StunError::UnexpectedType(msg_type));
    }
    let txid: [u8; 12] = msg[8..20].try_into().map_err(|_| StunError::Truncated)?;
    if let Some(expected) = expected_txid {
        if &txid != expected {
            return Err(StunError::TransactionIdMismatch);
        }
    }
    if msg.len() < 20 + msg_len {
        return Err(StunError::Truncated);
    }

    // Walk the TLV attributes. Prefer XOR-MAPPED-ADDRESS; fall back to MAPPED-ADDRESS.
    let mut fallback: Option<SocketAddr> = None;
    let mut off = 20usize;
    let end = 20 + msg_len;
    while off + 4 <= end {
        let attr_type = u16::from_be_bytes([msg[off], msg[off + 1]]);
        let attr_len = u16::from_be_bytes([msg[off + 2], msg[off + 3]]) as usize;
        let val_start = off + 4;
        let val_end = val_start + attr_len;
        if val_end > end {
            return Err(StunError::Truncated);
        }
        let value = &msg[val_start..val_end];
        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                return decode_mapped_address(value, &txid, true);
            }
            ATTR_MAPPED_ADDRESS if fallback.is_none() => {
                fallback = decode_mapped_address(value, &txid, false).ok();
            }
            _ => {}
        }
        // Attributes are padded to a 4-byte boundary (RFC 5389 §15).
        off = val_end + ((4 - (attr_len % 4)) % 4);
    }
    fallback.ok_or(StunError::NoMappedAddress)
}

/// Decode a (XOR-)MAPPED-ADDRESS attribute value into a [`SocketAddr`].
///
/// Layout (RFC 5389 §15.1/§15.2): `[reserved:1][family:1][port:2][address:4 or 16]`. When `xor` is
/// set, the port is XORed with the top 16 bits of the magic cookie and the address is XORed with the
/// full cookie (IPv4) or cookie‖transaction-id (IPv6).
fn decode_mapped_address(
    value: &[u8],
    txid: &[u8; 12],
    xor: bool,
) -> Result<SocketAddr, StunError> {
    if value.len() < 4 {
        return Err(StunError::Truncated);
    }
    let family = value[1];
    let raw_port = u16::from_be_bytes([value[2], value[3]]);
    let cookie_be = MAGIC_COOKIE.to_be_bytes();
    let port = if xor {
        raw_port ^ ((MAGIC_COOKIE >> 16) as u16)
    } else {
        raw_port
    };

    match family {
        FAMILY_IPV4 => {
            if value.len() < 8 {
                return Err(StunError::Truncated);
            }
            let mut octets = [value[4], value[5], value[6], value[7]];
            if xor {
                for (i, o) in octets.iter_mut().enumerate() {
                    *o ^= cookie_be[i];
                }
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        FAMILY_IPV6 => {
            if value.len() < 20 {
                return Err(StunError::Truncated);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            if xor {
                // XOR key is the 32-bit cookie followed by the 96-bit transaction id.
                let mut key = [0u8; 16];
                key[..4].copy_from_slice(&cookie_be);
                key[4..].copy_from_slice(txid);
                for (o, k) in octets.iter_mut().zip(key.iter()) {
                    *o ^= *k;
                }
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        other => Err(StunError::UnexpectedType(other as u16)),
    }
}

/// Perform a single STUN Binding transaction against `server` over `socket`, returning the
/// discovered reflexive (public) [`SocketAddr`] of `socket`. Bounded by `timeout`; a lost datagram
/// surfaces as [`StunError::Timeout`] (the caller retries or falls through to the next method).
///
/// This is **THE API to obtain a DIALABLE server-reflexive candidate**: it returns the reflexive
/// `ip:port` mapping of the caller's OWN listen socket, so the port is the real external binding a
/// remote peer can dial (unlike [`discover_reflexive_address`], which learns the public IP over a
/// throwaway ephemeral socket — see its `## Port caveat`). Connectivity-core (dig-node) should STUN
/// from its actual listen socket via this function to advertise a dialable candidate.
///
/// The `socket` should be the very UDP socket whose external mapping the caller wants to learn —
/// the reflexive address is specific to the NAT binding created by *that* socket.
///
/// The returned address is checked against [`is_usable_reflexive_addr`]: a parsed-but-unusable
/// (non-global/reserved) reflexive address is rejected as [`StunError::NoMappedAddress`] (#1387).
///
/// ## Anti-spoof: source address validation (#179 finding 2)
///
/// A UDP reply's source address is easy to check and hard for an off-path attacker to spoof
/// (spoofing the source AND getting the reply routed back requires being on-path or the same
/// network). This function therefore accepts a datagram only when it actually originates from
/// `server`; anything else (a stray reply, a scan, an attacker racing a forged response) is
/// discarded and the receive loop continues within the overall `timeout` deadline — a single
/// mismatched-source datagram must not fail the whole transaction, since the real reply may still be
/// in flight. This is independent, defense-in-depth hygiene alongside the transaction-id check
/// ([`new_transaction_id`]); neither replaces the other.
pub async fn query_reflexive_address(
    socket: &UdpSocket,
    server: SocketAddr,
    timeout: Duration,
) -> Result<SocketAddr, StunError> {
    let txid = new_transaction_id();
    let req = encode_binding_request(&txid);
    socket
        .send_to(&req, server)
        .await
        .map_err(|e| StunError::Io(e.to_string()))?;

    let mut buf = [0u8; 512];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(StunError::Timeout);
        }
        let (n, from) = match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok(x)) => x,
            Ok(Err(e)) => return Err(StunError::Io(e.to_string())),
            Err(_) => return Err(StunError::Timeout),
        };
        if from != server {
            // Not from the queried server — ignore and keep waiting for the genuine reply.
            continue;
        }
        let addr = parse_binding_response(&buf[..n], Some(&txid))?;
        // Defense-in-depth (#1387): a malicious/misconfigured STUN server can return a bogus
        // reflexive address (loopback, multicast, a documentation range, port 0, …) that we would
        // otherwise advertise. Reject any address that is not a usable reflexive candidate; the
        // caller (or `discover_reflexive_address`) then falls through to the next candidate.
        if !is_usable_reflexive_addr(&addr) {
            return Err(StunError::NoMappedAddress);
        }
        return Ok(addr);
    }
}

/// Discover this node's server-reflexive (public) address via STUN, IPv6-first with IPv4 FALLBACK
/// (CLAUDE.md §5.2). `stun_servers` are the resolved STUN endpoints across BOTH families (e.g. every
/// A + AAAA record of `<relay-host>:3478` — the caller MUST NOT pre-collapse to one family). The STUN
/// Binding transaction is raced over the local∩server family intersection via [`dig_ip::connect`]:
/// IPv6 is attempted first and IPv4 is used as a fallback when the IPv6 STUN server is unreachable —
/// the reflexive address is NEVER nulled just because the IPv6 STUN server did not respond. Returns
/// the discovered reflexive [`SocketAddr`], or `None` when no family's STUN server answered.
///
/// This is the canonical front-door fix for the #1062 gap: consumers (dig-node) MUST call this
/// instead of hand-rolling a family sort or collapsing `to_socket_addrs()` to a single family — the
/// happy-eyeballs racer and the local∩server intersection live here, in ONE place, per the dig-ip
/// charter ("NO repo hand-rolls a family sort or happy-eyeballs racer").
///
/// ## Port caveat
///
/// Each candidate is STUNed over a THROWAWAY ephemeral UDP socket bound just for that transaction,
/// so the returned IP is the node's stable public IP but the **PORT is that throwaway socket's NAT
/// binding — NOT reliably dialable** under most NAT types (a remote peer dialing it will usually
/// fail). Use this to learn the public IP; for a DIALABLE server-reflexive candidate, STUN from
/// your ACTUAL listen socket via [`query_reflexive_address`] instead.
pub async fn discover_reflexive_address(
    stun_servers: &[SocketAddr],
    local: dig_ip::LocalStack,
    timeout: Duration,
) -> Option<SocketAddr> {
    if stun_servers.is_empty() {
        return None;
    }

    let mut candidates = dig_ip::PeerCandidates::new();
    candidates.extend(
        stun_servers.iter().copied(),
        dig_ip::CandidateSource::StunReflexive,
    );

    let config = dig_ip::DialConfig {
        per_attempt_timeout: timeout,
        ..Default::default()
    };

    // One "dial" == one full STUN Binding transaction against a candidate server. We bind an
    // ephemeral UDP socket in the SERVER's family (dig-ip only hands us a family the local host can
    // originate on) and learn that socket's reflexive mapping. The racer returns the first family's
    // successful reflexive address, preferring IPv6.
    let winner = dig_ip::connect(&local, &candidates, config, |stun_addr| async move {
        let bind: SocketAddr = if stun_addr.is_ipv6() {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|e| format!("bind {bind}: {e}"))?;
        query_reflexive_address(&socket, stun_addr, timeout)
            .await
            .map_err(|e| e.to_string())
    })
    .await;

    match winner {
        Ok(w) => Some(w.conn),
        Err(_) => None,
    }
}

/// Generate a 96-bit STUN transaction id from a CSPRNG (RFC 5389 §10.1: "It primarily serves to
/// correlate requests with responses... **and MUST be uniformly and randomly chosen from the
/// interval 0 .. 2**96 - 1, and SHOULD be cryptographically random").
///
/// The transaction id is the ONLY anti-spoof mechanism [`query_reflexive_address`] applies to a
/// Binding response (the datagram source is not validated in isolation — see
/// [`query_reflexive_address`]'s source check): a predictable id (e.g. one derived from wall-clock
/// time) lets an off-path attacker who can approximate the send instant forge a `BINDING_SUCCESS`
/// carrying a poisoned reflexive address before the real STUN server's reply arrives. Sourcing every
/// bit from [`ring::rand::SystemRandom`] (already in the dependency tree via rustls) closes that.
///
/// `pub` so tests can assert directly on the id's statistical properties (see `tests/stun.rs`)
/// without re-running the full network transaction.
pub fn new_transaction_id() -> [u8; 12] {
    use ring::rand::{SecureRandom, SystemRandom};

    let mut id = [0u8; 12];
    // `SystemRandom::fill` only fails on catastrophic RNG unavailability (e.g. no OS entropy
    // source) — there is no sane fallback in that case, so we panic rather than silently degrade
    // back to a predictable id (which would reopen exactly the vulnerability this fixes).
    SystemRandom::new()
        .fill(&mut id)
        .expect("OS CSPRNG must be available to generate a STUN transaction id");
    id
}

#[cfg(test)]
mod reflexive_guard_tests {
    //! Unit tests for the private [`is_usable_reflexive_addr`] guard (#1387). Covers every reject
    //! category across BOTH families, and asserts private/CGNAT/ULA are ACCEPTED (not a blanket
    //! `is_global` — see the function's doc-comment).
    use super::is_usable_reflexive_addr;
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("valid SocketAddr literal")
    }

    #[test]
    fn accepts_genuinely_global_addresses() {
        assert!(is_usable_reflexive_addr(&addr("1.1.1.1:443")));
        assert!(is_usable_reflexive_addr(&addr("8.8.8.8:53")));
        assert!(is_usable_reflexive_addr(&addr(
            "[2606:4700:4700::1111]:443"
        )));
    }

    #[test]
    fn accepts_private_cgnat_and_ula() {
        // NOT rejected: legitimate reflexive addresses on a LAN / behind CGNAT (#1062 e2e).
        assert!(is_usable_reflexive_addr(&addr("192.168.1.5:9000")));
        assert!(is_usable_reflexive_addr(&addr("10.0.0.7:9000")));
        assert!(is_usable_reflexive_addr(&addr("172.16.5.5:9000")));
        assert!(is_usable_reflexive_addr(&addr("100.64.0.1:9000"))); // CGNAT (RFC 6598)
        assert!(is_usable_reflexive_addr(&addr("[fd00::1]:9000"))); // ULA (fc00::/7)
    }

    #[test]
    fn rejects_port_zero() {
        assert!(!is_usable_reflexive_addr(&addr("1.1.1.1:0")));
        assert!(!is_usable_reflexive_addr(&addr("[2606:4700:4700::1111]:0")));
    }

    #[test]
    fn rejects_reserved_ipv4() {
        assert!(!is_usable_reflexive_addr(&addr("0.0.0.0:1234"))); // unspecified
        assert!(!is_usable_reflexive_addr(&addr("127.0.0.1:1234"))); // loopback
        assert!(!is_usable_reflexive_addr(&addr("169.254.1.1:1234"))); // link-local
        assert!(!is_usable_reflexive_addr(&addr("224.0.0.1:1234"))); // multicast
        assert!(!is_usable_reflexive_addr(&addr("255.255.255.255:1234"))); // broadcast
        assert!(!is_usable_reflexive_addr(&addr("192.0.2.1:1234"))); // TEST-NET-1
        assert!(!is_usable_reflexive_addr(&addr("198.51.100.1:1234"))); // TEST-NET-2
        assert!(!is_usable_reflexive_addr(&addr("203.0.113.1:1234"))); // TEST-NET-3
    }

    #[test]
    fn rejects_reserved_ipv6() {
        assert!(!is_usable_reflexive_addr(&addr("[::]:1234"))); // unspecified
        assert!(!is_usable_reflexive_addr(&addr("[::1]:1234"))); // loopback
        assert!(!is_usable_reflexive_addr(&addr("[fe80::1]:1234"))); // link-local fe80::/10
        assert!(!is_usable_reflexive_addr(&addr("[febf::1]:1234"))); // link-local upper edge
        assert!(!is_usable_reflexive_addr(&addr("[ff02::1]:1234"))); // multicast ff00::/8
        assert!(!is_usable_reflexive_addr(&addr("[2001:db8::1]:1234"))); // documentation 2001:db8::/32
    }

    #[test]
    fn rejects_ipv4_mapped_and_compat_smuggling_reserved_ranges() {
        // Bug 1: an on-path STUN server controls the 16 decoded bytes and could smuggle any rejected
        // IPv4 range as an IPv4-mapped (`::ffff:a.b.c.d`) or deprecated IPv4-compat (`::a.b.c.d`)
        // address. After to_canonical folding these MUST hit the V4 predicate and be rejected.
        assert!(!is_usable_reflexive_addr(&addr("[::ffff:127.0.0.1]:1234"))); // mapped loopback
        assert!(!is_usable_reflexive_addr(&addr(
            "[::ffff:169.254.1.1]:1234"
        ))); // mapped link-local
        assert!(!is_usable_reflexive_addr(&addr("[::ffff:224.0.0.1]:1234"))); // mapped multicast
        assert!(!is_usable_reflexive_addr(&addr("[::ffff:192.0.2.1]:1234"))); // mapped TEST-NET-1
        assert!(!is_usable_reflexive_addr(&addr(
            "[::ffff:255.255.255.255]:1234"
        ))); // mapped broadcast
        assert!(!is_usable_reflexive_addr(&addr("[::ffff:0.0.0.0]:1234"))); // mapped unspecified
        assert!(!is_usable_reflexive_addr(&addr("[::7f00:1]:1234"))); // compat 127.0.0.1
    }

    #[test]
    fn accepts_ipv4_mapped_private() {
        // The accept-private design survives folding: a mapped private address is still ACCEPTED.
        assert!(is_usable_reflexive_addr(&addr("[::ffff:10.0.0.1]:9000")));
    }

    #[test]
    fn rejects_never_dialable_ipv4_ranges() {
        // Bug 2: never-dialable ranges the stdlib predicates miss (their unstable helpers can't be
        // called, so the masks are hand-rolled).
        assert!(!is_usable_reflexive_addr(&addr("198.18.0.1:1234"))); // benchmarking 198.18.0.0/15
        assert!(!is_usable_reflexive_addr(&addr("198.19.0.1:1234"))); // benchmarking upper half
        assert!(!is_usable_reflexive_addr(&addr("240.0.0.1:1234"))); // reserved/class-E 240.0.0.0/4
        assert!(!is_usable_reflexive_addr(&addr("0.1.2.3:1234"))); // this-network 0.0.0.0/8 non-zero host
        assert!(!is_usable_reflexive_addr(&addr("192.88.99.1:1234"))); // 6to4 relay anycast
    }
}
