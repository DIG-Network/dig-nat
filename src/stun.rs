//! STUN (RFC 5389) reflexive-address discovery — how this node learns the public address the
//! outside world sees its traffic arrive from.
//!
//! The RFC 5389 Binding codec, the UDP client transaction, and the address-scope classifier are
//! owned by the `dig_stun` crate — the DIG ecosystem's one shared home for them
//! (dig_ecosystem#3204), extracted byte-for-byte from THIS crate's own `0.21.1` and then
//! RECONCILED against dig-node's on-chain advertisement gate, whose range table had independently
//! drifted from this one (see "Reconciliation" below). This module re-exports every item its own
//! consumers — dig-node's `seams/dig_peer/net.rs`, and this crate's own tests — already use, so
//! nothing downstream needed to change to move onto the shared implementation.
//!
//! This module keeps only what is genuinely dig-nat's own: [`discover_reflexive_address`], the
//! happy-eyeballs walk over several STUN servers. It composes [`query_reflexive_address`] with
//! `dig_ip::connect` and CANNOT move into `dig-stun` itself — `dig-ip` is ALSO level
//! `00-foundation`, so that edge would be a forbidden same-level dependency (Appendix B,
//! reference-DOWN-only). dig-nat, at level `10-primitives`, is the one crate allowed to depend on
//! both and compose them.
//!
//! # Reconciliation
//!
//! `dig_stun::scope::is_usable_reflexive_addr` (now backing [`query_reflexive_address`]) is a
//! STRICTER table than this crate's own pre-adoption guard for three ranges that were never a
//! legitimate reflexive answer: `192.0.0.0/24` (IETF protocol assignment, RFC 6890), `2001:2::/48`
//! (benchmarking, RFC 5180), and `100::/64` (discard-only, RFC 6666) are now rejected where this
//! crate used to accept them — see `reflexive_guard_tests` below and `tests/socket_io.rs` for the
//! pinned regression. Every other classification is unchanged: private/CGNAT/ULA are still
//! ACCEPTED (deliberately not a blanket `is_global` filter — see `dig_stun::scope`'s own doc
//! comment).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

pub use dig_stun::{
    encode_binding_request, new_transaction_id, parse_binding_response, query_reflexive_address,
    StunError, ATTR_MAPPED_ADDRESS, ATTR_XOR_MAPPED_ADDRESS, BINDING_REQUEST, BINDING_SUCCESS,
    MAGIC_COOKIE,
};

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

#[cfg(test)]
mod reflexive_guard_tests {
    //! Unit tests for the address-usability guard, now owned by `dig_stun::scope` (#1387, moved to
    //! the shared crate by dig_ecosystem#3204). Covers every reject category across BOTH families,
    //! asserts private/CGNAT/ULA are ACCEPTED (not a blanket `is_global` — see `dig_stun::scope`'s
    //! own doc comment), and pins the THREE ranges the reconciliation against dig-node's on-chain
    //! gate newly tightened (module-level "Reconciliation" doc above; dig-stun `SPEC.md` §5.4).
    use dig_stun::scope::is_usable_reflexive_addr;
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
        // An on-path STUN server controls the 16 decoded bytes and could smuggle any rejected IPv4
        // range as an IPv4-mapped (`::ffff:a.b.c.d`) or deprecated IPv4-compat (`::a.b.c.d`)
        // address. After fold-to-v4, these MUST hit the V4 predicate and be rejected.
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
        assert!(!is_usable_reflexive_addr(&addr("198.18.0.1:1234"))); // benchmarking 198.18.0.0/15
        assert!(!is_usable_reflexive_addr(&addr("198.19.0.1:1234"))); // benchmarking upper half
        assert!(!is_usable_reflexive_addr(&addr("240.0.0.1:1234"))); // reserved/class-E 240.0.0.0/4
        assert!(!is_usable_reflexive_addr(&addr("0.1.2.3:1234"))); // this-network 0.0.0.0/8 non-zero host
        assert!(!is_usable_reflexive_addr(&addr("192.88.99.1:1234"))); // 6to4 relay anycast
    }

    /// dig_ecosystem#3204 RECONCILIATION: three ranges ACCEPTED by this crate's pre-adoption guard
    /// are now `NeverDialable` per `dig_stun::scope`'s table, reconciled against dig-node's
    /// on-chain gate (dig-stun `SPEC.md` §5.4). None is a range any legitimate STUN server can ever
    /// answer with — reconciling toward the SAFER (stricter) reading costs an implausible
    /// candidate, never a real one.
    #[test]
    fn rejects_ranges_newly_tightened_by_the_dig_stun_reconciliation() {
        // 192.0.0.0/24 — IETF protocol assignment (RFC 6890). dig-node's on-chain gate already
        // rejected this; this crate's own dial guard did not.
        assert!(!is_usable_reflexive_addr(&addr("192.0.0.1:1234")));
        // 2001:2::/48 — benchmarking (RFC 5180). Same direction as above.
        assert!(!is_usable_reflexive_addr(&addr("[2001:2::1]:1234")));
        // 100::/64 — discard-only (RFC 6666). Same direction as above.
        assert!(!is_usable_reflexive_addr(&addr("[100::1]:1234")));
    }
}
