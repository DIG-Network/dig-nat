//! IPv6 candidate-selection tests for the UPnP path's parallel IPv6 source.
//!
//! UPnP/IGD is IPv4-inherent (it maps an IPv4 pinhole), but a host with a GLOBAL (routable) IPv6
//! address needs no NAT mapping at all — that address is a directly-dialable candidate and MUST be
//! advertised first. [`select_global_ipv6`] picks the best IPv6 to advertise from the host's
//! addresses: a global-unicast address is preferred over link-local (`fe80::/10`) and ULA
//! (`fc00::/7`), which are not usable for peer reachability across the internet.

use std::net::{IpAddr, Ipv6Addr};

use dig_nat::method::upnp::select_global_ipv6;

fn ip(s: &str) -> IpAddr {
    IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
}

/// A global-unicast address is selected over a link-local one.
#[test]
fn prefers_global_over_link_local() {
    let candidates = vec![ip("fe80::1"), ip("2001:db8::1")];
    assert_eq!(select_global_ipv6(&candidates), Some(ip("2001:db8::1")));
}

/// A global-unicast address is selected over a ULA (fc00::/7).
#[test]
fn prefers_global_over_ula() {
    let candidates = vec![ip("fd00::1"), ip("2606:4700::1111")];
    assert_eq!(select_global_ipv6(&candidates), Some(ip("2606:4700::1111")));
}

/// With ONLY non-global candidates (link-local / ULA / loopback), nothing routable is advertised.
#[test]
fn none_when_only_non_global() {
    let candidates = vec![ip("fe80::1"), ip("fd00::abcd"), ip("::1")];
    assert_eq!(select_global_ipv6(&candidates), None);
}

/// IPv4 candidates are ignored (this selects an IPv6 to advertise).
#[test]
fn ignores_ipv4_candidates() {
    let candidates = vec!["192.168.1.5".parse().unwrap(), ip("2001:db8::5")];
    assert_eq!(select_global_ipv6(&candidates), Some(ip("2001:db8::5")));
}

/// The first global-unicast candidate is chosen when several are present (stable selection).
#[test]
fn picks_first_global_when_several() {
    let candidates = vec![ip("2001:db8::1"), ip("2001:db8::2")];
    assert_eq!(select_global_ipv6(&candidates), Some(ip("2001:db8::1")));
}

/// An empty list yields nothing.
#[test]
fn empty_is_none() {
    assert_eq!(select_global_ipv6(&[]), None);
}
