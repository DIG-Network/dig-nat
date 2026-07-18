//! The local∩peer address-family INTERSECTION conformance matrix, as dig-nat wires it.
//!
//! dig-nat's dial path (`MtlsDialer::dial`) delegates family selection + happy-eyeballs racing to the
//! canonical `dig-ip` crate: it aggregates a traversal outcome's addresses into a
//! [`dig_ip::PeerCandidates`] (via [`dig_nat::dialer::candidates_from_outcome`]) and calls
//! [`dig_ip::connect`] with the local host's [`dig_ip::LocalStack`]. These tests drive that exact
//! wiring with a deterministic [`LocalStack::from_flags`] + a canned dial closure (no real sockets),
//! asserting the guarantees `dig-nat` INHERITS from dig-ip: a dial NEVER attempts a family the peer
//! lacks (G2) or the local host lacks (G1); dual-stack prefers IPv6; a failed IPv6 falls back to
//! IPv4; and a disjoint pair fails cleanly with `NoCommonFamily` (no dial attempted, no hang).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dig_ip::{connect, ConnectError, DialConfig, LocalStack};
use dig_nat::dialer::candidates_from_outcome;
use dig_nat::method::{MethodOutcome, TraversalKind};

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// A fast, deterministic dial config so the racing logic is exercised without real delay.
fn cfg() -> DialConfig {
    DialConfig {
        per_attempt_timeout: Duration::from_millis(200),
        attempt_delay: Duration::from_millis(20),
    }
}

/// The peer candidates as the dialer builds them from a direct-method outcome carrying `addrs`.
fn peer(addrs: Vec<SocketAddr>) -> dig_ip::PeerCandidates {
    candidates_from_outcome(&MethodOutcome::candidates(TraversalKind::Direct, addrs))
}

/// Records every address the dial closure was asked to connect, so a test can assert WHICH families
/// were attempted (proving G1/G2 structurally, not just via the winner).
#[derive(Default)]
struct DialLog {
    attempted: Mutex<Vec<SocketAddr>>,
    count: AtomicUsize,
}

impl DialLog {
    fn attempted(&self) -> Vec<SocketAddr> {
        self.attempted.lock().unwrap().clone()
    }
}

/// Run `dig_ip::connect` over `peer` from a `local` stack, connecting every candidate successfully
/// and logging the attempt order.
async fn dial_all_ok(
    local: LocalStack,
    peer: &dig_ip::PeerCandidates,
    log: Arc<DialLog>,
) -> Result<SocketAddr, ConnectError<String>> {
    connect(&local, peer, cfg(), move |addr| {
        let log = log.clone();
        async move {
            log.attempted.lock().unwrap().push(addr);
            log.count.fetch_add(1, Ordering::SeqCst);
            Ok::<SocketAddr, String>(addr)
        }
    })
    .await
    .map(|w| w.addr)
}

// (2) Dual-stack local + dual-stack peer → the IPv6 candidate wins.
#[tokio::test(start_paused = true)]
async fn dual_stack_prefers_ipv6() {
    let log = Arc::new(DialLog::default());
    let peer = peer(vec![sa("203.0.113.5:4444"), sa("[2001:db8::1]:4444")]);
    let winner = dial_all_ok(LocalStack::from_flags(true, true), &peer, log)
        .await
        .expect("a candidate connects");
    assert_eq!(winner, sa("[2001:db8::1]:4444"), "IPv6 wins on dual stack");
    assert!(winner.is_ipv6());
}

// (3) Dual-stack, IPv6 fails → IPv4 fallback wins.
#[tokio::test(start_paused = true)]
async fn ipv6_failure_falls_back_to_ipv4() {
    let peer = peer(vec![sa("[2001:db8::1]:4444"), sa("203.0.113.5:4444")]);
    let winner = connect(
        &LocalStack::from_flags(true, true),
        &peer,
        cfg(),
        move |addr| async move {
            if addr.is_ipv6() {
                Err::<SocketAddr, String>("v6 unreachable".into())
            } else {
                Ok(addr)
            }
        },
    )
    .await
    .expect("falls back to IPv4")
    .addr;
    assert_eq!(winner, sa("203.0.113.5:4444"));
    assert!(winner.is_ipv4());
}

// (4) G2 — dual-stack local, v4-only peer → ONLY the IPv4 address is ever dialed.
#[tokio::test(start_paused = true)]
async fn never_dials_a_family_the_peer_lacks() {
    let log = Arc::new(DialLog::default());
    let peer = peer(vec![sa("203.0.113.5:4444")]); // peer offers only IPv4
    let winner = dial_all_ok(LocalStack::from_flags(true, true), &peer, log.clone())
        .await
        .expect("connects over IPv4");
    assert!(winner.is_ipv4());
    let attempted = log.attempted();
    assert_eq!(attempted, vec![sa("203.0.113.5:4444")]);
    assert!(
        attempted.iter().all(|a| a.is_ipv4()),
        "no IPv6 family the peer lacks is ever attempted"
    );
}

// (5) G1 — v4-only local, dual-stack peer → ONLY the IPv4 address is ever dialed.
#[tokio::test(start_paused = true)]
async fn never_dials_a_family_the_local_host_lacks() {
    let log = Arc::new(DialLog::default());
    let peer = peer(vec![sa("[2001:db8::1]:4444"), sa("203.0.113.5:4444")]);
    let winner = dial_all_ok(LocalStack::from_flags(false, true), &peer, log.clone())
        .await
        .expect("connects over IPv4");
    assert!(winner.is_ipv4());
    let attempted = log.attempted();
    assert_eq!(
        attempted,
        vec![sa("203.0.113.5:4444")],
        "an IPv4-only host never emits an IPv6 SYN"
    );
}

// v6-only local, dual-stack peer → only the IPv6 address is dialed.
#[tokio::test(start_paused = true)]
async fn v6_only_local_dials_only_ipv6() {
    let log = Arc::new(DialLog::default());
    let peer = peer(vec![sa("[2001:db8::1]:4444"), sa("203.0.113.5:4444")]);
    let winner = dial_all_ok(LocalStack::from_flags(true, false), &peer, log.clone())
        .await
        .expect("connects over IPv6");
    assert!(winner.is_ipv6());
    assert_eq!(log.attempted(), vec![sa("[2001:db8::1]:4444")]);
}

// (1) Disjoint families — v6-only peer from a v4-only local host → clean NoCommonFamily, ZERO dials.
#[tokio::test(start_paused = true)]
async fn disjoint_families_report_no_common_family_without_dialing() {
    let log = Arc::new(DialLog::default());
    let peer = peer(vec![sa("[2001:db8::1]:4444")]); // peer offers only IPv6
    let err = dial_all_ok(LocalStack::from_flags(false, true), &peer, log.clone())
        .await
        .expect_err("no common family");
    assert!(matches!(err, ConnectError::NoCommonFamily(_)));
    assert!(
        log.attempted().is_empty(),
        "a disjoint pair attempts NO dial (no doomed, hanging SYN)"
    );
    assert_eq!(log.count.load(Ordering::SeqCst), 0);
}
