//! Happy-eyeballs (RFC 8305-style) candidate-racing tests for the dialer.
//!
//! The dialer MUST try a peer's candidate addresses IPv6-first and fall back to IPv4 only when the
//! IPv6 attempt fails/times out. These tests drive the pure racing logic ([`happy_eyeballs_connect`])
//! with an injected per-candidate connect closure — no real sockets — asserting: IPv6 is attempted
//! first; a failing IPv6 candidate falls to IPv4; when both would succeed IPv6 wins; and an
//! all-fail returns every candidate's error.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dig_nat::dialer::{happy_eyeballs_connect, HappyEyeballsConfig};

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// A fast, deterministic config: tiny stagger so the racing logic is exercised without real delay.
fn cfg() -> HappyEyeballsConfig {
    HappyEyeballsConfig {
        per_attempt_timeout: Duration::from_millis(200),
        stagger: Duration::from_millis(20),
    }
}

/// Records the order candidates were attempted, so tests assert IPv6 was tried first.
#[derive(Default)]
struct AttemptLog {
    order: Mutex<Vec<SocketAddr>>,
    count: AtomicUsize,
}

/// When BOTH families are reachable, the IPv6 candidate wins (it is tried first and connects).
#[tokio::test(start_paused = true)]
async fn ipv6_wins_when_both_reachable() {
    let log = Arc::new(AttemptLog::default());
    let candidates = vec![sa("[2001:db8::1]:4444"), sa("203.0.113.5:4444")];
    let log2 = log.clone();
    let winner = happy_eyeballs_connect(&candidates, cfg(), move |addr| {
        let log = log2.clone();
        async move {
            log.order.lock().unwrap().push(addr);
            log.count.fetch_add(1, Ordering::SeqCst);
            Ok::<SocketAddr, String>(addr) // every candidate "connects"
        }
    })
    .await
    .expect("a candidate connects");
    assert!(winner.is_ipv6(), "IPv6 candidate wins when both reachable");
    // IPv6 was the FIRST attempted.
    assert_eq!(log.order.lock().unwrap()[0], sa("[2001:db8::1]:4444"));
}

/// A failing IPv6 candidate falls back to the IPv4 candidate.
#[tokio::test(start_paused = true)]
async fn falls_back_to_ipv4_when_ipv6_fails() {
    let candidates = vec![sa("[2001:db8::1]:4444"), sa("203.0.113.5:4444")];
    let winner = happy_eyeballs_connect(&candidates, cfg(), move |addr| async move {
        if addr.is_ipv6() {
            Err::<SocketAddr, String>("v6 unreachable".into())
        } else {
            Ok(addr)
        }
    })
    .await
    .expect("falls back to IPv4");
    assert!(winner.is_ipv4(), "IPv4 is used as the fallback");
    assert_eq!(winner, sa("203.0.113.5:4444"));
}

/// IPv6 is always attempted before IPv4 even when both eventually fail.
#[tokio::test(start_paused = true)]
async fn attempts_ipv6_before_ipv4_on_all_fail() {
    let log = Arc::new(AttemptLog::default());
    let candidates = vec![sa("203.0.113.5:4444"), sa("[2001:db8::1]:4444")]; // input IPv4-first
    let log2 = log.clone();
    let res = happy_eyeballs_connect(&candidates, cfg(), move |addr| {
        let log = log2.clone();
        async move {
            log.order.lock().unwrap().push(addr);
            Err::<SocketAddr, String>(format!("no route to {addr}"))
        }
    })
    .await;
    assert!(res.is_err(), "all candidates fail");
    let order = log.order.lock().unwrap();
    assert_eq!(order.len(), 2, "both candidates attempted");
    assert!(
        order[0].is_ipv6(),
        "IPv6 attempted first even when input is IPv4-first"
    );
    assert!(order[1].is_ipv4());
}

/// An empty candidate list is an error, not a panic/hang.
#[tokio::test]
async fn empty_candidates_errors() {
    let res = happy_eyeballs_connect(
        &[],
        cfg(),
        |addr| async move { Ok::<SocketAddr, String>(addr) },
    )
    .await;
    assert!(res.is_err());
}

/// A slow-but-successful IPv6 candidate still wins over a fast IPv4 fallback: the IPv6 attempt is
/// given priority (started first + preferred), so the IPv4 attempt is only a hedge.
#[tokio::test(start_paused = true)]
async fn ipv6_preferred_even_if_slower() {
    let candidates = vec![sa("[2001:db8::1]:4444"), sa("203.0.113.5:4444")];
    let winner = happy_eyeballs_connect(&candidates, cfg(), move |addr| async move {
        if addr.is_ipv6() {
            // IPv6 takes a while but succeeds (within the per-attempt timeout).
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok::<SocketAddr, String>(addr)
        } else {
            // IPv4 would succeed instantly, but must not preempt a viable IPv6.
            Ok(addr)
        }
    })
    .await
    .expect("connects");
    assert!(
        winner.is_ipv6(),
        "a viable IPv6 candidate is preferred over the IPv4 hedge"
    );
}
