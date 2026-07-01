//! Strategy tests — the core abstraction: methods are tried direct-first / relay-last,
//! first-success-wins, all-fail returns a clear error, and tier-5 hole-punch is preferred over
//! tier-6 relayed transport. All with mock methods + a fake dialer — NO real network.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use dig_nat::error::MethodError;
use dig_nat::method::{MethodOutcome, TraversalKind, TraversalMethod};
use dig_nat::peer::{PeerConnection, PeerTarget};
use dig_nat::strategy::{connect_with_strategy, Dialer};
use dig_nat::{NatError, PeerId};

/// A mock traversal method that either yields a canned outcome or a canned failure, and records the
/// GLOBAL order in which methods were attempted so tests can assert ordering.
struct MockMethod {
    kind: TraversalKind,
    succeed: bool,
    order_log: Arc<Mutex<Vec<TraversalKind>>>,
    counter: Arc<AtomicUsize>,
}

impl MockMethod {
    fn arc(
        kind: TraversalKind,
        succeed: bool,
        order_log: Arc<Mutex<Vec<TraversalKind>>>,
        counter: Arc<AtomicUsize>,
    ) -> Arc<dyn TraversalMethod> {
        Arc::new(MockMethod {
            kind,
            succeed,
            order_log,
            counter,
        })
    }
}

#[async_trait]
impl TraversalMethod for MockMethod {
    fn kind(&self) -> TraversalKind {
        self.kind
    }
    async fn attempt(&self, _peer: &PeerTarget) -> Result<MethodOutcome, MethodError> {
        self.order_log.lock().unwrap().push(self.kind);
        self.counter.fetch_add(1, Ordering::SeqCst);
        if self.succeed {
            Ok(MethodOutcome {
                kind: self.kind,
                dial_addr: "127.0.0.1:1".parse().unwrap(),
            })
        } else {
            Err(MethodError::failed(self.kind, "mock failure"))
        }
    }
}

fn test_peer() -> PeerTarget {
    PeerTarget::relay_only(PeerId::from_bytes([0u8; 32]), "DIG_MAINNET")
}

/// Methods are attempted in rank order regardless of the order passed in: Direct(0) before Upnp(1)
/// before HolePunch(4) before Relayed(5).
#[tokio::test]
async fn attempts_in_rank_order_not_input_order() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let counter = Arc::new(AtomicUsize::new(0));
    // Pass them DELIBERATELY out of order; all fail so every one is attempted.
    let methods = vec![
        MockMethod::arc(
            TraversalKind::Relayed,
            false,
            order.clone(),
            counter.clone(),
        ),
        MockMethod::arc(TraversalKind::Direct, false, order.clone(), counter.clone()),
        MockMethod::arc(
            TraversalKind::HolePunch,
            false,
            order.clone(),
            counter.clone(),
        ),
        MockMethod::arc(TraversalKind::Upnp, false, order.clone(), counter.clone()),
    ];
    // All methods fail at the attempt stage, so the dialer is never reached.
    let dialer = SucceedingDialer {
        succeed_kind: TraversalKind::Direct,
    };
    let res = connect_with_strategy(&test_peer(), methods, &dialer, Duration::from_secs(1)).await;
    assert!(matches!(res, Err(NatError::AllMethodsFailed(_))));
    assert_eq!(
        *order.lock().unwrap(),
        vec![
            TraversalKind::Direct,
            TraversalKind::Upnp,
            TraversalKind::HolePunch,
            TraversalKind::Relayed
        ],
        "rank order enforced regardless of input order"
    );
}

/// First method whose attempt succeeds short-circuits: later methods are never attempted. (The dial
/// stage is mocked to also succeed via a dialer that returns Ok for the successful kind.)
#[tokio::test]
async fn first_success_wins_and_stops() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let counter = Arc::new(AtomicUsize::new(0));
    let methods = vec![
        MockMethod::arc(TraversalKind::Direct, true, order.clone(), counter.clone()),
        MockMethod::arc(TraversalKind::Upnp, true, order.clone(), counter.clone()),
        MockMethod::arc(TraversalKind::Relayed, true, order.clone(), counter.clone()),
    ];
    // A dialer that succeeds for Direct only.
    let dialer = SucceedingDialer {
        succeed_kind: TraversalKind::Direct,
    };
    let res = connect_with_strategy(&test_peer(), methods, &dialer, Duration::from_secs(1)).await;
    let conn = res.expect("direct should win");
    assert_eq!(conn.method, TraversalKind::Direct);
    // Only Direct's attempt ran — Upnp/Relayed never reached.
    assert_eq!(*order.lock().unwrap(), vec![TraversalKind::Direct]);
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

/// Tier-5 hole punch is preferred over tier-6 relayed transport: when both would succeed, the punch
/// wins and the relayed data plane is NEVER touched (bandwidth-saving guarantee).
#[tokio::test]
async fn hole_punch_preferred_over_relayed() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let counter = Arc::new(AtomicUsize::new(0));
    let methods = vec![
        MockMethod::arc(TraversalKind::Relayed, true, order.clone(), counter.clone()),
        MockMethod::arc(
            TraversalKind::HolePunch,
            true,
            order.clone(),
            counter.clone(),
        ),
    ];
    let dialer = SucceedingDialer {
        succeed_kind: TraversalKind::HolePunch,
    };
    let conn = connect_with_strategy(&test_peer(), methods, &dialer, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(conn.method, TraversalKind::HolePunch);
    assert_eq!(
        *order.lock().unwrap(),
        vec![TraversalKind::HolePunch],
        "relayed (tier 6) is never attempted when the punch (tier 5) succeeds"
    );
}

/// Only when the hole punch fails does the strategy fall to the relayed transport.
#[tokio::test]
async fn falls_to_relayed_only_after_hole_punch_fails() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let counter = Arc::new(AtomicUsize::new(0));
    let methods = vec![
        MockMethod::arc(
            TraversalKind::HolePunch,
            false,
            order.clone(),
            counter.clone(),
        ),
        MockMethod::arc(TraversalKind::Relayed, true, order.clone(), counter.clone()),
    ];
    let dialer = SucceedingDialer {
        succeed_kind: TraversalKind::Relayed,
    };
    let conn = connect_with_strategy(&test_peer(), methods, &dialer, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(conn.method, TraversalKind::Relayed);
    assert_eq!(
        *order.lock().unwrap(),
        vec![TraversalKind::HolePunch, TraversalKind::Relayed]
    );
}

/// No methods → NoMethodsEnabled.
#[tokio::test]
async fn empty_methods_errors() {
    let dialer = SucceedingDialer {
        succeed_kind: TraversalKind::Direct,
    };
    let res = connect_with_strategy(&test_peer(), vec![], &dialer, Duration::from_secs(1)).await;
    assert!(matches!(res, Err(NatError::NoMethodsEnabled)));
}

/// A method whose attempt succeeds but whose DIAL fails falls through to the next method.
#[tokio::test]
async fn dial_failure_falls_through() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let counter = Arc::new(AtomicUsize::new(0));
    let methods = vec![
        MockMethod::arc(TraversalKind::Direct, true, order.clone(), counter.clone()),
        MockMethod::arc(TraversalKind::Upnp, true, order.clone(), counter.clone()),
    ];
    // Direct's attempt succeeds but the dial refuses; Upnp then dials fine.
    let dialer = DialFailsFor {
        fail: TraversalKind::Direct,
        succeed: TraversalKind::Upnp,
    };
    let conn = connect_with_strategy(&test_peer(), methods, &dialer, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(conn.method, TraversalKind::Upnp);
    assert_eq!(
        *order.lock().unwrap(),
        vec![TraversalKind::Direct, TraversalKind::Upnp]
    );
}

/// A method that hangs past the per-method timeout is abandoned (bounded) — the strategy does not
/// hang, it records a timeout and moves on.
#[tokio::test(start_paused = true)]
async fn hung_method_times_out_and_falls_through() {
    struct HangMethod;
    #[async_trait]
    impl TraversalMethod for HangMethod {
        fn kind(&self) -> TraversalKind {
            TraversalKind::Direct
        }
        async fn attempt(&self, _peer: &PeerTarget) -> Result<MethodOutcome, MethodError> {
            // Sleep far longer than the per-method timeout.
            tokio::time::sleep(Duration::from_secs(3600)).await;
            unreachable!()
        }
    }
    let order = Arc::new(Mutex::new(Vec::new()));
    let counter = Arc::new(AtomicUsize::new(0));
    let methods: Vec<Arc<dyn TraversalMethod>> = vec![
        Arc::new(HangMethod),
        MockMethod::arc(TraversalKind::Upnp, true, order.clone(), counter.clone()),
    ];
    let dialer = SucceedingDialer {
        succeed_kind: TraversalKind::Upnp,
    };
    let conn = connect_with_strategy(&test_peer(), methods, &dialer, Duration::from_millis(50))
        .await
        .unwrap();
    assert_eq!(
        conn.method,
        TraversalKind::Upnp,
        "hung Direct was bounded; Upnp won"
    );
}

// The success-path dialers build a PeerConnection whose `session` is a real (loopback, in-memory)
// yamux session from the shared harness — exercising the real mux code path with no network. The
// strategy only requires that a valid PeerConnection comes back for the winning kind.

mod tls_harness;
use tls_harness::loopback_client_session;

/// A dialer that succeeds (real loopback mux session) only for `succeed_kind`.
struct SucceedingDialer {
    succeed_kind: TraversalKind,
}
#[async_trait]
impl Dialer for SucceedingDialer {
    async fn dial(
        &self,
        peer: &PeerTarget,
        outcome: &MethodOutcome,
    ) -> Result<PeerConnection, MethodError> {
        if outcome.kind != self.succeed_kind {
            return Err(MethodError::failed(
                outcome.kind,
                "dialer not configured for this kind",
            ));
        }
        Ok(PeerConnection {
            peer_id: peer.peer_id,
            method: outcome.kind,
            remote_addr: outcome.dial_addr,
            session: loopback_client_session(),
        })
    }
}

/// A dialer that fails for one kind and succeeds (real loopback mux session) for another.
struct DialFailsFor {
    fail: TraversalKind,
    succeed: TraversalKind,
}
#[async_trait]
impl Dialer for DialFailsFor {
    async fn dial(
        &self,
        peer: &PeerTarget,
        outcome: &MethodOutcome,
    ) -> Result<PeerConnection, MethodError> {
        if outcome.kind == self.fail {
            return Err(MethodError::failed(outcome.kind, "dial refused"));
        }
        if outcome.kind == self.succeed {
            return Ok(PeerConnection {
                peer_id: peer.peer_id,
                method: outcome.kind,
                remote_addr: outcome.dial_addr,
                session: loopback_client_session(),
            });
        }
        Err(MethodError::failed(outcome.kind, "unexpected kind"))
    }
}
