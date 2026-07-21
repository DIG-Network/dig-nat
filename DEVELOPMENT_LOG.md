# dig-nat — development log

Durable, non-obvious realizations from developing dig-nat. Context, not a change diary.

## yamux is transport-bound → a live transport swap happens at the STREAM-ROUTING layer, not the byte layer

`yamux::Connection` runs over ONE mTLS byte stream and owns that stream's framing/windowing state; you
CANNOT swap the underlying byte transport under a live `yamux::Connection` (its sequence/window state is
tied to the exact byte pipe). So fast-connect's live relayed→direct promotion (`connect_fast`,
`FastPeerConnection`) does NOT migrate a live session or a live stream. Instead the active transport is a
whole swappable slot (`ArcSwap<TransportSlot>`, each slot = its own mTLS `PeerSession`); promotion is a
single pointer store that redirects only SUBSEQUENT `open_stream` calls. An in-flight stream keeps
running on the slot it started on (it holds an `Arc<TransportSlot>`, so its session is never dropped from
under it), and the swapped-out relayed slot is drained (in-flight streams finish, or a grace cap elapses)
before being dropped.

This is correct BY CONSTRUCTION because DIG's peer API is a factory of short-lived, request-scoped streams
(`open_range_stream`, `query_availability` — a fresh yamux stream each) with NO cross-stream ordering
contract: route-new + drain-old loses/reorders/duplicates nothing, and needs no read-quiesce/flush because
the byte path is never swapped. Had there been a single long-lived ordered byte pipe contract, a seamless
swap would have been impossible without a replay/resume protocol.

Security corollary: because the session does not survive the swap, the safety of "swap transports to the
same peer" rests entirely on an IDENTITY-EQUALITY gate — the direct path's `peer_id`
(= SHA-256(TLS SPKI DER), transport-bound) AND its #1204 BLS pubkey MUST equal the relayed transport's
before promotion, plus one real application round-trip (empty-availability probe) to prove the new
transport actually carries bidirectional mux traffic (a NAT mapping can complete TLS then blackhole).
Never promote on handshake-completion alone.
