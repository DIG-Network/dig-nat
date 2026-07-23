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

## Relay glare — a simultaneous mutual dial re-manifests the #1536 deadlock; resolve by peer_id, not by who dialed

The relayed tier's responder path (`enable_accept` + `route_relayed`'s accept branch) fixes the base
#1536 deadlock (dialer = client, introduced circuit = server). But the `tunnels` map was keyed ONLY by
remote `peer_id` with no role, so when peers A and B BOTH fall to the relay tier and dial EACH OTHER at
the same time (the common two-NAT'd-peer flywheel case), each opens a client-role tunnel to the other and
each side's ClientHello routes into the OTHER's existing client session → both ends are TLS clients → the
exact `got ClientHello when expecting ServerHello` deadlock returns. Roles cannot be decided purely "by
who initiated" (both did), and they cannot be decided up-front purely by peer_id either — a single-sided
low-id initiator must still be able to dial a high-id peer (the ordinary accept path handles that, with
the wire client/server not matching the id order, which is fine — the id rule is a TIE-break, not a
who-dials rule). So glare must be DETECTED, then broken deterministically.

Two non-obvious pieces make it work:
1. **Detect the glare frame by peeking the TLS record.** A ClientHello arriving on a tunnel where we are
   ALSO the client is the glare signal; a ServerHello/app record on that same tunnel is the normal
   expected response. They are distinguished by the TLS record header: content-type byte 0 == `0x16`
   (handshake) and handshake-message-type byte 5 == `0x01` (ClientHello) vs `0x02` (ServerHello). Each
   `poll_write` from rustls ships one record as one relay frame, so the first frame from a fresh dialer
   is a clean ClientHello. This avoids needing a relay-level role signal or parsing beyond the header.
2. **Break the tie by lexicographic peer_id; guard tunnel teardown with a generation id.** Lower hex
   `peer_id` (= SHA-256(SPKI), fixed-length so string compare == byte compare) becomes SERVER; both ends
   compute the same rule → no retry loop. The lower-id side REPLACES its client tunnel with a server
   tunnel under the SAME peer key — so the old client `RelayTunnel`'s `Drop` (fired when its now-doomed
   dial fails) would otherwise evict the fresh server entry. A monotonic per-registration `id` on each
   `TunnelEntry` (and matching check in `close_tunnel`) prevents the stale Drop from removing the newer
   registration.

Test gotcha: tests that pre-open a tunnel via `open_tunnel` and then run an mTLS SERVER over it now
misfire, because `open_tunnel` tags the entry `Client` and the incoming ClientHello is read as glare.
Production servers never do this (they use `enable_accept`); the tests need a Server-role opener
(`open_server_tunnel`, test-only) to mirror a real server receiving a dialer's ClientHello.
