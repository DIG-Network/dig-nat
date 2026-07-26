# dig-nat — development log

Durable, non-obvious realizations from developing dig-nat. Context, not a change diary.

## Owning both sides of a framing contract is exactly when you enforce it on only one side

dig-nat defined `encode_framed` and `decode_framed` twelve lines apart in one file and, for its whole
life, capped only the decoder. `decode_framed` rejected any body over `MAX_FRAMED_BODY` (64 KiB);
`encode_framed` wrote a `u32` prefix and the body with no check, and could not have failed if it wanted
to — it returned `Vec<u8>` and `.expect()`ed on serialization. So the crate handed every serving peer a
loaded gun: emit a frame that no conforming receiver is permitted to accept, and watch the error appear
on someone else's machine as `InvalidData("control message too large")` with no mention of size.

Downstream, `dig-node` split its serve paths on a 3 MiB request WINDOW because nothing told it the
per-FRAME limit was 64 KiB of body — about 48 KiB of raw payload once `bytes` is base64'd, less again
once the first frame's `chunk_lens`/proof metadata is attached. Every read of a resource above roughly
48 KiB therefore failed at the reader. The read-leg e2e proofs that "passed" had served 20,477 and
27,067 bytes: both single-frame, both under the ceiling, neither capable of noticing.

**Why no test caught it, precisely.** The framing tests round-tripped small fixtures, and the transport
tests used in-process mocks. Both properties held for small payloads, and neither test could fail
because the bug was not a wrong VALUE — it was a missing BOUND, and a bound is only observable at a
scale the fixtures never reached. A symmetric round-trip is structurally blind here: it feeds the
decoder exactly what the encoder produced, so an encoder that produces something illegal and a decoder
that would reject it never meet.

Two lessons worth generalizing:

1. **When one module owns both sides of a wire contract, the asymmetry is more likely, not less.** Two
   separately-authored implementations negotiate the limit explicitly because neither trusts the other.
   One implementation "knows" its own encoder is fine. Enforce every receiver-side bound on the sender
   too, and make the sender's failure LOUD and LOCAL — a send-site error naming the constant is worth
   more than the check itself.
2. **A size limit needs a test at the limit, and the limit must be published.** The fix exports
   `MAX_FRAMED_BODY` and `MAX_RANGE_FRAME_PAYLOAD` so no consumer has to guess or hardcode `64 * 1024`
   (dig-node had). The ceiling is deliberately 32 KiB rather than the base64-only bound of ~48 KiB,
   because the first frame's metadata scales with the RESOURCE — a 512 MiB resource at 256 KiB chunks
   puts 2048 integers on it. An exact-fit constant passes an over-cap-refused test and still overflows
   in production, so the worst-case-metadata test is the one that actually holds the number in place.


### Postscript: two things the review gate caught, both the same mistake one level up

**Merging this crate did not fix the bug on the wire.** dig-node does not use dig-nat's framing at all
— `crates/dig-node-core/src/peer.rs` has its own `write_framed` (uncapped) and its own read cap written
as the literal `64 * 1024`, with a comment saying it mirrors dig-nat's constant. So the identical
asymmetry exists there independently, and correcting the oversized window constants does not close it.
Tracked as #1645. The generalizable point: when a bound is duplicated as a literal in a second
implementation, fixing the original changes nothing on the wire, and the comment claiming the two agree
is the only thing holding them together. That comment is not a mechanism.

**The headroom argument was wrong, and it was wrong the same way FOUR TIMES.** The number of
`chunk_lens` entries that fits on a first frame was derived wrong at every attempt, and each attempt
failed for the same structural reason: **one co-occurring maximum stayed implicit, and the answer came
out too generous.**

| attempt | implicit premise | figure | reality at all maxima |
|---|---|---|---|
| 1 | chunk SIZE (assumed 256 KiB chunks → 5-digit entries) | 3,373 | 68,909 B |
| 2 | entry WIDTH fixed, but PROOF size implicit (~1,400 B, cap is 4,096) | 2,891 | 68,371 B |
| 3 | proof fixed, but `chunk_count` held at 7 digits not 20 | 2,487 | 65,543 B |
| 4 | none — all four maxima held simultaneously | **2,486** | 65,536 B, exactly at the cap |

Every error was in the **unsafe direction**, and that is not a coincidence: leaving a maximum implicit
means measuring a *narrower* frame than the protocol permits, so the bound always comes out too large,
and a too-large sender bound licenses exactly the defect being fixed — a conforming sender emitting a
frame the receiver must reject. An error in the safe direction merely wastes a few entries; this class
of error reintroduces the bug.

The rules that fall out, and they are cheap:

- **Publish the NUMBER, and beside it name EVERY maximum it was derived against.** Not a formula: a
  formula is a formula whose premises get re-guessed. Four premises here — payload at its cap, proof at
  its cap, entries at their widest legal decimal form, every `u64` scalar at max width.
- **Hold every co-occurring field at ITS OWN cap in the fixture.** A fixture with a narrow proof or a
  small scalar measures a narrower frame than the protocol permits and will certify a too-generous
  bound. This is the same failure as the 2,048-entry "worst case" and as the sub-48 KiB e2e fixture that
  hid #1640 itself.
- **Pin the bound from BOTH sides.** At the value it must fit; one past it must not. A bound checked
  only from below can only ever confirm itself. Pinned both ways, exactly one value passes — raising it
  to 2,487, 2,495 or 2,891 fails the upper pin, lowering it to 2,048 fails the lower pin.
- **Settle these by SERIALIZING the real struct, never by arithmetic in prose.** Three of the four wrong
  answers came from reasoning about byte counts in sentences. Where a field does not exist yet (the
  0.13.0 prologue), measure it with a mirror struct rather than adding a byte count to a comment.
- **Derive against the FUTURE field set when it is known — and it paid off exactly as intended.** 2,486
  was computed on the then-unwritten 0.13.0 fields via a two-field mirror struct. When those fields
  actually landed, the real struct measured **65,536 B at 2,486 entries** — the mirror's 76 B reservation
  was exact, so a bound with ZERO slack survived a field addition without moving. The reservation
  technique is the transferable part: reserve the future field set by serializing a mirror of it, and the
  next release does not get to invalidate your published number.

Also worth separating: `MAX_FIRST_FRAME_CHUNK_LENS` = 2,486 is the hard arithmetic ceiling, while
`MAX_CHUNK_LENS_PER_FRAME` = 2,048 is the sender's paging threshold. Both are correct, they do different
jobs, and the gap between them is deliberate margin. Collapsing a safety margin into an exact ceiling is
how a system ends up operating with none.

A blunter way to say all of it: the refusal invariant in this crate is what surfaced the whole
collision. A guard that fails loudly at the sender turned four silent wrong numbers into four caught
ones.


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

## Relay glare, part 2 — the tie-break alone is not enough; role must be non-clobber + decided under one lock

The first #1536 glare fix applied the lower-id-is-server tie-break only on the existing-client-tunnel
path, which silently assumed both client tunnels register BEFORE either ClientHello arrives. A deeper
race breaks that: if peer A's ClientHello reaches B BEFORE B's own dial to A registers, B accepts A as
server (introduced-circuit path, no tunnel yet); B then dials A and the unconditional `register_tunnel`
insert CLOBBERS B's own server entry → an orphaned server accept task PLUS a client dialer under the same
key → two conflicting mTLS sessions to one peer → TLS error/hang. Role was effectively decided by
who-registered-first (timing), not by peer_id.

Three things make it robust under ALL orderings:
1. **Non-clobber `open_tunnel`.** Refuse a dial to a peer a circuit already exists for — the existing
   circuit (client OR server) IS the connection. This kills the timing-ordered double-session: once we
   serve a peer, our later dial to it is refused instead of clobbering. The accept path is likewise
   non-clobber (never overwrites an existing entry).
2. **Take the per-frame role lookup + yield under one lock; let non-clobber cover the seam.** The
   get-role → (deliver | ignore | yield-remove-client) decision runs under a single `tunnels`-lock
   acquisition. The follow-on server registration (`accept_introduced`) re-acquires the lock and
   re-checks for an existing entry, so the yield→accept transition spans TWO lock regions — that is
   benign because the re-check is non-clobber: a dial that races in between abandons the server register
   rather than clobbering into a double-session. (Don't be misled into thinking it's one atomic region;
   the safety comes from non-clobber, not from a single critical section across remove+reinsert.)
3. **Self / SPKI-collision guard.** A dial to our own id, or an inbound frame stamped with our own id
   (a hostile relay can reflect it), has no lower/higher end for the tie-break → must be rejected, not
   left to hang with no server.

Untrusted-relay caveat worth remembering: since the glare ClientHello is an opaque relayed frame, a
relay can INJECT a bogus 0x16..0x01 frame on a lower-id node's client tunnel to force it to yield its
real outbound dial to a server accept nothing completes — a selective relayed-dial DoS. mTLS identity is
never bypassed (the bogus circuit authenticates nothing), and the dial is not permanently lost (dropping
the dead server circuit frees the peer key for a re-dial), but consumers should bound the server-accept
with a timeout and re-dial on failure. It is an availability property inherent to an untrusted TURN relay.

## `#[non_exhaustive]` is the field that pays for all the future fields

0.13.0 added two fields to `RangeFrame` and one to `RangeRequest`, and the expensive part was not the
fields — it was that five consumer crates all had to release to see them, because these types had public
fields and no `#[non_exhaustive]`, so *any* field addition was a breaking change.

`#[non_exhaustive]` inverts that permanently: every future additive field on these wire types is a
**patch**, and consumers keep compiling. The catch is that the attribute is itself breaking — it forbids
ALL cross-crate struct literals (`E0639`) whether or not you add a field — so it can only go in alongside
a break you are already paying for. 0.13.0 was that window.

Two things learned doing it:

- **Constructors are the migration path, not a nicety.** A `#[non_exhaustive]` type with no constructor is
  simply unbuildable by a consumer. Every one of the six wire types got a `new`/named constructor plus
  `with_*` setters for the optional fields, and dig-nat's own integration tests are separate crates, so
  migrating them exercised the exact `E0639` the consumers were about to hit — the in-repo migration is
  the cascade's worked example.
- **`RangeFrame`'s constructor had to make the metadata OMITTABLE.** Continuation frames must not carry
  the resource-scaling set; a constructor that demanded it would have made every continuation-frame call
  site state a layout it is not stating. Hence `data()` + `with_identity()` + `with_chunk_lens_page()` +
  `with_inclusion_proof()`: the first-frame and continuation shapes are different call chains rather than
  one call with a pile of `None`s.

## A premise only a test believes is not a bound

`MAX_INCLUSION_PROOF_B64` = 4,096 was cited as *premise 2* of the published entry bound in SPEC.md and in
a doc comment, while existing only as a `const` inside a test file. Nothing enforced it, and no consumer
could read it — so an 8 KiB proof made a resource with well UNDER 2,486 chunks unsendable, which is
exactly what the word GUARANTEED said could not happen (#1655).

It failed closed, which is why it was survivable: a refusal, not an undecodable frame. But the lesson
generalizes past this constant. **If a published bound rests on a premise, the premise must be a
published, enforced value, and the test must import it rather than declare its own copy** — a
test-local `const` is indistinguishable from enforcement right up to the moment a real input exceeds it.
The test for it also has to be built so the refusal can only be the proof's fault: the fixture holds a
comfortably sub-bound entry count, because an at-bound one would have been refused either way.
