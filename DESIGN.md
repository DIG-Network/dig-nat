# dig-nat — design

`dig-nat` gives a DIG Node ONE way to reach a peer:

```rust
let conn = dig_nat::connect(&peer, &identity, &config).await?;
```

The caller describes the peer once and gets back a **mutually-authenticated (mTLS)** connection.
Which NAT-traversal technique actually established it is chosen internally, transparently — the
caller never selects a method. The result reports which method won (for observability) but the
caller uses the stream identically regardless.

## The abstraction

Everything hangs off two ideas:

- **[`TraversalMethod`]** — a small, single-purpose technique that answers "given this peer, can you
  produce a reachable address I can dial?" One module per method.
- **The [`strategy`]** — orders the enabled methods, tries each with a bounded timeout, and returns
  the first connection that establishes. This is the only place the "which method" decision lives.

The caller sees neither: `connect()` builds the enabled methods from the config, hands them to the
strategy with the production mTLS dialer, and returns the winner.

```
connect(peer, identity, config)
        │
        ├─ build enabled TraversalMethods from config
        │
        ▼
   strategy::connect_with_strategy   ── sorts by rank (direct-first, relay-last)
        │
        │  for each method, in order, each bounded by per_method_timeout:
        │    1. method.attempt(peer)  → a dialable address (or fall through)
        │    2. dialer.dial(peer, …)  → mTLS handshake + peer_id verification (or fall through)
        │
        ▼
   first success → PeerConnection { peer_id (verified), method, remote_addr, mTLS stream }
   all fail      → NatError::AllMethodsFailed([per-method reasons…])
```

## Traversal order (first success wins; relay is genuinely last)

Methods are always attempted in `TraversalKind::rank` order, independent of how the caller listed
them, so the cheapest / most-direct path is preferred and the fully-relayed transport is the true
last resort:

| Rank | Method | What it does | Relay involvement |
|------|--------|--------------|-------------------|
| 0 | **Direct** | Peer is publicly reachable / already port-forwarded — just dial it. | none |
| 1 | **UPnP/IGD** | Ask the local IGD (SSDP + SOAP) to open an inbound port mapping. | none |
| 2 | **NAT-PMP** (RFC 6886) | Ask the gateway (UDP :5351) for a mapping. | none |
| 3 | **PCP** (RFC 6887) | NAT-PMP's IPv6-capable successor. | none |
| 4 | **Relay-coordinated hole punch** | Exchange STUN-discovered candidate addresses **through the relay (signaling only)**, coordinate a simultaneous open, then connect **peer-to-peer directly**. | **signaling only** — a few tiny coordination messages; the relay carries **no data** |
| 5 | **Relayed transport (TURN-like)** | Proxy **all** peer data **through** the relay. | **data plane** — the relay proxies the whole (still-mTLS-encrypted) stream |

### Tier 5 vs tier 6 — the bandwidth distinction (important)

Tiers 5 and 6 both "involve the relay", but they are **separate methods with separate abstractions**:

- **Tier 5 — hole punch** (`method::hole_punch`, trait `HolePunchCoordinator`): the relay is a
  **rendezvous/signaling** channel only. Both peers learn their own reflexive (public) address via
  STUN, exchange candidates and coordinate simultaneous-open timing through the relay (RLY-007
  `hole_punch_request` / `hole_punch_coordinate`), and then the actual data connection is **direct,
  peer-to-peer**. The relay never sees the data. Minimal relay bandwidth.
- **Tier 6 — relayed transport** (`method::relayed`, trait `RelayedTransport`): the relay carries
  **every byte** (RLY-002 `relay_message`) — a TURN-like proxy. Highest relay bandwidth.

Because tier 6 is the expensive one, it is tried **only after** the tier-5 punch fails. The whole
point is to save relay bandwidth by brokering an introduction whenever possible instead of proxying
the stream. Both tiers still wrap the resulting byte path in the same mTLS session — for tier 6 the
relay proxies ciphertext it cannot read.

After a successful hole punch, tests assert the data path is direct (the relay's data plane is never
touched); the relayed transport is only reached when the punch is unavailable/fails.

## Identity + mTLS

Every node-to-node connection is **mutual TLS**. A peer's identity is:

```
peer_id = SHA-256( TLS SubjectPublicKeyInfo DER )
```

byte-identical to `dig-gossip`'s `peer_id_from_tls_spki_der` (`identity` module; pinned by a
cross-crate conformance test). DIG certs are **self-signed and the key IS the identity** — there is
no CA. So the rustls verifier (`mtls::PeerIdPinningVerifier`) does not check a trust chain; it:

1. captures the peer's leaf certificate,
2. derives its `peer_id`, and
3. **pins** it — rejects the handshake unless the derived id matches the `peer_id` the caller asked
   to reach (and always records the derived id so the caller learns exactly who it connected to).

The dialer presents this node's own certificate as the mTLS client cert, so both sides authenticate.
This makes the transport self-authenticating: connecting to `peer_id X` provably reaches the holder
of X's private key or fails.

## STUN (RFC 5389)

`stun` implements the Binding request/response directly (a 20-byte header + XOR-MAPPED-ADDRESS
attribute). It discovers this node's **server-reflexive** (public) address — the `ip:port` the
outside world sees — which is the candidate advertised for the hole punch. The DIG relay runs a STUN
server; any RFC-5389 server also works.

## Relay client + graceful fallback (relay resilience baked in)

`relay` is the relocated + generalized `dig-node` relay client. Two responsibilities:

1. **Persistent reservation** (`run_relay_connection`) — a NAT'd node holds a constant registered
   connection with the relay so peers can reach it and so the relay can broker hole punches.
2. **Last-resort transport** — tier 6 above.

The reservation loop bakes in the resilience guarantees:

- **Never blocks startup, never panics/exits.** It runs as a background task; a node with no relay
  keeps serving indefinitely.
- **Bounded reconnect.** Capped-exponential backoff (`backoff_secs`, base 5s → cap 300s) so a failed
  connect can never busy-loop.
- **Keepalive.** RLY-006 ping/pong keeps the reservation alive.
- **Log once per state change.** `RelayStatus` transitions log only on change, so a relay down for
  hours produces one warn line, not a flood.
- **Observable.** `RelayStatus` is a cheap atomic snapshot exposing one of four `RelayState`s
  (`disabled | connecting | connected | disconnected`) plus last error + attempt count, surfaced
  verbatim to a `control.relayStatus`-style RPC / `/health`.
- **Opt-out honored.** `DIG_RELAY_URL=off` (or `disabled`) → `RelayState::Disabled`, no attempts.
- **Endpoint from `dig-constants`.** Default `wss://relay.dig.net:9450` (single source of truth),
  overridable via `DIG_RELAY_URL`.

## Testability (no real network / no mainnet)

Every seam is an abstraction so the whole thing tests in-process:

- methods are `TraversalMethod` trait objects → tests inject **mock methods** to drive ordering,
  first-success-wins, relay-last, and all-fail→error;
- the mTLS dial is behind `Dialer` → tests inject a **fake dialer** returning a canned outcome;
- UPnP is behind `IgdGateway` → a **fake gateway** (no SSDP/SOAP);
- hole punch is behind `HolePunchCoordinator`, relayed transport behind `RelayedTransport` → **mock
  coordinators** (no relay) that also prove tier-5-before-tier-6;
- the relay client runs against a **loopback WebSocket relay** in tests;
- STUN, NAT-PMP, PCP encode/parse are pure functions tested against **RFC byte layouts**;
- mTLS identity is tested with an **ephemeral self-signed cert** (`rcgen`) round-tripped through
  `peer_id_from_leaf_cert_der`.

The one genuinely network-bound path — live UPnP SSDP discovery in `RealIgd` — is isolated behind
the trait and covered only by an opt-in integration test.

## Streaming-first, multiplexed transport (uniform across every tier)

Whatever tier establishes the link, the result is the same: one mTLS byte stream wrapped in
[`yamux`] multiplexing (`mux::PeerSession`). This makes the transport **streaming-first**, never
"send request, buffer the whole response in memory":

- **Many cheap concurrent logical streams.** `PeerConnection::open_stream()` opens an independent
  bidirectional stream; open N at once with no head-of-line blocking (yamux windows give
  backpressure — a slow reader slows its sender, not the whole connection).
- **Byte-range streams.** `PeerConnection::open_range_stream(&RangeRequest)` opens a stream scoped to
  `[offset, offset+length)` of a resource (or a whole capsule) by writing the `dig.fetchRange`
  preamble, then streams back `RangeFrame`s (`{offset, length, bytes, complete}`; the first frame
  adds `total_length` + `chunk_lens` + `chunk_index` + `inclusion_proof` + `root`). A downloader
  opens range streams to **different peers in parallel** and reassembles by offset.
- **Availability pre-check first.** `PeerConnection::query_availability(items)` is the
  `dig.getAvailability` control call — a small message-style request (not streamed) asked BEFORE any
  range fetch, batched across items at store / root / capsule granularity. The normative multi-source
  flow is: **discover** peers → **query availability** (keep only holders) → **fan** byte-ranges
  across holders concurrently → **verify** each against the chain-anchored root → **retry** a bad
  range from another holder → **reassemble** (per-range resume). dig-nat carries this; the content
  layer above it does the per-chunk merkle verification + AES-256-GCM-SIV decryption.

The mux + range + availability wire shapes conform to the published **L7 peer-network spec**
(docs.dig.net "L7 · DIG Node peer network", §8 streaming, §9 range fetch + availability): the same
`dig.getAvailability` / `dig.fetchRange` / `RangeFrame` field names, STUN on `relay.dig.net:3478`,
and the peer-RPC error codes (`-32004` / `-32006 PEER_UNREACHABLE` / `-32007 RANGE_NOT_SATISFIABLE`,
exposed as `error::rpc_error_codes`). A `NatError` from a failed `connect` maps to
`-32006 PEER_UNREACHABLE`.

## Dependency philosophy

The small, well-specified NAT datagrams (NAT-PMP, PCP, STUN) are implemented **directly** — they are
tiny fixed-layout packets, so hand-rolling them keeps the dependency tree small AND makes every byte
unit-testable with no network. This mirrors the ecosystem's existing vendoring rationale (dig-relay /
dig-node vendor the relay wire rather than pull the whole dig-gossip stack). Only UPnP/IGD — a large
SSDP+SOAP protocol — uses an external crate (`igd-next`, the maintained fork), behind the same trait
as everything else.

## Spec conformance + reconciliation notes

The crate conforms to the published **L7 peer-network spec** (docs.dig.net, `docs/protocol/
peer-network.md`, commit `dde8674`). Frozen shapes reproduced here: `peer_id = SHA-256(SPKI DER)`;
the NAT ladder order (direct → UPnP → NAT-PMP → PCP → hole-punch signalling → relayed/TURN); STUN on
`relay.dig.net:3478`; the RLY-001..007 `RelayMessage` JSON wire; `dig.getAvailability` /
`dig.fetchRange` + `RangeFrame`; the peer-RPC error codes.

Open items for the spec authors / sibling crates to confirm as they land:

- **Relay STUN server.** A sibling agent is adding STUN + an introducer to `dig-relay`. `dig-nat`'s
  STUN client implements RFC 5389 Binding + XOR-MAPPED-ADDRESS on port 3478 per the spec; if the
  relay's emitted STUN wire diverges in any detail, reconcile in `stun.rs`.
- **Candidate-address model.** The spec's `dig.getPeers` returns candidate addresses with a `kind`
  (`direct`/`reflexive`/`mapped`/`relay`). `dig-nat` produces the reachable address per tier; the
  richer candidate *advertisement/selection* surface (and the `dig.getPeers`/`dig.announce`/
  `dig.getNetworkInfo` RPCs) lives in the node above dig-nat — dig-nat provides the transport those
  RPCs drive. When the node wires them, confirm the candidate `kind` mapping matches the tiers here.
- **Identity edge.** `peer_id = SHA-256(SPKI DER)` is re-implemented (not imported) from `dig-gossip`
  per the foundational-crate rule; the cross-crate conformance test (`tests/identity.rs`) keeps them
  locked. `SYSTEM.md` should record the dig-nat ↔ dig-gossip identity edge and the dig-nat ↔ dig-relay
  wire edge.
- **Auto-composition of `connect`.** `connect()` currently auto-composes the methods it can build
  from config alone (Direct); the UPnP/NAT-PMP/PCP/hole-punch/relayed methods are fully implemented +
  tested and composed by callers holding the runtime context (gateway, local port, reflexive addr,
  live relay). Wiring the discovery inputs through the builder so `connect` auto-composes all tiers is
  the natural next step once the node supplies them.
```
