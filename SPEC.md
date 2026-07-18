# dig-nat — normative specification

`dig-nat` establishes a single mutually-authenticated (mTLS) connection to a DIG Node peer using the
best available NAT-traversal method, transparently. This document is the authoritative, normative
statement of what the crate implements: its public contract, address-family policy, traversal
strategy, dial behavior, identity model, and conformance points. Keywords **MUST**, **SHOULD**, and
**MAY** are used as in RFC 2119.

## 1. Scope

An implementation of this spec provides `connect(peer, identity, config) -> PeerConnection`, where
the caller describes the peer once (identity + candidate addresses) and receives a verified,
multiplexed, encrypted connection. The caller **MUST NOT** be required to choose the traversal
method; the crate selects it. The traversal technique that established the connection **MUST** be
reported (`PeerConnection::method`) for observability but **MUST NOT** change how the caller uses the
connection.

## 2. Peer identity + mTLS (unchanged contract)

- A peer's identity is `peer_id = SHA-256(TLS SubjectPublicKeyInfo DER)`, byte-identical to
  `dig-gossip`. All node-to-node traffic is mutual TLS. Certificates are self-signed; the key IS the
  identity (there is no CA).
- The dialer **MUST** present this node's certificate as the mTLS client certificate and **MUST**
  reject the handshake unless the remote's derived `peer_id` equals the `peer_id` the caller asked to
  reach (`PeerIdPinningVerifier`). The verified identity **MUST** be reported on the returned
  connection.
- `LocalIdentity::key_der` (this node's PKCS#8 private key DER) **MUST** be held in a zeroizing
  container (`zeroize::Zeroizing<Vec<u8>>`) so the plaintext key bytes are scrubbed on every clone
  and drop — `LocalIdentity` is cloned per dial. Implementations **MUST NOT** hold the private key
  material in a plain, non-zeroizing buffer.

## 3. Address-family policy — IPv6-first, IPv4-fallback (NORMATIVE)

All peer-to-peer address handling in `dig-nat` is **IPv6-first with IPv4 as a fallback**. The
authority for address-family discovery, the local∩peer family intersection, and the happy-eyeballs
dial is the canonical **`dig-ip` crate** (CLAUDE.md §5.2) — see its `SPEC.md`. `dig-nat` MUST use
`dig_ip::connect` / `dig_ip::dial_order` rather than hand-rolling candidate ordering or a racer; it is
the FIRST consumer of that crate. This section states how `dig-nat` wires into it.

### 3.1 Candidate model

- A peer's directly-dialable addresses are carried as a **candidate list**
  (`PeerTarget::direct_addrs`), NOT a single address.
- The list is stored in **discovery order** — the caller supplies candidates in whatever order it
  learned them; `dig-nat` **MUST NOT** re-order them. The IPv6-first preference + the family
  intersection are applied at DIAL time by `dig-ip` (§3.3), which derives each address's family via
  `dig_ip::Family::of` (never a string heuristic; an IPv4-mapped IPv6 address is treated as IPv4).
- The constructors `PeerTarget::with_addr` / `PeerTarget::with_addrs` and the mutator
  `PeerTarget::set_direct_addrs` preserve the supplied order.
- `PeerTarget::direct_addrs()` returns the candidate list in discovery order. `PeerTarget::direct_addr()`
  returns the first candidate, or `None` for a relay-only target. A relay-only target
  (`PeerTarget::relay_only`) has an empty candidate list.

### 3.2 Outcome model

- A traversal method yields a `MethodOutcome` carrying the candidate addresses to dial
  (`MethodOutcome::dial_addrs`), in discovery order, never empty on success.
- The direct and mapping methods (Direct, UPnP, NAT-PMP, PCP) **MUST** carry the peer's whole
  candidate list so the dial can fall back across families. They construct the outcome via
  `MethodOutcome::candidates` (which stores the list as-is).
- The hole-punch and relayed methods yield a single coordinated peer address or the relay endpoint
  respectively, via `MethodOutcome::single`.
- `MethodOutcome::dial_addr()` returns the first candidate in discovery order.

### 3.3 Dial path — `dig-ip` (family intersection + happy eyeballs, RFC 8305)

The dialer **MUST** delegate family selection + racing to `dig_ip::connect`. `MtlsDialer::dial`:

- aggregates the outcome's addresses into a `dig_ip::PeerCandidates` (`dialer::candidates_from_outcome`),
  tagging each with a `dig_ip::CandidateSource` for observability (provenance MUST NOT influence the
  intersection rule);
- resolves the local host's `dig_ip::LocalStack` — `LocalStack::cached()` in production, or a pinned
  stack via `MtlsDialer::with_local_stack` for deterministic tests;
- calls `dig_ip::connect(&local, &candidates, config, dial_fn)` where `dial_fn` performs one
  candidate's raw TCP connect; then runs the single mTLS handshake over the winning stream.

The behaviour `dig-nat` INHERITS from `dig-ip` (its structural guarantees, tested here in
`tests/dial_family.rs`):

- **G1** — the dial NEVER attempts an address of a family the LOCAL host lacks (an IPv4-only host
  never emits an IPv6 SYN).
- **G2** — the dial NEVER attempts an address of a family the PEER lacks.
- **IPv6-first preference** — a viable IPv6 candidate wins even if a hedged IPv4 attempt connects
  sooner; IPv4 wins only when IPv6 genuinely fails/stalls.
- **Clean disjoint outcome** — when the local host and the peer share no family, the dial fails
  IMMEDIATELY with `dig_ip::ConnectError::NoCommonFamily` (surfaced as a `MethodError` whose reason
  contains "no common address family"); NO dial is attempted, so there is no doomed, hanging SYN.
- The per-attempt timeout + inter-attempt stagger are configurable (`HappyEyeballsConfig`, mapped to
  `dig_ip::DialConfig`) so the racing is deterministically testable.
- The established connection's reported remote address (`PeerConnection::remote_addr`) reflects the
  candidate (and therefore family) actually used.

### 3.4 Per-method address-family notes

- **STUN (RFC 5389)** parses BOTH `FAMILY_IPV4` and `FAMILY_IPV6` XOR-MAPPED-ADDRESS attributes;
  reflexive-address discovery is family-agnostic.
- **PCP (RFC 6887)** uses 16-byte (128-bit) address fields throughout and is IPv6-capable (IPv4 is
  encoded as an IPv4-mapped IPv6 address).
- **UPnP/IGD** and **NAT-PMP (RFC 6886)** are protocol-inherently IPv4 (they map an inbound IPv4
  pinhole / speak an IPv4-only datagram). They remain the IPv4 fallback for inbound reachability.
  Because a host with a global-unicast IPv6 address needs no NAT mapping, the UPnP path **SHOULD**
  additionally discover a routable IPv6 candidate for advertisement:
  `upnp::select_global_ipv6` selects the address to advertise, preferring a global-unicast IPv6 over
  link-local (`fe80::/10`), ULA (`fc00::/7`), loopback, and unspecified addresses (which are not
  peer-reachable across the internet). Such an IPv6 candidate **MUST** be advertised ordered first.

## 4. Traversal strategy

- Methods are always attempted in `TraversalKind::rank` order regardless of the order the caller
  listed them: `Direct (0) → Upnp (1) → NatPmp (2) → Pcp (3) → HolePunch (4) → Relayed (5)`. The
  cheapest/most-direct path is preferred; the fully-relayed transport is the last resort.
- Each method attempt AND its dial are each bounded by a per-method timeout; a hung method or dial
  **MUST NOT** block `connect`.
- The first method that produces a verified mTLS `PeerConnection` wins; later methods are not
  attempted. If no method is enabled, `connect` returns `NoMethodsEnabled`. If every enabled method
  fails, it returns `AllMethodsFailed` with the ordered per-method reasons.
- Tier 4 (hole punch) uses the relay as a **signaling-only** rendezvous (the data path is direct
  peer-to-peer); tier 5 (relayed) proxies ALL data through the relay. Tier 5 **MUST** be attempted
  only after tier 4 fails, to conserve relay bandwidth. Both tiers wrap the resulting byte path in the
  same mTLS session.

## 5. Transport surface

- Whatever tier establishes the link, the result is one mTLS byte stream wrapped in `yamux`
  multiplexing (`PeerSession`). The caller opens many concurrent logical streams
  (`PeerConnection::open_stream`), byte-range streams (`PeerConnection::open_range_stream`,
  `dig.fetchRange`), and availability pre-checks (`PeerConnection::query_availability`,
  `dig.getAvailability`). Field names + wire shapes conform to the L7 peer-network spec.

## 5a. Persistent relay reservation + discovery (NORMATIVE)

A node behind NAT holds a CONSTANT registered connection to the relay (`run_relay_connection`) — its
reachability channel and the rendezvous for relay-coordinated hole-punch. This ONE long-lived
WebSocket is ALSO the relay-introducer discovery channel; discovery **MUST NOT** open a fresh
ephemeral socket per pass (two nodes whose sub-second register-then-close windows never overlap would
never see each other).

- The reservation **MUST** register exactly once per session (RLY-001) and keep the socket open,
  sending RLY-006 keepalives, and reconnect with capped-exponential backoff on any drop.
- Over the SAME socket the reservation **MUST** send RLY-005 `GetPeers` immediately after registering
  and periodically thereafter (`DISCOVERY_INTERVAL_SECS`), and **MUST** fold the `Peers` response plus
  relay-pushed `PeerConnected` / `PeerDisconnected` notices into the discovered-peer set.
- The discovered-peer set is exposed via `RelayStatus::known_peers` / `known_peer_count` for the
  consumer (dig-gossip's pool/address book) to read. It is per-session — cleared on every reconnect so
  a stale list is never served across a drop.
- The relay is an UNTRUSTED intermediary. The discovered-peer set **MUST** be bounded to a fixed cap
  (`MAX_KNOWN_PEERS`, 1024) and deduped by `peer_id`: a hostile/compromised relay can stream an
  unbounded flood of `PeerConnected` frames — or a single oversized `Peers` frame — with distinct
  fabricated `peer_id`s. Once the set is full, further distinct peers **MUST** be dropped (the set
  never grows past the cap), and both the per-push fold and the `Peers`-frame replace **MUST** enforce
  it. Membership/dedup **MUST** be O(1) so the flood cannot impose an O(n²) insert cost.

### 5a.1 Address-carrying introduction (B1, NORMATIVE)

The reservation advertises dialable candidates so a relay-discovered peer can be DIRECT-dialed over
the existing mTLS path instead of only reached over relayed transport. Both wire fields are additive
(NC-6 soft-fork) — default-empty, skipped-when-empty, appended last — so a pre-#924 peer/relay omits
them and falls back to identity-only relayed reachability. They are byte-identical to
`dig-relay-protocol` 0.2.0.

- On `Register` (RLY-001) the node **MUST** advertise its gossip LISTEN candidate address(es) in
  `Register.listen_addrs` (IPv6-first, §3). The host is typically the unspecified dual-stack address
  (`[::]`); the useful part the relay keeps is the port.
- When folding discovered peers, the reservation **MUST** parse `RelayPeerInfo.addresses` (the
  relay-resolved dialable candidates) and expose them via `RelayStatus::known_peers`, so the consumer
  (dig-gossip's pool/address book) can direct-dial them. A peer with empty `addresses` remains
  identity-only (today's relayed reachability).

## 5b. Relayed transport — the tier-6 TURN fallback (B2, NORMATIVE)

When no more-direct method (Direct/UPnP/PMP/hole-punch) can reach a peer, the connection is carried
THROUGH the relay by RLY-002 `relay_message` forwarding — the genuine last resort.

- The relayed transport **MUST** reuse the node's ONE persistent reservation socket (§5a) — it
  **MUST NOT** open a second connection to the relay. Outbound frames are injected into the live
  reservation write half; inbound `relay_message` frames are routed to the matching tunnel by the
  sender's `peer_id` (`from`).
- `RelayStatus::open_tunnel(target_peer, network_id)` yields a `RelayTunnel` — a bidirectional payload
  channel forwarded A→relay→B. `open_tunnel` **MUST** fail when no reservation is held
  (`relay_transport_ready` is false). Dropping the tunnel deregisters its routing.
- Per NC-1 / §5.4 the tunnel payload **MUST** be END-TO-END SEALED to the recipient's key by the
  caller: the relay is an untrusted forwarder that sees only ciphertext. This crate carries opaque
  bytes and does not itself seal — the consumer (dig-gossip) seals.
- Backpressure + flood defense: a single payload **MUST NOT** exceed `MAX_RELAY_PAYLOAD` (1 MiB) — an
  oversized `send` errors and an oversized inbound frame is dropped; each tunnel's inbound buffer is
  bounded (`RELAY_TUNNEL_INBOUND_CAP`) and a full buffer drops the frame (the RLY-002 `seq` lets the
  consumer detect the gap).
- The production `RelayedTransport` (the strategy's tier-6 seam) is `ReservationRelayedTransport`; it
  gates on a live reservation and reports the relay endpoint for observability, while the byte stream
  is taken via `open_tunnel`.

## 6. STUN/PCP anti-spoof requirements (NORMATIVE)

STUN Binding responses (RFC 5389) and PCP MAP responses (RFC 6887) travel over unauthenticated UDP.
Both protocols correlate a response to its request with a caller-chosen id (a 96-bit STUN transaction
id / a 96-bit PCP MAP nonce) that is the primary defense against an off-path attacker forging a
response before the real server's reply arrives. This crate additionally validates the response
source address. Both properties are REQUIRED, independently of each other:

- **Id/nonce generation MUST use a CSPRNG.** `stun::new_transaction_id` and the PCP MAP nonce
  generator **MUST** fill every byte of the 96-bit id/nonce from a cryptographically secure random
  source (`ring::rand::SystemRandom`). They **MUST NOT** derive the id/nonce from wall-clock time,
  a counter, or any other attacker-predictable input — RFC 5389 §10.1 requires the STUN transaction
  id be "uniformly and randomly chosen"; RFC 6887 §11.1 requires the PCP nonce be unpredictable.
  A predictable id/nonce is a poisoning vulnerability: it is the only check that gates a forged
  `BINDING_SUCCESS` / MAP-success response.
- **Response source validation.** A STUN client performing [`stun::query_reflexive_address`] and the
  PCP method's `transact` **MUST** verify the response datagram's source address equals the address
  the request was sent to (the configured STUN `server` / the PCP `gateway`) before accepting the
  response. A response from any other source **MUST** be discarded and the client **MUST** continue
  waiting within the transaction's deadline (dropping the whole transaction on one mismatched
  datagram would let a single spoofed packet defeat it). This is independent, defense-in-depth
  hygiene alongside the id/nonce check — it does not replace it.
- Both checks apply to every UDP request/response protocol this crate speaks (STUN today; PCP's
  nonce check is the same pattern). NAT-PMP (RFC 6886) has no per-transaction nonce by protocol design
  and is not held to the id/nonce requirement, but source validation still applies where practical.

## 7. Configuration + defaults

- `NatConfig` selects the enabled methods (default: all six), the per-method timeout, the relay
  endpoint (default `dig_constants::DIG_RELAY_URL`, `DIG_RELAY_URL=off` opt-out honored), and the STUN
  server (default derived from the relay host on port 3478).
- `HappyEyeballsConfig` defaults to a ~250ms stagger and a generous per-attempt timeout (the strategy
  per-method timeout is the real outer bound).

## 8. Public API surface (normative)

```
PeerTarget::with_addr(peer_id, addr, network_id)            // single candidate
PeerTarget::with_addrs(peer_id, Vec<SocketAddr>, network_id)// many candidates, discovery order
PeerTarget::relay_only(peer_id, network_id)                 // no direct candidates
PeerTarget::direct_addrs() -> &[SocketAddr]                 // candidates, discovery order
PeerTarget::direct_addr()  -> Option<SocketAddr>            // first candidate
PeerTarget::set_direct_addrs(Vec<SocketAddr>)               // replace (order preserved)

MethodOutcome::single(kind, addr)                           // hole-punch / relayed (one address)
MethodOutcome::candidates(kind, Vec<SocketAddr>)            // direct / mapping (discovery order)
MethodOutcome::dial_addr() -> Option<SocketAddr>            // first candidate
MethodOutcome.dial_addrs: Vec<SocketAddr>                   // candidates, discovery order

// Family selection + happy-eyeballs racing is dig-ip's job (dial-time); dig-nat wires into it:
dialer::HappyEyeballsConfig { per_attempt_timeout, stagger } // -> dig_ip::DialConfig
dialer::candidates_from_outcome(&MethodOutcome) -> dig_ip::PeerCandidates
dialer::MtlsDialer::new(identity).with_happy_eyeballs(cfg).with_local_stack(dig_ip::LocalStack)

connect(peer, identity, config) -> Result<PeerConnection, NatError>
```

## 9. Conformance

- Candidate storage: `direct_addrs()` returns candidates in discovery order (no re-sorting); ordering
  + intersection are dig-ip's job at dial time.
- Family intersection (via dig-ip, `tests/dial_family.rs` using `LocalStack::from_flags`): dual-stack
  prefers IPv6; a failed IPv6 falls back to IPv4; a v4-only host dials only IPv4 (G1); a v4-only peer
  is dialed only over IPv4 (G2); a disjoint local/peer pair fails immediately with `NoCommonFamily` and
  attempts NO dial. End-to-end over the production `MtlsDialer`: `[unreachable IPv6, reachable IPv4]`
  connects over IPv4; a v4-only host asked for a v6-only peer returns a clean no-common-family error.
- IPv6 selection: `select_global_ipv6` returns a global-unicast IPv6 and rejects link-local / ULA /
  loopback / unspecified.
- Identity: `peer_id = SHA-256(SPKI DER)` matches `dig-gossip` (cross-crate conformance test).
- STUN/PCP anti-spoof: transaction id / MAP nonce samples show CSPRNG-level variation across their
  full byte range (not a wall-clock-derived pattern); `query_reflexive_address` and the PCP
  `transact` accept a response only from the address the request was sent to, looping past a
  mismatched-source datagram rather than failing the transaction outright.
