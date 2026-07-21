# dig-nat — normative specification

`dig-nat` establishes a single mutually-authenticated (mTLS) connection to a DIG Node peer using the
best available NAT-traversal method, transparently. This document is the authoritative, normative
statement of what the crate implements: its public contract, address-family policy, traversal
strategy, dial behavior, identity model, and conformance points. Keywords **MUST**, **SHOULD**, and
**MAY** are used as in RFC 2119.

## 1. Scope

An implementation of this spec provides two entry points:

- `connect(peer, node, config) -> PeerConnection` — the convenience entry for a caller with NO live
  transport handles; it composes only the tiers requiring no runtime input (currently **Direct**).
- `connect_with_runtime(peer, node, config, runtime) -> PeerConnection` — auto-composes the **FULL**
  ladder from the `NatRuntime` carrier's live handles (§4a). `connect` is exactly
  `connect_with_runtime` with an empty runtime.

The caller describes the peer once (identity + candidate addresses) and passes its own
`dig_tls::NodeCert` (its mTLS identity) and receives a verified, multiplexed, encrypted connection.
The caller **MUST NOT** be required to choose the traversal method; the crate selects it. The
traversal technique that established the connection **MUST** be reported (`PeerConnection::method`)
for observability but **MUST NOT** change how the caller uses the connection.

## 2. Peer identity + mTLS — delegated to `dig-tls`

The certificate model is owned entirely by the canonical **`dig-tls`** crate (hierarchy L00);
`dig-nat` (L10) **CONSUMES** it and holds NO cert / mTLS-config / binding / `peer_id` code of its own
(the duplicated copies were extracted to dig-tls in 0.6.0, so there is exactly one implementation and
no byte-drift risk). The names below are re-exported from dig-tls for consumer convenience.

- A peer's identity is `peer_id = SHA-256(TLS SubjectPublicKeyInfo DER)`, byte-identical to
  `dig-gossip` and to `dig-tls`. All node-to-node traffic is mutual TLS.
- The local mTLS identity is a `dig_tls::NodeCert`: a per-peer leaf **signed by the shipped public
  DigNetwork CA** (dig-tls ships the CA cert + key; the CA key is intentionally public — a shared
  trust-domain marker, the Chia precedent — so real authentication comes from the `peer_id` pin + the
  BLS binding, never CA-key secrecy). The dialer **MUST** present this `NodeCert` as the mTLS client
  certificate. Certificates are NO LONGER self-signed as of 0.6.0 — a peer that presents a leaf that
  does not chain to the DigNetwork CA **MUST** be rejected. (Migration: consumers regenerate their
  cert as a CA-signed `NodeCert` on adopt.)
- The rustls mutual-auth `ClientConfig`/`ServerConfig` — including the DigNetwork-CA chain check, the
  `peer_id` pin, and the #1204 BLS-binding verification — **MUST** be obtained from
  `dig_tls::client_config` / `dig_tls::server_config`. The dial **MUST** reject the handshake unless
  the remote's derived `peer_id` equals the `peer_id` the caller asked to reach, and the verified
  identity (and any bound BLS pubkey) **MUST** be reported on the returned connection.
- The node's PKCS#8 private key is held by `dig_tls::NodeCert` in a zeroizing container so the
  plaintext key bytes are scrubbed on drop; `NodeCert` is deliberately not `Clone` and is shared
  behind an `Arc`, so it is never copied per dial.

## 2a. Cert BLS-binding — peer_id ↔ BLS G1 identity (NORMATIVE, #1204)

The transport `peer_id` (§2) **MUST** be cryptographically bound to the node/relay **BLS12-381 G1
identity key** (dig-identity slot `0x0010`, EIP-2333 path `m/12381'/8444'/9'/0'`) so the
recipient-seal family (#1075 node↔node, #1199 relay) can seal a payload to a peer's BLS key and know a
misdelivery cannot be opened by the wrong node. This binding is the anti-substitution ROOT: an
attacker **MUST NOT** be able to present a victim's `peer_id` under a BLS key it controls, nor claim a
BLS key it does not control for a given `peer_id`.

### 2a.1 The binding (embedded in the leaf certificate)

- The mTLS leaf certificate (a CA-signed `dig_tls::NodeCert`) **MUST** carry a custom X.509 extension,
  OID `1.3.6.1.4.1.58968.1.1` (a DIG provisional private-use arc; canonical), whose value is:
  `version(1 byte = 0x01) || bls_pub(48 bytes, compressed G1) || bls_sig(96 bytes, G2)`.
- `bls_sig` **MUST** be a BLS G2 signature (Chia AugScheme) by the node/relay BLS secret key over
  `binding_message = "dig-nat/cert-bls-binding/v1" || SPKI_DER`, where `SPKI_DER` is the leaf's own
  `SubjectPublicKeyInfo` DER. Because `peer_id = SHA-256(SPKI_DER)`, signing the SPKI commits the BLS
  key to exactly that `peer_id`.
- The extension is **additive** (§5.1 spirit): it is non-critical and unknown to old verifiers, which
  ignore it. New writers **MAY** bump the `version` byte; verifiers **MUST** dispatch on it and keep
  accepting every version they understand — an unknown version is treated as "no binding this verifier
  understands", never as tampering.

### 2a.2 Verification (on every handshake)

A verifier that checks the binding **MUST**, for the presented leaf: recompute `binding_message` from
the leaf's own SPKI; reject unless the embedded `bls_pub` passes the G1 subgroup / non-identity check;
and reject unless `bls_sig` verifies under `bls_pub` over `binding_message`. A valid binding yields the
verified `bls_pub`, which **MUST** be reported on the connection (`PeerConnection::peer_bls_pub`) for
the sealing layer.

### 2a.3 Rollout policy (LOCAL, never wire-negotiated)

Verification is governed by a **local** `BindingPolicy` — it **MUST NOT** be negotiated from a value
the peer supplies, so a peer cannot request a downgrade:

- **Off** — do not verify the binding (pre-adoption / opt-out).
- **Opportunistic** (the rollout DEFAULT) — verify a binding when present; **reject** a
  present-but-INVALID one; **accept** an ABSENT one (tolerates legacy un-bound peers).
- **Required** — a valid binding is mandatory; **reject** both ABSENT and INVALID.

A downgrade that strips the extension **MUST** be rejected under **Required** (an absent binding fails
closed), so stripping the extension can never silently disable a required-mode session.

### 2a.4 Relay descriptor (#1199) — self-authenticating discovery record

A relay/peer discovery record (`RelayDescriptor`: `peer_id_spki_hash`, `bls_pub`, `addresses`,
`network_id`, optional `did`, `signature`) learned BEFORE a direct handshake (PEX/DHT/relay
registration, or relay store-and-forward) **MUST** be verified before it is trusted as a seal target:
the `bls_pub` **MUST** pass the G1 subgroup check; the `signature` (BLS G2 over the canonical
length-prefixed descriptor bytes behind `"dig-nat/relay-descriptor/v1"`) **MUST** verify under
`bls_pub`; on a live dial the `peer_id_spki_hash` **MUST** equal `SHA-256(presented SPKI)`; and where a
`did` and a resolver are available, a resolvable `did` **MUST** resolve to the same `bls_pub` (an
unresolvable DID is tolerated — nodes/relays are normally DID-less). On a direct connection the cert
binding (§2a.1) is authoritative and **MUST** be re-verified; the descriptor is only a pre-dial hint.

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
- **Reflexive discovery is happy-eyeballs across BOTH families (NORMATIVE, CLAUDE.md §5.2).**
  `stun::discover_reflexive_address(stun_servers, local, timeout)` races a STUN Binding transaction
  over the `local ∩ stun_servers` family intersection via `dig_ip::connect` — **IPv6-first with IPv4
  FALLBACK**. Callers MUST pass STUN endpoints across BOTH families (e.g. every A + AAAA record of the
  relay's `host:3478`) and MUST NOT pre-collapse `to_socket_addrs()` to a single family. The reflexive
  address is **NEVER** nulled just because the IPv6 STUN server was unreachable: an IPv4-only host (or
  a dual-stack host whose IPv6 STUN server does not answer) falls back to the reachable IPv4 STUN
  server and returns its reflexive address. Returns `None` only when no family's STUN server answered
  within `timeout` (or the candidate list is empty). This is the canonical fix for the #1062 gap where
  an IPv4-only EC2 host stranded on the IPv6 STUN address (`reflexive_addr:null`) and advertised only
  its private VPC IP; per the dig-ip charter, NO consumer hand-rolls a family sort or happy-eyeballs
  racer — this function is the single front door.
- **Reflexive-address usability guard (NORMATIVE, defense-in-depth).** A parsed reflexive address is
  accepted as a candidate only if it is a plausible dial target. `query_reflexive_address` REJECTS
  (surfacing `StunError::NoMappedAddress`, which `discover_reflexive_address` treats as a candidate
  failure and falls through) any reflexive address that is, across BOTH families: unspecified
  (`0.0.0.0`/`::`), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`),
  multicast (`224.0.0.0/4`, `ff00::/8`), a documentation range (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`, `2001:db8::/32`), the IPv4 limited broadcast (`255.255.255.255`), the IPv4
  "this-network" block (`0.0.0.0/8`), the 6to4 relay anycast prefix (`192.88.99.0/24`), the
  benchmarking range (`198.18.0.0/15`), the reserved / class-E block (`240.0.0.0/4`), or has
  `port == 0`. **IPv4-mapped (`::ffff:a.b.c.d`) and deprecated IPv4-compatible (`::a.b.c.d`) IPv6
  forms are folded to their IPv4 address BEFORE classification** (`Ipv6Addr::to_ipv4`, which folds
  both the mapped and the deprecated compatible forms), so a
  STUN server — which fully controls the 16 decoded address bytes — cannot smuggle a rejected IPv4
  range (e.g. `::ffff:127.0.0.1`) past the IPv6 arm; the rejection therefore holds identically whether
  a reserved address arrives as native IPv4 or as a mapped/compat IPv6. This is a defense against a
  malicious or misconfigured STUN server (the relay runs one) returning a bogus reflexive address a
  consumer would then advertise. It is **NOT** a blanket `is_global` filter: PRIVATE (RFC 1918), CGNAT
  (`100.64.0.0/10`), and IPv6 ULA (`fc00::/7`) addresses are ACCEPTED — they are legitimate reflexive
  addresses on a LAN or behind carrier-grade NAT (a mapped private form such as `::ffff:10.0.0.1` is
  likewise accepted), and rejecting them would break LAN/test-network reflexive discovery (including
  the #1062 EC2 e2e). The pure parser `parse_binding_response` does NOT apply this guard; callers
  wanting a usable candidate use `query_reflexive_address`.
- **Dialable candidate vs. public-IP-only (NORMATIVE).** `query_reflexive_address(socket, …)` returns
  a **DIALABLE** server-reflexive candidate: it learns the reflexive `ip:port` mapping of the caller's
  OWN listen `socket`, so the port is the real external NAT binding a remote peer can dial. It is the
  API connectivity-core (dig-node) uses to obtain an advertisable candidate.
  `discover_reflexive_address` instead STUNs each candidate over a THROWAWAY ephemeral UDP socket, so
  its returned IP is the stable public IP but the PORT is that throwaway socket's binding — **not
  reliably dialable** under most NAT types. Use `discover_reflexive_address` to learn the public IP;
  use `query_reflexive_address` for a dialable candidate.
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

## 4a. Full-ladder auto-composition + the runtime carrier (NORMATIVE)

`connect_with_runtime` **MUST** auto-compose the traversal ladder from two inputs kept strictly
separate: the DATA config (`NatConfig`, `Clone + Debug`) and the LIVE handles (`NatRuntime`, which
**MUST NOT** be `Clone` or `Debug` — it carries `Arc<dyn …>` trait objects + live sockets).

- A tier is composed **iff** it is enabled in `config.enabled_methods` AND its runtime inputs are
  present in `runtime`. A tier missing its inputs **MUST** be omitted silently — the crate **MUST
  NOT** attempt a tier it cannot actually run (no phantom or silently-broken dial). Per-tier inputs:
  - **Direct** — none (always composable).
  - **UPnP** — `local_port` (+ optional injected `IgdGateway`; else the real SSDP gateway).
  - **NAT-PMP** — `local_port` + `gateway_v4`.
  - **PCP** — `local_port` + `gateway_v4` + `client_ip`.
  - **HolePunch** — `hole_punch` coordinator + `my_external_addr` (STUN reflexive).
  - **Relayed** — a `relayed` `RelayedDialer` handle.
- If no tier is composable, `connect`/`connect_with_runtime` **MUST** return `NoMethodsEnabled`.
- Every composed tier — INCLUDING the relayed one — **MUST** run the identical `dig-tls` mTLS
  (CA-chain check + `peer_id` pin + #1204 BLS binding). A relayed or hole-punched connection **MUST
  NOT** be weaker than a direct one.

## 4b. Fast-connect — first-usable transport + live relayed→direct promotion (NORMATIVE)

`connect_fast(peer, node, config, runtime) -> FastPeerConnection` is an ADDITIVE alternate entry point
alongside `connect`/`connect_with_runtime` (which are UNCHANGED). Where `connect` returns ONE connection
over the first tier that lands, `connect_fast` returns the first-USABLE transport immediately AND
promotes to a better (direct) one in the background when it lands and proves itself — without
interrupting in-flight work.

- **Start:** `connect_fast` **MUST** launch, concurrently, (a) a relayed dial over the held reservation
  (iff `runtime` wired a `RelayedDialer`) and (b) the DIRECT traversal ladder race — the full ladder
  MINUS the relayed tier (`Direct → Upnp → NatPmp → Pcp → HolePunch`, via `connect_with_strategy`). It
  **MUST** return a `FastPeerConnection` as soon as EITHER lands (first-usable-path). A NAT'd peer whose
  relay lands first is returned relayed-active with the direct ladder still racing; a public peer whose
  direct dial wins outright is returned direct-active and the relay is never used. It returns
  `AllMethodsFailed` iff both attempts fail (`NoMethodsEnabled` if neither tier could be composed).
- **No stream migration (route-new + drain-old):** a live logical stream **MUST NOT** migrate transports.
  The active transport is an atomically-swappable slot; `open_stream` loads the CURRENT slot and opens
  there, so only NEW streams route to a promoted transport. An in-flight stream **MUST** complete on the
  transport it started on. This is correct because the peer API is a factory of short-lived,
  request-scoped streams with no cross-stream ordering contract — so no read-quiesce/flush is needed and
  there is no loss/reorder/duplication (the byte path is never swapped under a live `yamux` session,
  which is transport-bound).
- **Promotion gate (conservative — SECURITY-CRITICAL):** a direct path **MUST** be promoted only when ALL
  hold: (1) the direct-tier mTLS handshake completed with the `peer_id` pin verified; (2) IDENTITY
  EQUALITY — the direct connection's `peer_id` AND its #1204 BLS pubkey EQUAL the relayed transport's
  (the invariant that makes swapping transports "to the same peer" safe); (3) ONE successful application
  round-trip over the direct session (an empty `query_availability(vec![])` probe), proving real
  bidirectional mux traffic (a NAT mapping can complete TLS then blackhole). A path that fails ANY gate
  **MUST** be refused and the connection stays relayed. Promotion **MUST NOT** occur on
  handshake-completion alone.
- **Promote + drain:** on a passed gate the active slot is swapped to the direct transport atomically
  (`current_method()` flips to `Direct`; subscribers are notified). The swapped-out relayed slot **MUST**
  be held until its in-flight streams finish OR a bounded grace cap (`NatConfig::fast_connect_grace`,
  default 5s) elapses, then dropped. Dropping the relayed slot releases ONLY the per-peer `RelayTunnel`;
  it **MUST NOT** tear down the node's persistent relay reservation (§5a).
- **Failure modes:** (a) direct never lands → stay relayed indefinitely (usable), reservation intact;
  (b) a promoted direct transport that dies → fall back by re-establishing a relayed session (the
  reservation is still held), flipping `current_method()` back to `Relayed`; (c) a relay drop while still
  relayed → the existing reservation reconnect/backoff (§5a) applies.
- **mTLS + NC-1:** the session does not survive the swap and need not — `peer_id = SHA-256(TLS SPKI DER)`
  is transport-bound and the direct path runs its OWN mTLS to the SAME `peer_id`; identity-equality
  (gate 2) is the invariant. NC-1 payload sealing sits ABOVE dig-nat keyed to the peer's BLS pubkey
  (identical across transports) and is unaffected by a transport swap. This introduces NO wire change
  (same RLY-002 relayed wire, same mTLS, same `peer_id` derivation).

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
- Opening the reservation WebSocket **MUST** be IPv6-first with graceful IPv4 fallback (§3.3, §5.2): the
  endpoint host is resolved to its A + AAAA candidates and the TCP connect is raced via `dig_ip::connect`
  (RFC 8305 happy eyeballs), then the WS handshake runs over the winning socket (TLS-over-that-stream for
  `wss://`). It **MUST NOT** use a sequential, single-family resolve-and-connect.
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

### 5b.1 Relayed dial — mTLS over the relay tunnel (NORMATIVE)

The relayed tier is composed by `connect_with_runtime` from a `RelayedDialer` handle (implemented by
`ReservationRelayedTransport`). Dialing it **MUST** carry the SAME mTLS as a direct dial:

- `RelayedDialMethod::attempt` gates on `RelayedDialer::is_ready()` (a held reservation) and yields the
  relay endpoint as the observability dial address. When not ready it **MUST** fail cleanly (the
  strategy records the failure), never produce a doomed dial.
- The dialer **MUST** open the byte tunnel via `RelayedDialer::open_dial_tunnel(peer_id_hex,
  network_id)`, wrap the resulting `RelayTunnel` in a byte-stream adapter (`RelayTunnelStream`,
  tokio `AsyncRead + AsyncWrite`), and run the IDENTICAL `dig_tls::client_config` handshake +
  `yamux` session over it — so a relayed `PeerConnection` presents the same CA chain, `peer_id` pin,
  and #1204 BLS binding as a direct one.
- The relay routes tunnels by `peer_id`. A relay that substitutes a DIFFERENT peer for the pinned one
  (a redirect attack) **MUST** be rejected by the mTLS `peer_id` pin — identity is proven by the
  certificate, never by the relay's routing. The relay sees only TLS records (ciphertext); §5.4
  recipient-sealing remains a layer ABOVE this transport.
- `RelayTunnelStream` maps each write to one RLY-002 frame (≤ `MAX_RELAY_PAYLOAD`) and each read to
  one inbound payload (buffering the remainder across reads); a dropped reservation surfaces as a
  clean stream EOF that fails the handshake.

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
  endpoint (default `dig_constants::DIG_RELAY_URL`, `DIG_RELAY_URL=off` opt-out honored), the STUN
  server (default derived from the relay host on port 3478), and the peer cert-`binding_policy`
  (default `Opportunistic`; `connect` applies it to the peer's #1204 cert binding).
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
dialer::MtlsDialer::new(Arc<dig_tls::NodeCert>).with_happy_eyeballs(cfg).with_local_stack(dig_ip::LocalStack)
dialer::MtlsDialer::with_binding_policy(BindingPolicy)      // cert-binding stance (default Opportunistic)

connect(peer, &Arc<dig_tls::NodeCert>, config) -> Result<PeerConnection, NatError>
connect_with_runtime(peer, node, config, &NatRuntime) -> Result<PeerConnection, NatError>
config.binding_policy: BindingPolicy                        // peer cert-binding stance (default Opportunistic)
config.fast_connect_grace: Duration                         // §4b post-promotion drain window (default 5s)
PeerConnection.peer_bls_pub: Option<[u8; 48]>              // verified peer BLS G1 key (§2a)

// Fast-connect (§4b) — additive first-usable + live relayed→direct promotion:
connect_fast(peer, node, config, &NatRuntime) -> Result<FastPeerConnection, NatError>
FastPeerConnection::open_stream() / open_range_stream(&RangeRequest) -> io::Result<FastPeerStream>  // &self
FastPeerConnection::query_availability(items) -> io::Result<AvailabilityResponse>                   // &self
FastPeerConnection::current_method() -> TraversalKind      // authoritative active tier (flips on promote/fallback)
FastPeerConnection::subscribe() -> watch::Receiver<TraversalKind>  // active-transport change notifications
FastPeerConnection::peer_id() / remote_addr()

// Certificate / mTLS / identity model — RE-EXPORTED from dig-tls (dig-nat owns no copy):
dig_nat::NodeCert                                           // = dig_tls::NodeCert (CA-signed leaf + key + peer_id)
dig_nat::PeerId, peer_id_from_tls_spki_der, peer_id_from_leaf_cert_der  // = dig_tls
dig_nat::BindingPolicy { Off, Opportunistic (default), Required }       // = dig_tls
dig_nat::verify_binding_from_leaf_cert(cert_der) -> BindingOutcome      // = dig_tls (Bound{bls_pub}/Absent/Invalid)
dig_nat::{CapturedPeerId, CapturedBlsPub}                   // = dig_tls::verify handles

// Relay descriptor (§2a.4, #1199)
relay_descriptor::RelayDescriptor { peer_id_spki_hash, bls_pub, addresses, network_id, did, signature }
relay_descriptor::verify_relay_descriptor(&desc, presented_spki_der, did_resolver) -> Result<(), RelayDescriptorError>
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
- Identity: `peer_id = SHA-256(SPKI DER)` matches `dig-gossip` (`tests/identity.rs` conformance).
- Cross-crate BLS conformance (`tests/identity.rs`, the extraction's keystone): dig-tls's BLS G1/G2
  work (via its own `chia-bls`/`blst`) and dig-identity's **MUST** agree byte-for-byte — the same
  secret scalar derives the same 48-byte G1 pubkey in both, signatures cross-verify in both
  directions, and the pubkey dig-tls binds into a real `NodeCert` (recovered via
  `verify_binding_from_leaf_cert`) equals dig-identity's derived pubkey. This is the check dig-tls's
  `bls.rs` defers to the integration level; it FAILS if a future `chia-bls`/`blst` bump ever diverges.
- Cert BLS-binding (§2a, verified via re-exported `dig_tls` in `tests/identity.rs` + exhaustively in
  dig-tls's own suite): a CA-signed `NodeCert` verifies to `Bound{bls_pub}`; a substituted BLS pubkey,
  a binding replayed onto a different SPKI, a bad G1 point, and a malformed/unknown-version extension
  all verify to `Invalid`; an un-bound cert is `Absent`. Over a real `MtlsDialer` handshake
  (`tests/dialer.rs`): the dial verifies the peer's `peer_id`, rejects a mismatch, and muxes. Relay
  descriptors reject a tampered signature, a `peer_id_spki_hash` mismatch, a substituted
  pubkey, a bad G1 point, and a DID resolving to a different key; an unresolvable DID is tolerated.
- STUN/PCP anti-spoof: transaction id / MAP nonce samples show CSPRNG-level variation across their
  full byte range (not a wall-clock-derived pattern); `query_reflexive_address` and the PCP
  `transact` accept a response only from the address the request was sent to, looping past a
  mismatched-source datagram rather than failing the transaction outright.
