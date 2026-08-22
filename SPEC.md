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
- The local mTLS identity is a `dig_tls::NodeCert` (a per-peer leaf carrying the #1204 BLS-G1
  binding), which the dialer **MUST** present as the mTLS client certificate.
- **The auto-dialer authenticates peers by SPKI-pinned mTLS, NOT by a DigNetwork-CA chain (#1422).**
  Real authentication comes from three checks, none of which requires the peer's leaf to chain to any
  CA: (1) `peer_id = SHA-256(TLS SPKI DER)` **MUST** equal the `peer_id` the caller asked to reach
  (the pin); (2) rustls proof-of-possession of the leaf's private key; (3) the #1204 BLS-binding
  verification. A **self-signed** peer leaf **MUST** be accepted (live §5.2 DIG peers present
  self-signed / chia-ssl leaves; the DIG-CA-everywhere migration #1378 is deferred), while a leaf
  whose derived `peer_id` does not match the pinned target **MUST** be rejected.
- The rustls mutual-auth outbound config — the SPKI-pinned `peer_id` verification, rustls
  proof-of-possession, and the #1204 BLS-binding verification — **MUST** be obtained from
  `dig_tls::client_config_spki_pinned` (the dial passes `Some(peer_id)`, never `None`, so the specific
  peer is always authenticated). The verified identity (and any bound BLS pubkey) **MUST** be reported
  on the returned connection.
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

- **G1** — when the local∩peer family intersection is NON-EMPTY, the dial MUST NOT attempt an address
  of a family the LOCAL host lacks (a host with a detected IPv4 route and a dual-stack peer never
  emits an IPv6 SYN).
- **G2** — the dial NEVER attempts an address of a family the PEER lacks.
- **IPv6-first preference** — a viable IPv6 candidate wins even if a hedged IPv4 attempt connects
  sooner; IPv4 wins only when IPv6 genuinely fails/stalls.
- **Fail OPEN on an empty intersection** — `LocalStack` detection is affirmative-only: a successful
  probe proves a family is routable, but a failed probe proves only the absence of a DEFAULT route,
  not that the family is unreachable (overlay / split-tunnel / container networks, and the pre-route
  window at boot, all produce false negatives). So the intersection is an OPTIMIZATION, not a veto:
  when it is empty and the peer HAS candidates, the dial MUST attempt ALL of the peer's candidates
  IPv6-first rather than stranding a peer the negative detection cannot honestly rule out.
- **Clean nothing-to-dial outcome** — `dig_ip::ConnectError::NoCommonFamily` (surfaced as a
  `MethodError` whose reason contains "no common address family") is returned ONLY when the peer
  offers no candidate at all; NO dial is attempted, so there is no doomed, hanging SYN.
- The per-attempt timeout + inter-attempt stagger are configurable (`HappyEyeballsConfig`, mapped to
  `dig_ip::DialConfig`) so the racing is deterministically testable.
- The established connection's reported remote address (`PeerConnection::remote_addr`) reflects the
  candidate (and therefore family) actually used.

### 3.3a Self-dial refusal — the transport chokepoint (NORMATIVE, #1590 / #836)

`MtlsDialer::dial` is the single method EVERY peer dial funnels through (Direct, every port-mapping
tier, hole-punch, AND relayed). It **MUST**, before racing any candidate or opening any tunnel, refuse
a dial whose `PeerTarget::peer_id` equals the local node's own identity (`NodeCert::peer_id()`),
returning a `MethodError` whose reason contains `"self-dial"`, on **ALL** kinds — not only the relayed
tier. Keying the refusal on the verified `peer_id` (not on an address, which can collide via a
server-reflexive candidate) makes it deterministic and independent of candidate ordering: a provider
record for our own node — or one that carries our own reflexive address — can never cause the fetch
transport to dial itself, so the download orchestrator falls through to a real holder provider. This
subsumes and complements the relay-layer relayed self-dial refusal (§4c, #1536), which still applies as
defense-in-depth for a circuit opened by other paths.

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
  (SPKI-pinned `peer_id` verification + rustls proof-of-possession + #1204 BLS binding, §2). A relayed
  or hole-punched connection **MUST NOT** be weaker than a direct one.

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
  bidirectional mux traffic (a NAT mapping can complete TLS then blackhole). The gate-3 probe **MUST**
  succeed within `NatConfig::per_method_timeout`; a probe that errors OR times out is a gate FAILURE that
  fails closed (no promotion, stay relayed), so a post-TLS blackhole cannot hang promotion indefinitely.
  A path that fails ANY gate **MUST** be refused and the connection stays relayed. Promotion **MUST NOT**
  occur on handshake-completion alone.
- **Promote + drain:** on a passed gate the active slot is swapped to the direct transport atomically
  (`current_method()` flips to `Direct`; subscribers are notified). The swapped-out relayed slot **MUST**
  be held until its in-flight streams finish OR a bounded grace cap (`NatConfig::fast_connect_grace`,
  default 5s) elapses, then dropped. Dropping the relayed slot releases ONLY the per-peer `RelayTunnel`;
  it **MUST NOT** tear down the node's persistent relay reservation (§5a).
- **Failure modes:** (a) direct never lands → stay relayed indefinitely (usable), reservation intact;
  (b) a promoted direct transport that dies → fall back by re-establishing a relayed session (the
  reservation is still held), flipping `current_method()` back to `Relayed`; a lone death re-dials
  immediately, but a FLAPPING transport (re-dial succeeds then instantly dies) is paced by a
  capped-exponential backoff that resets once a re-established session is held stably, so a hostile/broken
  peer cannot drive an unbounded re-dial busy-loop; (c) a relay drop while still
  relayed → the existing reservation reconnect/backoff (§5a) applies.
- **mTLS + NC-1:** the session does not survive the swap and need not — `peer_id = SHA-256(TLS SPKI DER)`
  is transport-bound and the direct path runs its OWN mTLS to the SAME `peer_id`; identity-equality
  (gate 2) is the invariant. NC-1 payload sealing sits ABOVE dig-nat keyed to the peer's BLS pubkey
  (identical across transports) and is unaffected by a transport swap. This introduces NO wire change
  (same RLY-002 relayed wire, same mTLS, same `peer_id` derivation).

## 4c. Relayed responder — role negotiation on a relay circuit (NORMATIVE)

A relay circuit (tier-6, RLY-002) is a byte tunnel between two peers; the mTLS handshake carried over
it **MUST** have exactly ONE client end and ONE server end. The two ends negotiate roles by who
INITIATED:

- **Initiator = mTLS client.** The peer that opens the tunnel (`RelayStatus::open_tunnel` via the
  `RelayedDialer` → `MtlsDialer::dial`) runs `PeerSession::client`.
- **Reservation-holder that RECEIVES the introduced circuit = mTLS server.** When a live reservation
  receives an inbound RLY-002 `relay_message` from a peer it has NO open outbound tunnel to, that frame
  is an INTRODUCED circuit (a peer dialing this node over the relay). If — and only if — the holder has
  enabled the responder path (`RelayStatus::enable_accept`), it **MUST** register a server-role
  `RelayTunnel` for that peer, deliver the opening frame into it, and surface the tunnel for a consumer
  to accept via `RelayAcceptor::accept`, which runs `PeerSession::server` behind a `TlsAcceptor`
  (`dig_tls::server_config_spki_pinned`). The accepted `PeerConnection` reports the connecting peer's
  VERIFIED `peer_id` + #1204 BLS binding — identical authentication to a direct inbound connection.
- **ONLY a dialer's opening ClientHello may open an introduced circuit (NORMATIVE).** A frame from a
  peer with no registered tunnel is an introduced circuit **if and only if** it begins with a TLS
  handshake record whose first message is a ClientHello (content-type `0x16` at byte 0, handshake type
  `0x01` at byte 5). Any other frame — a ServerHello, an application record, a record too short to
  classify, or arbitrary bytes — **MUST** be dropped without registering a tunnel and without surfacing
  an accept. The mTLS role of a relay circuit therefore derives from the circuit's DIRECTION (whoever
  sent the opening handshake is the client; its counterpart is the server) and is decided at exactly ONE
  place. A frame that merely arrives on a key with no circuit is not a new circuit: it belongs to one
  that no longer exists here (notably a peer's records still in flight after `fast_connect` released the
  per-peer tunnel on a relayed→direct promotion, §4b) or to one that was never this node's. Admitting
  such a frame stands an mTLS SERVER up against a peer that is itself a server — a handshake that cannot
  complete (`got ServerHello when expecting ClientHello` / `UnexpectedMessage`) — and lets a single
  arbitrary byte cost a tunnel slot plus an accept task.
- **Accept is opt-in; unknown-peer frames are otherwise DROPPED.** When the responder path is NOT
  enabled, an inbound frame from a peer with no open tunnel **MUST** be dropped (the untrusted-relay
  default). This preserves the pre-existing flood defense for consumers that only dial.
- **Bounded (untrusted-relay flood defense).** The accept path **MUST** refuse to create a new inbound
  circuit once the registered-tunnel count reaches `MAX_RELAY_TUNNELS`, and the accept channel is
  bounded — a full channel drops the newest introduced circuit rather than queueing unboundedly. A
  hostile relay flooding fabricated `from` ids therefore cannot exhaust memory or spawn unbounded
  accept tasks.
- **GLARE — simultaneous mutual dial (NORMATIVE).** Two peers that fall to the relay tier and dial EACH
  OTHER at the same time both open a client-role tunnel, so each side's ClientHello arrives on a tunnel
  where it is ALSO the client. This **MUST** be resolved deterministically so exactly one side is the
  server: **the peer with the numerically-lower `peer_id` (lexicographic compare of the hex
  `SHA-256(SPKI)` id) becomes the mTLS SERVER.** Both ends compute the same rule from the two ids, so a
  crossed pair converges to one-client-one-server under ANY frame ordering with NO retry loop. When a
  ClientHello (a TLS handshake record: content-type `0x16`, handshake type `0x01`) arrives on a
  client-role tunnel: the lower-id side **MUST** drop its outbound client tunnel and accept the peer's
  circuit as server (via the responder path above); the higher-id side **MUST** retain its client role
  and ignore the peer's competing ClientHello (the peer yields and answers with a ServerHello). A
  ServerHello / application record on a client-role tunnel is the expected response and is routed
  normally — it is NOT glare. Each tunnel registration carries a monotonic id so a yielded client
  tunnel's teardown never deregisters the replacement server tunnel under the same peer key.
- **At most ONE circuit per peer key — non-clobber (NORMATIVE).** A node **MUST NOT** hold two circuits
  (a client dial AND a server accept) to the same peer simultaneously. Opening a relayed dial to a peer
  a live circuit already exists for **MUST** be refused (the existing circuit IS the connection), and
  the introduced-circuit accept path **MUST NOT** overwrite an existing entry. This covers the
  TIMING-ordered glare variant — a peer's ClientHello arriving BEFORE our own dial to it registers: we
  accept it as a server, and our subsequent dial to that peer is refused rather than clobbering the
  server circuit into a conflicting second mTLS session. The per-frame role LOOKUP + any same-frame
  yield (client-tunnel removal) are performed under a single `tunnels`-lock acquisition; the subsequent
  server registration re-acquires the lock and re-checks for an existing entry (the non-clobber guard),
  so a dial that races in between the two regions cannot produce a conflicting second circuit — the
  registration is abandoned rather than clobbering.
- **Self / collision guard (NORMATIVE).** A relayed dial whose target equals the local `peer_id`, and an
  inbound frame stamped with the local `peer_id` (a theoretical SPKI collision, or a hostile relay
  reflecting our own id), **MUST** be rejected — such a pair has no lower/higher end for the tie-break
  and would otherwise hang with no server.
- **Injected-ClientHello availability caveat (SECURITY).** Because an introduced/glare ClientHello is an
  opaque relayed frame, an untrusted relay CAN inject a fabricated ClientHello on a lower-id node's
  client tunnel to force it to yield its outbound dial to a server accept that no real peer completes —
  a selective relayed-dial denial (both legs fail). This never bypasses mTLS identity (the injected
  circuit authenticates nothing), but it is an availability lever inherent to an untrusted TURN relay.
  The dial is NOT permanently lost: once the never-completing server circuit is dropped, the peer key
  frees and a fresh dial may be attempted. Consumers **SHOULD** bound the server-accept handshake with a
  timeout and re-attempt the outbound dial on failure.

Without a responder path, both circuit ends acted as TLS client and the handshake deadlocked; without
the deterministic role tie-break + non-clobber, a simultaneous or timing-ordered mutual dial
re-manifested the same deadlock or spawned two conflicting sessions to one peer
(`got ClientHello when expecting ServerHello`, #1536).

## 5. Transport surface

- Whatever tier establishes the link, the result is one mTLS byte stream wrapped in `yamux`
  multiplexing (`PeerSession`). The caller opens many concurrent logical streams
  (`PeerConnection::open_stream`), byte-range streams (`PeerConnection::open_range_stream`,
  `dig.fetchRange`), and availability pre-checks (`PeerConnection::query_availability`,
  `dig.getAvailability`). Field names + wire shapes conform to the L7 peer-network spec.
- A `dig.fetchRange` stream carries a `RangeRequest` preamble followed by `RangeFrame`s, each a
  `u32`-BE length-prefixed JSON body. A frame's `bytes` field **MUST** be the **base64** encoding of
  that window's ciphertext — the canonical `dig.fetchRange` frame wire
  (`dig_rpc_protocol::types::RangeFrame`), identical to what the DIG node's peer serve path emits. A
  reader **MUST** also accept a JSON byte ARRAY for `bytes` (the pre-0.11.2 dig-nat encoding) so a
  mixed-version peer still decodes.

### 5.1 Frame size limits (NORMATIVE)

Five constants bound every length-prefixed frame on a peer stream. All are exported at the crate root
(`dig_nat::MAX_FRAMED_BODY`, `dig_nat::MAX_RANGE_FRAME_PAYLOAD`, `dig_nat::MAX_INCLUSION_PROOF_B64`,
`dig_nat::MAX_CHUNK_LENS_PER_FRAME`, `dig_nat::MAX_FIRST_FRAME_CHUNK_LENS`) and are **shared
byte-identical wire values**: every implementation of DIG peer framing **MUST** use these exact
numbers. Each is readable through its documented path — a bound a consumer cannot read is prose, not a
contract.

| constant | value | bounds |
|---|---|---|
| `MAX_FRAMED_BODY` | `65536` (64 KiB) | the JSON body of ANY framed message, after the `u32`-BE prefix |
| `MAX_RANGE_FRAME_PAYLOAD` | `32768` (32 KiB) | the raw `RangeFrame.bytes` length a single frame may carry |
| `MAX_INCLUSION_PROOF_B64` | `4096` | the base64 `RangeFrame.inclusion_proof` length — a 96-level merkle path |
| `MAX_CHUNK_LENS_PER_FRAME` | `2048` | `chunk_lens` entries a SENDER puts on one frame before it pages the prologue |
| `MAX_FIRST_FRAME_CHUNK_LENS` | `2486` | `chunk_lens` entries GUARANTEED to fit on one frame with every co-occurring field at ITS maximum |

- A receiver **MUST** reject a length prefix greater than `MAX_FRAMED_BODY` with an `InvalidData`
  error, without allocating the announced length.
- **A decode failure on a peer-supplied frame MUST NOT quote the frame back.** The `InvalidData`
  error a receiver raises for an unparseable body **MUST** state the failure *category* (syntax /
  data / EOF) and its line and column, and **MUST NOT** contain any of the received bytes.
  `serde_json`'s native message embeds the offending value verbatim, so relaying it would let a
  sender choose text that appears in the receiver's own diagnostics — both an injection channel and
  an echo of attacker-chosen content. `SafeText::describing_json_error` is the conforming rendering.
- **A conforming sender MUST NOT emit a frame a conforming receiver is required to reject.** This is
  the governing invariant, and it is symmetric by construction: encoding **MUST** fail, at the sender,
  when the serialized body would exceed `MAX_FRAMED_BODY`, when `RangeFrame.bytes` exceeds
  `MAX_RANGE_FRAME_PAYLOAD`, or when `RangeFrame.inclusion_proof` exceeds `MAX_INCLUSION_PROOF_B64`.
  It **MUST NOT** silently produce such a frame. Each refusal **MUST** name the constant it enforces:
  `MAX_INCLUSION_PROOF_B64` is *premise 2* of `MAX_FIRST_FRAME_CHUNK_LENS`, and a premise only a test
  believes is not a bound. A resource whose proof exceeds the cap has NO conforming range stream at
  all; the holder **MUST** answer a structured `RANGE_METADATA_UNREPRESENTABLE` error and stream no
  frames, rather than emit metadata a reader cannot verify.
- `MAX_RANGE_FRAME_PAYLOAD` is deliberately **conservative, not exact-fit**. `bytes` travels base64
  (4 bytes out per 3 in), so 32 KiB of payload occupies 43,692 body bytes, leaving 21,844 bytes of the
  64 KiB body for the JSON keys and the first frame's verification metadata — `root`, `total_length`,
  `chunk_index`, the base64 `inclusion_proof`, and the whole resource's `chunk_lens` array, whose size
  scales with the RESOURCE rather than the frame. An implementation **MUST NOT** raise the payload
  ceiling toward the base64-only bound of ~48 KiB: the residual allowance is what keeps a first frame
  with a chunk table decodable.
- That allowance is finite, and `MAX_FIRST_FRAME_CHUNK_LENS` is where it ends: **2,486** entries.
  A conforming implementation **MUST** derive that figure against **every** co-occurring maximum
  simultaneously, and **MUST** state each one wherever the figure is published:
  1. the payload at `MAX_RANGE_FRAME_PAYLOAD` (32,768 B raw, 43,692 B base64);
  2. the `inclusion_proof` at `MAX_INCLUSION_PROOF_B64` = 4,096 B (published AND encoder-enforced);
  3. every `chunk_lens` entry at its widest legal decimal form — a chunk may be 256 KiB, so six digits;
  4. every `u64` scalar at max width (20 digits): `offset`, `length`, `total_length`, `chunk_index`,
     `chunk_count`, and `chunk_lens_offset`. Deliberately stricter than the protocol-tight widths —
     a bound that depends on a scalar happening to be small carries a fifth implicit premise.

  Measured on the 0.13.0 field set — the real struct, including `chunk_count` and `chunk_lens_offset` —
  a frame at exactly 2,486 entries with all four maxima held simultaneously serializes to **65,536 B**:
  the cap exactly, with ZERO slack. One entry more is 65,543 B. The figure was pre-derived against these
  fields before they landed and is therefore UNCHANGED by 0.13.0. About 155 MiB of resource at the
  canonical 64 KiB FastCDC target chunk size, about 38 MiB at the 16 KiB minimum.

  Because the slack is zero, **any** further field added to `RangeFrame` moves this number, and the
  both-sides pin below is the only thing that will say so. That is why the pin is normative rather than
  advisory.

  A figure derived with any one of those maxima left implicit comes out **too generous**, which is the
  unsafe direction — it licenses a conforming sender to emit a frame the receiver must reject, the exact
  defect §5.1 exists to close. Such a figure **MUST** be treated as a defect, not a rounding difference.
- `MAX_FIRST_FRAME_CHUNK_LENS` is **not** the sender's paging threshold and **MUST NOT** be used as
  one. `MAX_CHUNK_LENS_PER_FRAME` = 2,048 is where a serve path begins paging the prologue — a full
  page at the same maxima measures **62,470 B**, leaving **3,066 B** (438 entries) of margin below the
  body cap — while `MAX_FIRST_FRAME_CHUNK_LENS` is the hard arithmetic ceiling. Two numbers doing two
  different jobs; the gap between them is the only margin the budget has, and an implementation
  **MUST NOT** collapse one into the other.

Testability — the bound **MUST** be pinned from BOTH sides, because a bound checked only from below can
only confirm itself: a payload of `MAX_RANGE_FRAME_PAYLOAD + 1` **MUST** fail to encode; a frame at
exactly `MAX_FIRST_FRAME_CHUNK_LENS` entries with **all four maxima above held simultaneously** **MUST**
fit within `MAX_FRAMED_BODY` and **MUST** decode unchanged; and one entry beyond that **MUST NOT** fit.
`MAX_INCLUSION_PROOF_B64` **MUST** be pinned the same way — a proof of exactly the cap encodes, one byte
more is refused — and a body of exactly `MAX_FRAMED_BODY` **MUST** encode while one byte more **MUST**
be refused, since the caps are inclusive.
Every co-occurring field **MUST** be at its own published cap in those fixtures — a fixture that
quietly shrinks one field (a narrow proof, a small scalar) measures a narrower frame than the protocol
permits and will certify a too-generous bound. The over-cap proof fixture **MUST** use an entry count
comfortably BELOW the bound, so that the refusal can only be attributed to the proof.

The bounds **MUST** be derived by SERIALIZING the real struct. Four historical derivations of
`MAX_FIRST_FRAME_CHUNK_LENS` were wrong, every one of them arithmetic in prose, and every one wrong in
the too-generous direction.

#### 5.1.1 Splitting a range into frames (NORMATIVE)

- A serving peer **MUST** split a requested range into frames of at most `MAX_RANGE_FRAME_PAYLOAD` raw
  `bytes` each. A per-request *window* — how much one `RangeRequest` may ask for — is a separate and
  larger quantity, and is **NOT** a valid per-frame size.
- Range-frame metadata **splits by whether it scales with the resource**:
  - the **fixed-size identity set** — `root`, `total_length`, `chunk_count` (plus `chunk_index` where the
    window is chunk-aligned) — rides **every** frame. It costs a bounded number of bytes and it is what
    lets a reader reject a wrong-generation or wrong-layout holder the moment a frame arrives.
  - the **resource-scaling set** — `chunk_lens` and `inclusion_proof`, whose size is a function of the
    RESOURCE rather than of the frame — is sent **once per range stream**, on the first frame or across a
    paged prologue, located by `chunk_lens_offset`. It **MUST NOT** be repeated on later frames: on a
    later frame `chunk_lens` was only a redundant equality check on an array the client already held.

##### The paged prologue (NORMATIVE)

- A sender **MUST NOT** put more than `MAX_CHUNK_LENS_PER_FRAME` entries of `chunk_lens` on one frame.
  A layout larger than that **MUST** be sent as a **paged prologue**: successive frames each carrying at
  most that many entries, each stamped with the `chunk_lens_offset` at which its page begins.
- Every frame carrying a `chunk_lens` page **MUST** state `chunk_lens_offset`, and every frame of the
  stream **MUST** state `chunk_count` — the total number of entries the reassembled array has. A reader
  places each page at its stated offset and holds the complete layout once it has `chunk_count` entries.
  An absent `chunk_lens_offset` means the page begins at entry 0, which is the single-frame layout and
  the pre-0.13.0 shape.
- Pages **MUST** tile the array exactly, without gaps or overlap, and the reassembled array's entries
  **MUST** sum to `total_length`. `chunk_lens` is a **DECRYPT** input, not a verify input: per-chunk
  AES-256-GCM-SIV needs the WHOLE array, and a reader rejects any array whose sum differs from
  `total_length`. A partial layout is therefore unusable, never partially useful.
- A reader **MUST** bound the layout it accumulates by `chunk_count`, and `chunk_count` by the
  consumer's own `MAX_MODULE_CHUNK_COUNT` — a hostile sender **MUST NOT** be able to force unbounded
  allocation by announcing a huge count or by sending pages beyond it.
##### Reassembling the paged prologue (NORMATIVE)

A reader accumulates the pages of one range stream into one array of `chunk_count` entries. The rules
below are a **class**, not a list of observed misbehaviours: each is stated over every page that could
break it, because a rule aimed at one behaviour (a short LAST page) is bypassed by the next variant of
it (a short MIDDLE page, a repeated page, an offset off by one). `ChunkLensAssembler` is the reference
implementation and `ChunkLensError` names one variant per rule.

- A reader **MUST** refuse a declared `chunk_count` exceeding `MAX_RESOURCE_CHUNK_COUNT` (1,048,576)
  **before** allocating, and **MUST** reserve the array **fallibly**. Sizing an allocation to a
  stranger's declared number is a memory-exhaustion primitive: one small frame declaring a vast count is
  otherwise enough to abort a node. At the ceiling the array is 8 MB of `u64`, which is the whole
  derivation of that number.
- A page **MUST** be non-empty and **MUST NOT** exceed `MAX_CHUNK_LENS_PER_FRAME` entries. An empty page
  fills nothing, so accepting it lets a sender stream frames indefinitely without completing the prologue.
- A page's `chunk_lens_offset` **MUST** be a multiple of `MAX_CHUNK_LENS_PER_FRAME` and **MUST** be
  strictly below `chunk_count`. The offset range check **MUST** be performed in the wire's own `u64`
  width, so an offset near `u64::MAX` cannot truncate into a valid index.
- A page **MUST NOT** extend past `chunk_count`, and every page except the tail **MUST** be exactly
  `MAX_CHUNK_LENS_PER_FRAME` entries long. A short non-final page leaves a gap that no page-aligned page
  can ever fill, so it is refused **on arrival** rather than surfacing later as an unexplained
  incompleteness.
- A page for an already-filled slot **MUST** be REJECTED and **MUST NOT** overwrite what was accepted.
  Overwriting would let the LAST sender of a page decide its contents.
- A rejected page **MUST** leave the accumulated state unchanged — a rejection is not a partial
  application.
- A reader **MUST NOT** expose a partial array under any circumstance, and **MUST** treat a prologue that
  ends short of `chunk_count` as a failure that yields **no array at all**. `chunk_lens` is a **DECRYPT**
  input whose entries must sum to `total_length`; a layout short even one entry cannot decrypt the
  resource, so a partial array is unusable rather than partially useful.
- A `chunk_count` of zero is a complete prologue with an empty array. Reporting it forever-incomplete
  would stall a stream over a resource that is already fully described.
- A sender **MUST** produce pages of exactly this shape. `RangeFrame::split_chunk_lens_pages` is the
  normative split and the mirror of the reassembler; a serve path **SHOULD** use it rather than re-derive
  the paging rule, since #1640 was precisely an encode/decode asymmetry in which the two sides of one
  rule were maintained separately.

- A client that already holds the commitment for this `root` **SHOULD** set `RangeRequest.skip_layout`,
  and a holder honouring it omits the resource-scaling set entirely (the identity set is **NOT**
  suppressed). `skip_layout` absent or `false` preserves the pre-0.13.0 behaviour, so a holder that does
  not understand the field is never broken by it — it simply sends metadata the client discards.
- The whole ecosystem's permitted sizes are now representable: `digstore-host`'s `MAX_MODULE_BYTES` of
  256 MiB (about 4,096 chunks at the 64 KiB target) and dig-download's `MAX_MODULE_CHUNK_COUNT` of
  1,048,576 both ride a paged prologue. The ONE unrepresentable input is an `inclusion_proof` whose
  base64 exceeds `MAX_INCLUSION_PROOF_B64`; see §5.1.

##### Wire compatibility of these fields (NORMATIVE)

- `chunk_count`, `chunk_lens_offset` and `skip_layout` are **additive** (§5.1 backwards compatibility):
  an older reader ignores them, and a newer reader parses an older message with each absent.
- The `dig.getAvailability` and `dig.fetchRange` types are `#[non_exhaustive]` and are built through
  their constructors, never through a struct literal. The consequence is deliberate and worth stating:
  **every future additive field on these types is a PATCH, not a minor or a major** — a consumer's code
  keeps compiling — which is why the 0.13.0 consumer cascade does not have to repeat.
- An implementation **MUST NOT** work around the proof cap locally — not by raising `MAX_FRAMED_BODY`
  (a RECEIVER bound: no sender may exceed it until every receiver is deployed, and no finite cap holds
  a million entries without abandoning the bounded-allocation property the cap exists for), not by
  truncating `chunk_lens` (it is a DECRYPT input; per-chunk AES-256-GCM-SIV needs the whole array, and
  a reader rejects any array whose sum ≠ `total_length`), and not by emitting an unverified frame. Each
  would be a silent wire divergence, which is the class of defect §5.1 exists to close.
- A conforming sender **SHOULD** serialize-and-check its frame before writing, so the serve path does
  not *depend* on the encoder's refusal to stay correct. The refusal in §5.1 is the backstop, not the
  mechanism.

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
- A relay `Error` frame **MUST** be classified before it is allowed to end the reservation, because
  the relay reports both reservation-level and PER-REQUEST failures on the same channel:
  - Codes meaning THIS node's registration did not happen or is no longer valid — `1 NOT_REGISTERED`,
    and the four that accompany a failing `register_ack` (`4 CAPACITY`, `5 ID_IN_USE`,
    `6 IDENTITY_MISMATCH`, `7 RATE_LIMITED`) — **MUST** end the reservation loop and re-register with
    backoff.
  - Per-request codes — `2 BAD_MESSAGE` (one frame we sent) and `3 PEER_NOT_FOUND` (the peer we tried
    to reach is not on this relay) — **MUST NOT** disturb the reservation. `PEER_NOT_FOUND` is routine
    on a live network; treating it as fatal de-registers the node on every failed dial and flaps it in
    and out of every other peer's introductions.
  - An UNKNOWN code **MUST** be treated as per-request (reservation held) and logged. The asymmetry is
    deliberate: a wrong guess costs a log line, whereas defaulting to fatal would let a newly-introduced
    code drop every node on the network off its relay at once.
  These codes are byte-identical to `dig-relay`'s `errcode` catalogue.
- The relay is an UNTRUSTED intermediary. The discovered-peer set **MUST** be bounded to a fixed cap
  (`MAX_KNOWN_PEERS`, 1024) and deduped by `peer_id`: a hostile/compromised relay can stream an
  unbounded flood of `PeerConnected` frames — or a single oversized `Peers` frame — with distinct
  fabricated `peer_id`s. Once the set is full, further distinct peers **MUST** be dropped (the set
  never grows past the cap), and both the per-push fold and the `Peers`-frame replace **MUST** enforce
  it. Membership/dedup **MUST** be O(1) so the flood cannot impose an O(n²) insert cost.

### 5a.3 Wire extensibility (NORMATIVE)

`RelayMessage` is `#[non_exhaustive]`. Adding a new RLY-0xx message is therefore an ADDITIVE change:
a consumer's `match` already carries a wildcard arm, so a new variant ships as a PATCH and reaches
every consumer on a plain `cargo update`.

This is a contract, not a convenience. Before it, each wire addition was a semver-major event for a
`pub enum`, so every crate pinned to the previous minor had to be bumped and re-released before the
node could pick the change up — RLY-009 cost exactly that five-crate cascade (dig_ecosystem #1935).

- A receiver MUST tolerate an unknown `type` discriminator by IGNORING the frame, never by erroring
  and never by dropping the reservation — an unrecognised message is how a newer peer looks to an
  older one, and treating it as fatal would make every future addition an outage.
- A new variant MUST NOT change the meaning or encoding of an existing one; the four vendored copies
  (`dig-gossip`, `dig-relay`, `dig-nat`, `dig-node`) MUST stay byte-identical for every message they
  both understand.

### 5a.2 RLY-009 — aggregated DHT-record answers (NORMATIVE)

The relay is not a DHT node and holds no provider records, but it keeps a live reservation to every
registered peer. RLY-009 lets it ASK: a Kademlia node stores records for keys near its OWN `peer_id`,
so each node's store describes MANY OTHER peers' content, and the union across connected nodes is a
broad slice of the real DHT with the relay never joining it (dig_ecosystem #1935).

- The relay MAY send `get_dht_records { max_keys }` over the reservation. A node that opts in
  answers `dht_records { records, total_keys, truncated }`.
- **Opt-in.** A node MUST answer only when a reader has been registered
  (`RelayStatus::set_dht_records_provider`). With none registered it MUST stay SILENT — on the wire
  indistinguishable from a pre-RLY-009 node, which the relay MUST treat as "no data", never an error.
- **Counts, never identities.** `records` carries `content_key` → live provider COUNT. A provider
  record is a `(peer_id, content_key)` pair, and publishing that linkage is precisely what the
  relay's `/map` privacy contract forbids. No provider identity may appear in an RLY-009 answer.
- **The bound is the relay's, and MUST be honoured.** The provider store is attacker-influenced (any
  peer may `add_provider`), so an answer ignoring `max_keys` would let a Sybil dictate the frame size
  on the socket the node depends on for its own reachability. `total_keys` reports the true
  pre-truncation count and `truncated` says whether the cap bit, so a partial view is never
  presented as complete.
- **A node MUST ignore an inbound `dht_records`.** It is the answerer, never the asker; treating a
  stray one as an error would let a confused or hostile relay drop the node's reservation.
- Additive (NC-6 soft-fork), and byte-identical across the four vendored copies of this wire
  (`dig-gossip`, `dig-relay`, `dig-nat`, `dig-node`).

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

## 6a. Rendering untrusted text in errors (NORMATIVE, #1674)

Text that a remote party influenced — a decode failure's offending input, a TLS error derived from the
certificate a peer presented, a relay's status line — **MUST** be neutralized at the point it is
RENDERED, not at the point it is logged. Sanitizing at each log site is not sanitizing: the next log
line starts again from the raw value.

- `SafeText` is the conforming carrier. Its only constructors are `from_untrusted` (escapes every
  control and bidirectional-formatting character, bounds the result to `MAX_SAFE_TEXT_CHARS = 512`)
  and `from_static` (a `&'static str`, i.e. a source literal). A raw runtime `String` cannot enter it
  unsanitized, so an error that HOLDS a `SafeText` cannot carry raw peer text however it is built.
- A rendered error **MUST NOT** contain U+000A, U+000D, any other control character, or any
  bidi-formatting character originating from a remote party.
- Both `Display` **and** `Debug` **MUST** neutralize. `Debug` reaches a log at least as often —
  `{:?}` on a `Result`, an `unwrap` panic, a `tracing` field — so a safe `Display` over a leaky
  `Debug` closes half the surface. `MethodError` states both explicitly rather than relying on a
  derived `Debug` that happens to escape as a side effect of quoting.
- `MethodError.reason` remains a `String` so a consumer can match on it, and is neutralized in both
  renderings. A consumer that reads the field directly and logs it **MUST** neutralize it itself.

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
  is dialed only over IPv4 (G2); an EMPTY intersection over a peer that has candidates fails OPEN and
  attempts them all IPv6-first; a peer with NO candidates fails immediately with `NoCommonFamily` and
  attempts NO dial. End-to-end over the production `MtlsDialer`: `[unreachable IPv6, reachable IPv4]`
  connects over IPv4; a v4-only-detected host asked for a v6-only peer really attempts that candidate
  and surfaces the transport failure, never a no-common-family refusal.
- IPv6 selection: `select_global_ipv6` returns a global-unicast IPv6 and rejects link-local / ULA /
  loopback / unspecified.
- Identity: `peer_id = SHA-256(SPKI DER)` matches `dig-gossip` (`tests/identity.rs` conformance).
- Cross-crate BLS conformance (`tests/identity.rs`, the extraction's keystone): dig-tls's BLS G1/G2
  work (via its own `chia-bls`/`blst`) and dig-identity's **MUST** agree byte-for-byte — the same
  secret scalar derives the same 48-byte G1 pubkey in both, signatures cross-verify in both
  directions, and the pubkey dig-tls binds into a real `NodeCert` (recovered via
  `verify_binding_from_leaf_cert`) equals dig-identity's derived pubkey. This is the check dig-tls's
  `bls.rs` defers to the integration level; it FAILS if a future `chia-bls`/`blst` bump ever diverges.
- Frozen BLS vectors (`tests/bls_golden_vectors.rs`): the cross-crate conformance above is a
  RELATIVE check — a `chia-bls` uplift that changed the derivation on both sides at once would keep
  it green. So the EIP-2333 secret scalar, the compressed 48-byte G1 public key, and the
  deterministic 96-byte G2 AugScheme signature are additionally pinned as absolute byte vectors for
  three label-derived keys. A dependency uplift **MUST** reproduce them exactly; a changed value is a
  wire-compatibility break with peers already deployed, never a value to re-bless.
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
