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

All peer-to-peer address handling in `dig-nat` is **IPv6-first with IPv4 as a fallback**. This
applies to the candidate model, the outcome model, and the dial path.

### 3.1 Candidate model

- A peer's directly-dialable addresses are carried as an **ordered candidate list**
  (`PeerTarget::direct_addrs`), NOT a single address.
- The list **MUST** be ordered **IPv6-first**: every IPv6 candidate precedes every IPv4 candidate.
  The relative order **WITHIN** each family **MUST** be preserved (a stable ordering), so a caller can
  express a preference among same-family candidates.
- Ordering **MUST** be decided by the address family (`SocketAddr::is_ipv6`). Implementations **MUST
  NOT** decide family by inspecting the string form (a bracketed `[v6]:port` and an `v4:port` both
  contain `:`).
- The constructors `PeerTarget::with_addr` (one address) and `PeerTarget::with_addrs` (many) and the
  mutator `PeerTarget::set_direct_addrs` **MUST** apply this ordering regardless of input order.
- `PeerTarget::direct_addrs()` returns the ordered list. `PeerTarget::direct_addr()` returns the
  single best (first, i.e. IPv6-preferred) candidate, or `None` for a relay-only target. A relay-only
  target (`PeerTarget::relay_only`) has an empty candidate list.

### 3.2 Outcome model

- A traversal method yields a `MethodOutcome` carrying the candidate addresses to dial
  (`MethodOutcome::dial_addrs`), ordered IPv6-first, never empty on success.
- The direct and mapping methods (Direct, UPnP, NAT-PMP, PCP) **MUST** carry the peer's whole
  IPv6-first candidate list so the dial can fall back across families. They construct the outcome via
  `MethodOutcome::candidates`, which re-applies the IPv6-first ordering.
- The hole-punch and relayed methods yield a single coordinated peer address or the relay endpoint
  respectively, via `MethodOutcome::single`.
- `MethodOutcome::dial_addr()` returns the first (IPv6-preferred) candidate.

### 3.3 Dial path — happy eyeballs (RFC 8305-style)

The dialer **MUST** attempt a peer's candidate addresses IPv6-first and **MUST** use IPv4 only as a
fallback when the IPv6 candidate(s) fail or stall:

- Candidates are attempted in IPv6-first priority order. The implementation **MUST** defensively
  re-order the candidates IPv6-first before racing (it does not rely on the caller having sorted).
  An implementation **MAY** skip the re-order step when it can cheaply prove the input is already
  IPv6-first (e.g. `peer::is_ipv6_first`) — this is a pure performance optimization and **MUST NOT**
  weaken the guarantee: genuinely unsorted input **MUST** still be corrected.
- The IPv6 candidate(s) **MUST** be started first. A lower-priority (IPv4) candidate **MAY** be
  started as a hedge once the preferred candidate has not completed within a configurable stagger
  (RFC 8305 "Connection Attempt Delay").
- IPv6 is the **preference**, not merely the first to start: a lower-priority (IPv4) success **MUST**
  be returned only once every higher-priority (IPv6) attempt has concluded (failed or timed out). A
  viable IPv6 candidate therefore wins even if a hedged IPv4 attempt happens to connect first; IPv4
  wins only when IPv6 genuinely fails.
- Each candidate attempt **MUST** be bounded by a configurable per-attempt timeout. The stagger and
  per-attempt timeout are configurable (`HappyEyeballsConfig`) so the racing logic is deterministically
  testable.
- If every candidate fails, the dial **MUST** return an error enumerating the per-candidate reasons;
  it **MUST NOT** panic or hang. An empty candidate list is an error.
- The established connection's reported remote address (`PeerConnection::remote_addr`) **MUST** reflect
  the candidate (and therefore family) actually used.

The pure racing function is `dialer::happy_eyeballs_connect`; the production dialer
(`dialer::MtlsDialer`) uses it to race the TCP connect, then runs the single mTLS handshake over the
winning stream.

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
PeerTarget::with_addrs(peer_id, Vec<SocketAddr>, network_id)// many candidates, sorted IPv6-first
PeerTarget::relay_only(peer_id, network_id)                 // no direct candidates
PeerTarget::direct_addrs() -> &[SocketAddr]                 // ordered IPv6-first
PeerTarget::direct_addr()  -> Option<SocketAddr>            // first (IPv6-preferred) candidate
PeerTarget::set_direct_addrs(Vec<SocketAddr>)               // replace, re-sort IPv6-first
peer::sort_ipv6_first(&mut [SocketAddr])                    // the ordering primitive
peer::is_ipv6_first(&[SocketAddr]) -> bool                  // cheap "already ordered?" check

MethodOutcome::single(kind, addr)                           // hole-punch / relayed (one address)
MethodOutcome::candidates(kind, Vec<SocketAddr>)            // direct / mapping (IPv6-first list)
MethodOutcome::dial_addr() -> Option<SocketAddr>            // first (IPv6-preferred) candidate
MethodOutcome.dial_addrs: Vec<SocketAddr>                   // ordered IPv6-first

dialer::HappyEyeballsConfig { per_attempt_timeout, stagger }
dialer::happy_eyeballs_connect(&[SocketAddr], cfg, connect_one) -> Result<T, String>
dialer::MtlsDialer::new(identity).with_happy_eyeballs(cfg)

connect(peer, identity, config) -> Result<PeerConnection, NatError>
```

## 9. Conformance

- Candidate ordering: given a mixed list, `direct_addrs()` returns all IPv6 before any IPv4, stable
  within family; the ordering is by `IpAddr` family, not the string form.
- Happy eyeballs: given `[unreachable IPv6, reachable IPv4]`, the dial connects over IPv4; given both
  reachable, IPv6 wins; IPv6 is attempted before IPv4 even when input is IPv4-first; all-fail returns
  every candidate's reason.
- IPv6 selection: `select_global_ipv6` returns a global-unicast IPv6 and rejects link-local / ULA /
  loopback / unspecified.
- Identity: `peer_id = SHA-256(SPKI DER)` matches `dig-gossip` (cross-crate conformance test).
- STUN/PCP anti-spoof: transaction id / MAP nonce samples show CSPRNG-level variation across their
  full byte range (not a wall-clock-derived pattern); `query_reflexive_address` and the PCP
  `transact` accept a response only from the address the request was sent to, looping past a
  mismatched-source datagram rather than failing the transaction outright.
