# dig-nat

Abstract NAT traversal for DIG Node peer connections. **One `connect()` API** establishes a
mutually-authenticated (mTLS) connection to a peer using the best available traversal method,
transparently — the caller never chooses the method, and `relay.dig.net` is the last-resort fallback.

```rust
use dig_nat::{connect, NatConfig, LocalIdentity, PeerTarget, PeerId};

// You have your own mTLS identity, the peer's id, and (maybe) an address hint.
let peer = PeerTarget::with_addr(peer_id, addr, "DIG_MAINNET");
let conn = connect(&peer, &identity, &NatConfig::default()).await?;

println!("connected to {} via {:?}", conn.peer_id, conn.method); // e.g. "… via Direct"
// `conn.stream` is an authenticated, encrypted mTLS byte stream to the peer.
```

## What it does

Given a peer, `dig-nat` tries — in order, first success wins — the cheapest, most-direct path first
and the bandwidth-heavy relay last:

1. **Direct** — peer publicly reachable / already port-forwarded
2. **UPnP/IGD** port mapping
3. **NAT-PMP** (RFC 6886)
4. **PCP** (RFC 6887)
5. **Relay-coordinated hole punch** — relay used for *signaling only*; the data path is direct P2P
6. **Relayed transport (TURN-like)** — relay proxies all data; the genuine last resort

The returned connection is always **mutual TLS** with the peer's identity verified:
`peer_id = SHA-256(TLS SubjectPublicKeyInfo DER)` (matching `dig-gossip`). Which method won is
reported for observability but the caller uses the stream identically.

## Key properties

- **Method is transparent.** The caller connects to a *peer*, not via a *technique*.
- **Graceful fallback.** Every method is bounded by a timeout; if all fail you get a clear
  `NatError::AllMethodsFailed` with per-method reasons — never a panic or a hang.
- **Relay resilience baked in.** The relay client (relocated + generalized from `dig-node`) keeps a
  node's persistent reservation alive with keepalive + capped-exponential-backoff reconnect,
  tolerates the relay being down (retries in the background, never crashes the node), logs once per
  state change, exposes a `RelayStatus` snapshot, and honours `DIG_RELAY_URL=off`.
- **Self-authenticating transport.** Connecting to `peer_id X` provably reaches the holder of X's
  key or fails (rustls verifier pins the peer_id).
- **Endpoint from `dig-constants`.** Default relay `wss://relay.dig.net:9450`.

## Layout

| Module | Responsibility |
|--------|----------------|
| `connect` (lib root) | The public API — assembles methods + runs the strategy |
| `strategy` | Orders methods (direct-first, relay-last), first-success-wins, all-fail→error |
| `method::{direct,upnp,natpmp,pcp,hole_punch,relayed}` | One module per technique, behind `TraversalMethod` |
| `dialer` | The production mTLS dial (rustls) with peer_id pinning |
| `mtls` | The rustls verifier that derives + pins `peer_id = SHA-256(SPKI DER)` |
| `identity` | `PeerId` + `peer_id_from_tls_spki_der` (matches dig-gossip) |
| `stun` | RFC 5389 reflexive-address discovery |
| `relay` + `wire` | The relay client (reservation + last-resort transport) + the vendored RLY-001..007 wire |
| `config` / `peer` | `NatConfig` builder, `LocalIdentity`, `PeerTarget`, `PeerConnection` |

See [`DESIGN.md`](./DESIGN.md) for the full architecture, the tier-5-vs-tier-6 bandwidth
distinction, and the testability model.

## License

Licensed under either of Apache-2.0 or MIT at your option.
