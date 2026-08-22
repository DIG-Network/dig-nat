# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.20.0] - 2026-08-22

### Build
- **deps:** Uplift dig-tls 0.3 -> 0.4 (chia-bls 0.36.1), release 0.20.0 (#27)

## [0.19.0] - 2026-08-08

### Features
- **deps:** Bump dig-constants 0.10, dig-identity 0.6, dig-ip 0.1.2 (#25)

## [0.18.0] - 2026-08-02

### Features
- **wire:** Make RelayMessage non_exhaustive so wire additions stop being breaking (#24)

## [0.17.0] - 2026-08-02

### Features
- **relay:** RLY-009 — answer the relay's request for aggregated DHT records (#23)

## [0.16.0] - 2026-08-02

### Bug Fixes
- **relay:** A per-request error must not tear down the reservation (#22)

## [0.15.0] - 2026-07-31

### Features
- **safe-text:** SafeText — peer bytes cannot reach an error string by construction (#1674) (#21)

## [0.14.1] - 2026-07-28

### Bug Fixes
- **relay:** Derive the circuit TLS role from direction, not from whatever frame arrives

## [0.14.0] - 2026-07-27

### Features
- **mux:** ChunkLensAssembler — decode-side mirror of the paged prologue (0.14.0) (#19)

## [0.13.0] - 2026-07-26

### Features
- **mux:** Paged range-metadata prologue wire + published/enforced proof cap (0.13.0) (#18)

## [0.12.0] - 2026-07-26

### Bug Fixes
- **mux:** Publish the RangeFrame payload ceiling and refuse over-cap frames at the sender (#1640) (#17)

## [0.11.2] - 2026-07-25

### Bug Fixes
- **mux:** RangeFrame `bytes` is base64 on the wire, not serde_bytes (#1586) (#16)

## [0.11.1] - 2026-07-25

### Bug Fixes
- **dig-nat:** Refuse self-dial on ALL tiers at the MtlsDialer chokepoint (#1590, #836) (#15)

## [0.11.0] - 2026-07-23

### Bug Fixes
- **dig-nat:** Relayed responder path — accept introduced circuits as mTLS server (#1536) (#14)

## [0.10.0] - 2026-07-21

### Bug Fixes
- **dig-nat:** Auto-dialer adopts SPKI-pinned mTLS — accept self-signed §5.2 peers (#1422) (#13)

## [0.9.0] - 2026-07-21

### Features
- **dig-nat:** Fast-connect (TURN-first) + relay-dial happy-eyeballs (0.9.0, #1389 #1390) (#12)

## [0.8.1] - 2026-07-21

### Bug Fixes
- **dig-nat:** Reject non-global/reserved STUN reflexive addresses + clarify dialable-candidate API (#11)

## [0.8.0] - 2026-07-21

### Features
- **dig-nat:** Happy-eyeballs STUN reflexive discovery (§5.2 IPv6-first, IPv4-fallback) (#1385) (#10)

## [0.7.0] - 2026-07-20

### Features
- Connect() auto-composes the full NAT ladder + mTLS-over-relay tunnel dial (0.7.0) (#9)

## [0.6.0] - 2026-07-20

### Features
- Consume dig-tls for cert/mTLS/peer_id/BLS-binding (dig-nat 0.6.0, #1274) (#8)

## [0.5.1] - 2026-07-19

### Chores
- **deps:** Source dig-constants + dig-identity from crates.io; widen dig-constants to >=0.4,<0.6 (#7)

## [0.5.0] - 2026-07-19

### Features
- **cert-binding:** MTLS cert BLS peer_id binding + relay-descriptor verification (#1204) (#6)

## [0.4.0] - 2026-07-18

### Features
- **dialer:** Migrate dial path to dig-ip (local∩peer family intersection) (#5)

## [0.3.0] - 2026-07-18

### Features
- **relay:** Address-carrying reservation (B1) + real RLY-002 relayed transport (B2) (#4)

## [0.2.1] - 2026-07-17

### Bug Fixes
- **deps:** Widen dig-constants req to >=0.2,<0.4 for 0.3.0 (#3)

## [0.2.0] - 2026-07-17

### Features
- **relay:** Discover peers over the persistent reservation socket (#2)

## [0.1.1] - 2026-07-12

### Bug Fixes
- **deps:** Re-resolve DIG git deps to rewritten (co-author/signed) revs

### CI
- Enforce version increment in PRs (package.json / Cargo.toml)- Enforce Conventional Commits with commitlint on PRs- Enforce Conventional Commits with commitlint on PRs- Release automation (git-cliff changelog + tag on merge); publish is manual workflow_dispatch (#230)- Re-arm crates.io auto-publish on version tag (token in org secrets; auto-publish-everything #230)- Add flaky-test management (#489) (#1)

### Chores
- **changelog:** Add git-cliff config for Conventional-Commit changelog


