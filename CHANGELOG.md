# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.6.0] - 2026-07-19

### ⚠ BREAKING CHANGES

- **cert model:** dig-nat now CONSUMES the canonical `dig-tls` crate (crates.io `dig-tls = "0.1"`)
  for ALL certificate / mTLS / peer_id / BLS-binding concerns. The duplicated modules
  `cert_binding`, `mtls`, and `identity` are DELETED and their equivalents are re-exported from
  dig-tls, so there is exactly one implementation of the DIG cert model and no byte-drift risk (#1274).
  - `LocalIdentity` is REMOVED — pass a `dig_tls::NodeCert` (re-exported as `dig_nat::NodeCert`) to
    `connect`. `connect(peer, node, config)` now takes `&Arc<NodeCert>` instead of `&LocalIdentity`.
  - `cert_binding::build_bound_cert` and `CertBindingError` are REMOVED — mint a `NodeCert` via
    `NodeCert::generate_signed` / `load_or_generate` (dig-tls) instead.
  - **Certs are now CA-signed (DigNetwork CA), not self-signed.** A peer that presents a leaf that
    does not chain to the shipped DigNetwork CA is rejected. Consumers regenerate their cert as a
    CA-signed `NodeCert` on adopt. The #1204 BLS binding is byte-compatible (same OID, context
    `dig-nat/cert-bls-binding/v1`, layout); only the issuer changed.
  - `MtlsDialer::new` now takes `Arc<NodeCert>`.

### Features

- **config:** `NatConfig` gains a `binding_policy` (default `Opportunistic`) threaded into `connect`
  so the peer's #1204 cert binding is verified per the configured stance (#1274).

### Tests

- Cross-crate BLS conformance (`tests/identity.rs`): dig-tls's and dig-identity's BLS G1/G2 backends
  agree byte-for-byte (same pubkey, cross-verifying signatures, matching cert-bound seal target) — the
  integration-level check dig-tls's `bls.rs` defers to. FAILS if a future chia-bls/blst bump diverges.

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


