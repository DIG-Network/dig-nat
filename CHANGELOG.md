# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

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


