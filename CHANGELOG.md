# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.4.0] - 2026-07-18

### Features
- **dialer:** Migrate the dial path to the canonical `dig-ip` crate — dig-nat is its first consumer.
  `MtlsDialer::dial` now dials only the local∩peer address-family INTERSECTION (never a family the
  local host or the peer lacks), IPv6-first with graceful IPv4 fallback; a disjoint local/peer pair
  fails immediately with `NoCommonFamily` instead of a doomed, hanging SYN. Removes the hand-rolled
  happy-eyeballs racer + IPv6-first family sort (`happy_eyeballs_connect`, `peer::sort_ipv6_first`,
  `peer::is_ipv6_first`); candidates are now stored in discovery order and ordered by dig-ip at dial
  time. mTLS/cert/pinning behaviour is unchanged. (#1029)

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


