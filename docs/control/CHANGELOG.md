# Argus Engineering Change Log

## 2026-08-29 — PR #18 recorded; scope overlap deny; DOM fixtures

### Added

- Deny-by-overlap for Layer-1 scope so a parent CIDR cannot scan a more-specific
  carve-out (clinical `172.30.0.50/32` inside lab `172.30.0.0/24`).
- Packed integer/hex tokens that do not fit in IPv4 fail closed instead of
  becoming IPv6.
- Squash-merge topology coverage in control-docs CI (one-parent `main` pushes).
- Browser DOM fixture inventory and static-console contract tests.

### Changed

- Control dashboard, roadmap, and STATUS.json record PR #18 as merged.
  Out-of-band HMAC signer and bounded V2 foundation are no longer "in review".
- Issue #4 is closed by PR #18; independently administered WORM remains LATER.
- README and package README test badges updated to the PR #18 collection (315).

### Preserved

- Scope, tool firewall, argument, budget, time, approval, sandbox, audit,
  redirect, request-size, localhost, and server-controlled live-mode values.
- Continuous mode remains experimental and unsupported.
- Local JSON anchor is still not WORM. No live scan or deployment.

### Explicitly not changed

- No Playwright CI job yet. Fixture inventory is the start of that gate.
- No unattended scheduler, production claim, or multi-user service.

## 2026-07-30 — Argus 1.0 supervised RC closeout

Delivered by [PR #17](https://github.com/gesh75/argus/pull/17), merged as
`b75af239c441204699114ce34970e37b394b3c21`.

### Added

- Canonical control pack under `docs/control/`.
- Deterministic `docs/index.html` generator and regression tests.
- Machine-readable `STATUS.json`.
- Explicit release-boundary tests for CLI, localhost UI, and V2 continuous
  construction.
- Shallow-history freshness coverage for PR synthetic merges and post-merge
  `main` pushes.

### Changed

- Declared Argus 1.0 as a supervised defensive assessment release candidate.
- Gated V2 `ContinuousRunner` behind explicit experimental opt-in.
- Corrected V1/V2 maturity, audit, anchor, continuous-mode, specialized-agent,
  persistence, test-count, quickstart, Python, CI, and CodeQL claims.
- Linked the root README to the canonical control pack and dashboard.
- Resolved all three findings from the one authorized independent read-only
  review.

### Preserved

- Scope, tool firewall, argument, budget, time, approval, sandbox, audit,
  redirect, request-size, localhost, and server-controlled live-mode values.
- Phase 1 and Phase 2A regression coverage.
- Existing Phase 1 V1 audit backup and all competing local worktree evidence.

### Verified

- 292 Python 3.12 hash-locked tests passed.
- Ruff introduced no new or changed finding; all changed Python files passed.
- Bandit found no medium/high issue; authoritative GitHub `pip-audit` passed.
- Clean sdist/wheel build, locked wheel install, and CLI smoke passed.
- Final PR CI/CodeQL and post-merge `main` CI/CodeQL passed; open CodeQL
  alerts: zero.

### Explicitly not changed

- No real scan, target traffic, credential use, deployment, production service,
  regulated data, or network-exposed operation.
- No external signer, external anchor, operational V2 lifecycle, autonomous
  remediation, or Phase 3–6 implementation.

## 2026-07-28 — Repository automation

- PR #16 added comprehensive Copilot instructions and coding-agent setup.
- PR #15 resolved four CodeQL alerts.
- PR #14 enabled CodeQL and initial Copilot context.

## 2026-07-25 — Phase 2A

- PR #13 added strict V1/V2 audit replay, sequence-bound domain-separated V2
  HMAC records, POSIX locking, durable local log/anchor boundaries, read-only
  diagnostics, explicit anchor recovery, and crash/concurrency tests.

## 2026-07-22 — Phase 1

- PR #12 completed the safety freeze and execution-boundary closure: redirect
  refusal, localhost ASGI peer checks, streamed body limit, server-owned live
  mode, DOM-safe rendering, dependency/package repair, and regression tests.
