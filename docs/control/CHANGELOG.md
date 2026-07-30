# Argus Engineering Change Log

## Unreleased — release closeout

### Added

- Canonical control pack under `docs/control/`.
- Deterministic `docs/index.html` generator and regression tests.
- Machine-readable `STATUS.json`.
- Explicit release-boundary tests for CLI, localhost UI, and V2 continuous
  construction.

### Changed

- Declared Argus 1.0 as a supervised defensive assessment release candidate.
- Gated V2 `ContinuousRunner` behind explicit experimental opt-in.
- Corrected V1/V2 maturity, audit, anchor, continuous-mode, specialized-agent,
  persistence, test-count, quickstart, Python, CI, and CodeQL claims.
- Linked the root README to the canonical control pack and dashboard.

### Preserved

- Scope, tool firewall, argument, budget, time, approval, sandbox, audit,
  redirect, request-size, localhost, and server-controlled live-mode values.
- Phase 1 and Phase 2A regression coverage.
- Existing Phase 1 V1 audit backup and all competing local worktree evidence.

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

