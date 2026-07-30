# Argus Release Decisions

## ADR-001 — Ship Path A

- **Status:** accepted
- **Decision:** Argus 1.0 is a supervised defensive assessment release
  candidate. V1 is supported; V2 continuous mode remains experimental and is
  explicitly gated.
- **Rationale:** code inspection proved that completing Path B would require a
  full lifecycle redesign: collector execution, target handling, observation
  normalization, error semantics, identity, correlation, persistence,
  recovery, and delta closure. Shipping a partial Path B would create a false
  safety claim and an unreviewable increment.
- **Consequences:** no supported `continuous` command exists. Importing and
  constructing `ContinuousRunner` requires an explicit `experimental=True`
  development opt-in. CLI, localhost UI, README, roadmap, and dashboard show
  the same warning.
- **Re-entry gate:** Path B begins only as a fresh, separately approved branch
  from merged main and must satisfy the complete `NEXT` binary gate in
  [`ROADMAP.md`](ROADMAP.md).

## ADR-002 — Evidence gates replace completion percentages

- **Status:** accepted
- **Decision:** roadmaps use `NOW`, `NEXT`, `LATER`, and `DEFERRED`, with
  explicit commands, evidence, and binary exit gates.
- **Rationale:** a percentage or checked documentation task does not establish
  operational behavior.
- **Consequences:** “complete” means the executable gate passed and evidence is
  linked. Scaffold completion is labeled separately.

## ADR-003 — Local anchor is not WORM

- **Status:** accepted
- **Decision:** the Phase 2A JSON anchor is described only as a transactional
  local consistency checkpoint.
- **Rationale:** it shares the controller trust domain and can be replaced by an
  attacker who controls that account/filesystem.
- **Consequences:** an independently administered external anchor remains a
  later gate for higher-trust deployment.

## ADR-004 — Signer issue remains a separate security increment

- **Status:** accepted
- **Decision:** the release-closeout increment does not implement an external
  signer.
- **Rationale:** issue #4 requires a protocol, authentication, availability,
  recovery, operations, and rollback design. It is not required for the
  supervised isolated-lab release boundary and cannot be safely hidden inside a
  documentation closeout.
- **Consequences:** the orchestrator still holds the HMAC key. The key is
  scrubbed from child tool environments, but controller compromise remains a
  residual risk.

## ADR-005 — Deterministic control dashboard

- **Status:** accepted
- **Decision:** `docs/index.html` is generated from
  `docs/control/STATUS.json` and links into the canonical Markdown pack.
- **Rationale:** the previous independently maintained page could drift from
  repository and CI truth.
- **Consequences:** generation must be byte-identical; source commit, timestamp,
  evidence state, and deployment warnings are visible and tested.

## ADR-006 — No deployment in release closeout

- **Status:** accepted
- **Decision:** completion means merge and post-merge verification, not runtime
  deployment.
- **Rationale:** the mandate forbids live targets, credentials, production
  services, regulated data, and external mutable test systems.
- **Consequences:** release documentation states “not deployed”; a future
  operator deployment requires the runbook and independent authorization.

