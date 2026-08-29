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

## ADR-008 — Out-of-band signer landed; WORM remains later

- **Status:** accepted and delivered
- **Decision:** PR #18 implements `UnixSocketSigner` / `argus signer`. When
  `ARGUS_SIGNER_SOCKET` is set the orchestrator never loads
  `PENTEST_AUDIT_HMAC_KEY`. In-process signing remains the isolated-lab
  default. Independently administered WORM storage is a separate LATER gate.
- **Rationale:** issue #4 asked for the key out of the tool-runner process.
  That process isolation is now code. Claiming WORM would overstate the local
  JSON anchor, which still shares the controller trust domain (ADR-003).
- **Consequences:** issue #4 closes. ADR-004's residual ("orchestrator still
  holds the HMAC key") no longer applies when the socket env is set. Local
  JSON is still not WORM.

## ADR-009 — Deny matching uses overlap, not subnet_of

- **Status:** accepted
- **Decision:** Layer-1 denied networks match with `IPv4Network.overlaps()`.
  Longest-prefix-match still lets a lab `/24` allow override a broad `/12`
  deny, while a `/32` carve-out inside that `/24` refuses the parent CIDR.
- **Rationale:** `172.30.0.0/24` is not a subnet of `172.30.0.50/32`, so
  `subnet_of` authorized an nmap of the whole lab including the excluded
  host. Firewall semantics are overlap, not containment of the request
  inside the deny.
- **Consequences:** `aegis scan 172.30.0.0/24` is refused when the clinical
  `/32` is denied. Packed integers `>= 2**32` are refused as non-IPv4.

## ADR-007 — Close `NOW` at the reviewed merge

- **Status:** accepted and delivered
- **Decision:** PR #17 at head
  `8f1fed7d88c821f926c332ea691f151c58d73dbd` is the complete implementation
  boundary and was merged as
  `b75af239c441204699114ce34970e37b394b3c21`.
- **Evidence:** 292 hash-locked tests, unchanged Ruff finding set with no new
  finding, clean changed-file Ruff, zero medium/high Bandit issue, successful
  dependency audit, clean package/wheel smoke, one resolved read-only review,
  green PR and post-merge CI/CodeQL, and zero open CodeQL alerts.
- **Consequences:** `NOW` is closed. No V2 operationalization, signer work,
  deployment, or later roadmap item is implicitly authorized.
