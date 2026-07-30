# Argus Evidence-Gated Roadmap

Roadmap states are `NOW`, `NEXT`, `LATER`, and `DEFERRED`. Percent-complete
claims are intentionally not used. A state changes only when its binary exit
gate and evidence are satisfied.

## NOW — Argus 1.0 supervised defensive assessment release candidate

- **Objective:** close one coherent, reviewable supervised V1 release candidate.
- **Included scope:** worktree recovery; Path A V2 isolation; claim
  reconciliation; canonical control pack; deterministic dashboard; Python 3.12
  regression, security, dependency, package, wheel, CLI, CI, and CodeQL gates.
- **Exclusions:** operational V2, external signer, external/WORM anchor,
  network-exposed service, multi-user authentication, live deployment, and
  Phase 3–6 features.
- **Dependencies:** Phase 1 and Phase 2A merged baselines; hash-locked Python
  dependencies; GitHub Actions and CodeQL.
- **Security boundary:** no live traffic or credentials; no scope, tool,
  approval, sandbox, audit, redirect, or web-boundary weakening.
- **Verification commands:** the full command set in
  [`RUNBOOK.md`](RUNBOOK.md), including pytest, Ruff baseline comparison,
  changed-file Ruff, Bandit, pip-audit, clean archive build, wheel smoke,
  deterministic generation, and link validation.
- **Binary exit gate:** one PR merged with every required check green, no new
  CodeQL alert, one read-only reviewer with no unresolved blocker, clean
  post-merge main, and no deployment performed.
- **Evidence:** pull request, CI/CodeQL URLs, final `STATUS.json`, generated
  dashboard, and merge SHA.
- **Owner:** Georgi Gaydarov; implementation executed by the sole Codex session.
- **Current state:** complete. PR #17 merged as
  `b75af239c441204699114ce34970e37b394b3c21`; post-merge
  [CI 30523751828](https://github.com/gesh75/argus/actions/runs/30523751828)
  and
  [CodeQL 30523751784](https://github.com/gesh75/argus/actions/runs/30523751784)
  passed with zero open CodeQL alerts.
- **Re-entry condition:** any regression or contradicted release claim reopens
  `NOW`; no later phase starts first.

## NEXT — Bounded V2 operational foundation

- **Objective:** complete one end-to-end, dry-run-first V2 lifecycle.
- **Included scope:** typed proposals/results; explicit operator targets;
  guardrail authorization immediately before existing collector execution;
  normalized observations; asset-bound correlation; deterministic path
  identity; versioned transactional graph persistence; truthful new/changed/
  closed deltas; one bounded CLI command.
- **Exclusions:** unattended scheduling, production claims, remediation,
  multi-user operation, and arbitrary model-generated commands.
- **Dependencies:** merged `NOW`; approved V2 design specification; current V1
  collectors and guardrail reused without bypass.
- **Security boundary:** explicit target input; no target synthesis; no blanket
  exception suppression; no new execution path around `Guardrail.authorize()`.
- **Verification commands:** focused unit tests plus end-to-end
  save→reload→rerun→delta tests, idempotence checks, crash/corruption tests,
  full release gates, and dry-run CLI smoke.
- **Binary exit gate:** the complete proposal→authorization→collector→
  observation→graph→correlation→persistence→delta chain passes end to end;
  repeated cycles are idempotent; no continuous loop is enabled by default.
- **Evidence:** approved design, executable tests, committed implementation,
  green PR CI/CodeQL, operator runbook.
- **Owner:** unassigned until separately authorized.
- **Current state:** queued, not started.
- **Re-entry condition:** start only from the merged `NOW` main SHA with a fresh
  branch and explicit authorization.

## NEXT — Out-of-band audit signer

- **Objective:** resolve GitHub issue #4 by removing the HMAC key from the
  orchestrator process.
- **Included scope:** signer protocol, authentication, redacted failure
  semantics, availability behavior, key lifecycle, recovery, operations,
  rollback, and tests.
- **Exclusions:** external/WORM storage adapter unless separately approved.
- **Dependencies:** approved threat model and signer boundary; preservation of
  Phase 2A record compatibility.
- **Security boundary:** orchestrator never receives signing key material;
  signer failure denies audit-dependent actions.
- **Verification commands:** protocol tests, authentication failures,
  availability failures, replay compatibility, full regression and security
  gates.
- **Binary exit gate:** tool runner process and child environments contain no
  signing key while every audit operation remains fail closed and verifiable.
- **Evidence:** issue #4 closure PR, test report, operations and rollback proof.
- **Owner:** unassigned until separately authorized.
- **Current state:** open issue; not a blocker for supervised isolated V1.
- **Re-entry condition:** separately approved security increment.

## LATER — Independently administered external anchor

- **Objective:** detect valid whole-record tail removal outside the controller
  trust domain.
- **Included scope:** authenticated external adapter, append/retention policy,
  outage behavior, reconciliation, monitoring, and restore procedure.
- **Exclusions:** describing local JSON as WORM.
- **Dependencies:** external administration and storage selection; signer
  architecture decision.
- **Security boundary:** independent credentials and administration; outage
  fails closed for deployments claiming the stronger integrity level.
- **Verification commands:** tamper, outage, stale/ahead/divergent, restore,
  authorization, and retention-policy tests.
- **Binary exit gate:** independently administered evidence detects a valid
  local tail deletion and cannot be rewritten by the Argus controller.
- **Evidence:** provider configuration, retention proof, test report, runbook.
- **Owner:** unassigned.
- **Current state:** later.
- **Re-entry condition:** required before any higher-trust or regulated
  deployment evaluation.

## LATER — Browser-executed console security suite

- **Objective:** supplement static DOM-sink checks with actual browser behavior.
- **Included scope:** malicious result fixtures, rendering, navigation, CSP and
  localhost-boundary assertions.
- **Exclusions:** network exposure or multi-user UI.
- **Dependencies:** stable V1 console.
- **Security boundary:** synthetic data only; no live targets.
- **Verification commands:** Playwright browser test and current ASGI/static
  regressions.
- **Binary exit gate:** malicious fixtures execute no script and render only as
  text in a real browser.
- **Evidence:** trace/screenshots and CI test results.
- **Owner:** unassigned.
- **Current state:** later, non-blocking for current release.
- **Re-entry condition:** begin in the next UI-focused increment.

## DEFERRED — Unattended continuous service

- **Objective:** evaluate opt-in scheduled defensive sensing only after the V2
  foundation is operational.
- **Included scope:** scheduling, cancellation, backpressure, observability,
  bounded failure policy, operator controls, and safe shutdown.
- **Exclusions:** permanent autonomous remediation.
- **Dependencies:** complete `NEXT` V2 lifecycle, external signer decision,
  durable persistence, and an approved operations model.
- **Security boundary:** no default-on loop; every action reauthorized; bounded
  targets, cadence, budgets, and stop controls.
- **Verification commands:** soak, crash, cancellation, fault-injection,
  idempotence, authorization, and operations tests.
- **Binary exit gate:** approved threat model and bounded soak evidence show no
  skipped authorization, hidden failure, duplicate action, or unbounded retry.
- **Evidence:** separate design/implementation PR and operations record.
- **Owner:** unassigned.
- **Current state:** deferred.
- **Re-entry condition:** all dependencies complete and owner explicitly
  authorizes this separate increment.

## DEFERRED — Production, regulated, network-exposed, or multi-user deployment

- **Objective:** define a product boundary appropriate for higher-trust use.
- **Included scope:** authenticated identities, tenant isolation, secrets/PHI
  controls, deployment hardening, monitoring, recovery, compliance evidence,
  external signer, and external anchor.
- **Exclusions:** retroactive claim that alpha lab evidence proves production
  readiness.
- **Dependencies:** organizational risk acceptance and all prerequisite
  engineering increments.
- **Security boundary:** deny by default until independently reviewed and
  explicitly deployed.
- **Verification commands:** dedicated threat model, penetration test,
  deployment validation, disaster recovery exercise, and compliance review.
- **Binary exit gate:** owner and independent security reviewers approve a
  separately versioned deployment profile with reproducible evidence.
- **Evidence:** future deployment record; none exists today.
- **Owner:** unassigned.
- **Current state:** deferred.
- **Re-entry condition:** explicit owner authorization after technical and
  operational prerequisites are complete.
