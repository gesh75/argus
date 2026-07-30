# Argus V2 Implementation Re-entry Plan

> **Status: not started.** Do not continue the historical
> `feature/argus-defender-fabric-v2` branch. Begin only from merged release
> closeout `main` after separate authorization.

## Gate 0 — Approved design

- Map every proposal to explicit targets and an existing collector.
- Define typed proposals, results, observations, denials, and errors.
- Define deterministic asset/path identity and correlation rules.
- Define transactional persistence schema and recovery.
- Define bounded CLI and opt-in loop behavior.
- Prove no guardrail, sandbox, approval, audit, or web boundary changes.

Exit: approved design with file inventory, threat model, failure matrix, test
map, operations, and rollback.

## Gate 1 — End-to-end dry-run foundation

Implement test-first:

```text
proposal
→ authorization
→ collector
→ observation
→ graph
→ asset-bound correlation
→ deterministic persistence
→ delta
```

Exit: save→reload→rerun→delta tests pass; repeated cycles are idempotent; all
denials/errors are structured; no blanket exception suppression exists.

## Gate 2 — Bounded command

Add one dry-run-first command with explicit targets. Do not add a default
continuous loop.

Exit: help and offline smoke tests pass, unsupported modes remain absent, and
full Python 3.12/security/package/CI/CodeQL gates pass.

## Deferred gates

- separately authenticated out-of-band signer;
- independently administered external anchor;
- browser evidence UI;
- scheduler, alerting, soak testing, and operations;
- multi-user or higher-trust deployment.

See [`control/ROADMAP.md`](control/ROADMAP.md) for the authoritative roadmap and
binary exit criteria.
