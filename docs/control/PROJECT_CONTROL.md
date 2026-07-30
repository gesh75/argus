# Argus Project Control

## Control snapshot

| Field | Verified value |
|---|---|
| Repository | `gesh75/argus` |
| Canonical local path | `/Users/georgigaydarov/Projects/ecp-aegis-lab` |
| Release merge on remote `main` | `b75af239c441204699114ce34970e37b394b3c21` |
| Delivered branch | `fix/argus-release-closeout` at `8f1fed7d88c821f926c332ea691f151c58d73dbd` |
| Pull request | [#17](https://github.com/gesh75/argus/pull/17), merged |
| Branch source snapshot | Recorded in [`STATUS.json`](STATUS.json) |
| Worktree | One canonical writer; competing work preserved per [`AGENT_HANDOFF.md`](AGENT_HANDOFF.md) |
| Lifecycle | Release closeout |
| Maturity | Release candidate for supervised defensive assessment; alpha runtime maturity |
| Release target | Argus 1.0 supervised defensive assessment release candidate |
| Active phase | `NOW` complete — Path A closeout delivered |
| Last verified | Recorded in [`STATUS.json`](STATUS.json) |

## Supported boundary

Supported:

- Python 3.12+ on a POSIX macOS/Linux controller.
- Supervised, explicitly authorized defensive assessment in a separately
  verified isolated lab.
- V1 CLI with deterministic scope, tool, argument, budget, time, audit, and
  output controls.
- Localhost-only FastAPI console. Server startup owns live-mode selection;
  request bodies cannot select armed or live execution.
- Docker sandbox by default. Host-local execution requires an exact,
  parameter-bound approval token and remains an operator-controlled exception.
- Transactional V1/V2 audit replay, V2 append, local anchor consistency, and
  read-only diagnostics under the Phase 2A POSIX assumptions.

Unsupported:

- unattended, scheduled, or 24/7 operation;
- V2 continuous mode as a supported product;
- production, regulated, or live-target deployment;
- network-exposed or multi-user service operation;
- a claim that the local JSON anchor is WORM or independently administered;
- Windows-hosted audit writing;
- model-generated shell commands or bypass of the guardrail;
- deployment performed by this release-closeout increment.

## Binding release decision

The release uses **Path A**. V1 is the supported product. V2 specialized-agent,
continuous-runner, evidence-graph, correlation, delta, and persistence modules
remain importable experimental code, but construction of the V2 continuous
runner now requires an explicit development-only opt-in. No CLI command exposes
continuous mode. The CLI, localhost console, repository README, roadmap, and
generated dashboard all state the same boundary.

See [`DECISIONS.md`](DECISIONS.md) for the decision record and binary re-entry
gate for a future V2 foundation.

## Claim-versus-code matrix

| Capability | Classification | Evidence | Release statement |
|---|---|---|---|
| Scope and target normalization | Operational and tested | `guardrail.py`; guardrail and Phase 1 regression tests | Supported V1 control |
| Tool firewall and argument hygiene | Operational and tested | `guardrail.py`; `tools.py`; guardrail tests | Supported V1 control |
| Docker sandbox | Operational and tested at the subprocess boundary | `sandbox.py`; sandbox tests | Default supported execution boundary; lab isolation still requires independent verification |
| Local sandbox | Operational and tested with compensating controls | `sandbox.py`; approval and sandbox tests | Exception only; exact approval token required |
| Approval token flow | Operational and tested | `approval.py`; Phase 1 tests | Exact modes, canonical targets, and expiry; no wildcard |
| Network, host, AD, and web collectors | Operational and tested with fixtures/mocks | collector modules and focused tests | Supervised V1 only |
| Direct HTTP redirect handling | Operational and tested | `recon/web.py`; all common 3xx regression cases | Redirects are recorded, never followed |
| Localhost web boundary | Operational and tested | `web.py`; streamed-body, peer, header, execution, and DOM tests | Localhost-only; live host/AD disabled unless server-enabled |
| AI analyzer | Operational with cloud, local, and heuristic providers | `ai_analyzer.py`; heuristic and integration tests | Optional analysis; model output is not authorization |
| V1 planner | Operational and tested | `agent/planner.py`; agent and integration tests | Operator-invoked bounded loop, not unattended autonomy |
| Report generation | Operational and tested through orchestrators | `reporting.py`; integration regressions | CSV, Markdown, and JSON output |
| Transactional audit replay and V2 append | Operational and tested | Phase 2A storage, anchor, CLI, filesystem, and multiprocessing tests | Supported on the documented POSIX controller boundary |
| Local JSON anchor | Operational consistency checkpoint | `anchor.py`; anchor tests | Not WORM and not an independent trust domain |
| Out-of-band HMAC signer | Explicitly deferred | GitHub issue #4 | Orchestrator still holds the signing key |
| V2 `BaseAgent.run_authorized()` lifecycle | Scaffold only | It authorizes but does not execute a collector or record observations | Unsupported |
| V2 `ReconAgent` | Scaffold only | Initial proposal has an empty target list | Unsupported |
| V2 host, AD, and web specialized agents | Scaffold only | `propose()` returns no proposals | Unsupported |
| V2 `ContinuousRunner` | Implemented but not integrated, now explicitly gated | Skips targetless proposals, propagates collector failures, and has no supported CLI entry | Experimental and unsupported |
| V2 EvidenceGraph | Implemented but not release-grade | In-memory NetworkX graph with random path identifiers | Experimental |
| V2 correlation | Implemented but incorrect for operational use | Combines global categories rather than asset-bound relationships | Experimental |
| V2 graph persistence | Scaffold only | Direct JSON overwrite; no schema, lock, checksum, atomic durability, or recovery contract | Experimental |
| V2 delta/closed-path lifecycle | Scaffold only | Set subtraction exists; no demonstrated operational closure lifecycle | Experimental |
| Continuous or 24/7 service | Stale/incorrect when claimed as current | No supported command, scheduler, durable lifecycle, or operational contract | Explicitly unsupported |
| Regulated-production readiness | Documentation aspiration only | No authenticated multi-user service, external signer, external anchor, or deployment evidence | Explicitly unsupported |

## Completed achievements

- Phase 1 safety freeze: fail-closed web, redirect, request-size, packaging,
  scope, approval, and execution boundaries.
- Phase 2A transactional audit hardening: strict V1/V2 replay, sequence-bound
  domain-separated V2 HMAC records, one-lock outer operations, durable local
  append/anchor boundaries, diagnostics, and explicit recovery.
- CodeQL workflow and four alert remediations.
- Repository-wide Copilot safety instructions.
- Release-closeout worktree reconciliation and evidence preservation.
- Explicit experimental gate and warnings for V2 continuous mode.
- Canonical control pack and deterministic dashboard.
- PR #17 merged with head-SHA protection as
  `b75af239c441204699114ce34970e37b394b3c21`; its one independent read-only
  review was resolved and post-merge CI/CodeQL passed.

## Priority gaps

### P0

No unresolved P0 blocker exists for the supervised V1 release candidate.
Every required release and post-merge gate passed.

### P1

- GitHub issue #4: move HMAC signing out of the orchestrator into a separately
  authenticated signer.
- Independently administered external/WORM anchoring before any higher-trust
  deployment claim.
- Complete one bounded V2 lifecycle before exposing any continuous command.

### P2

- Browser-executed DOM security test in addition to current source and ASGI
  coverage.
- CI package-build and wheel-install smoke gate.
- Event-level audit idempotency for uncertain commit recovery.
- Cross-platform audit-writer design if Windows controller support is required.

## Repository and security state

- Release pull request: PR #17, merged.
- Open issues at baseline: issue #4 only.
- Open CodeQL alerts after merge: none.
- Baseline main CI, CodeQL, Copilot setup, and Pages runs passed at
  `79cb27269333a34ae6dac42897f9b15e99e4f667`.
- Local Python 3.12 hash-locked baseline: 279 collected, 279 passed.
- Final release-closeout evidence is recorded in [`STATUS.json`](STATUS.json)
  and [`CHANGELOG.md`](CHANGELOG.md).
- Post-merge CI:
  [run 30523751828](https://github.com/gesh75/argus/actions/runs/30523751828),
  passed.
- Post-merge CodeQL:
  [run 30523751784](https://github.com/gesh75/argus/actions/runs/30523751784),
  passed.

## Next exact action

No additional repository action is authorized. `NOW` is complete. Begin a
`NEXT` item only from current `main`, on a fresh branch, after separate
authorization.
