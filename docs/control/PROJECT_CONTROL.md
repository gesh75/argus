# Argus Project Control

## Control snapshot

| Field | Verified value |
|---|---|
| Repository | `gesh75/argus` |
| Canonical local path | `/Users/georgigaydarov/Projects/ecp-aegis-lab` |
| Release merge on remote `main` | `b75af239c441204699114ce34970e37b394b3c21` |
| Current `main` | `025492456d4e3ca8363d7210abd43d605373b663` (PR #18 squash-merge) |
| Delivered branch | `feat/control-refresh-dom-and-scope` |
| Pull request | this increment; records PR #18, lands overlap deny, starts DOM suite |
| Branch source snapshot | Recorded in [`STATUS.json`](STATUS.json) |
| Worktree | One canonical writer; competing work preserved per [`AGENT_HANDOFF.md`](AGENT_HANDOFF.md) |
| Lifecycle | Post-#18 control refresh and Layer-1 overlap fix |
| Maturity | Release candidate for supervised defensive assessment; alpha runtime maturity |
| Release target | Argus 1.0 supervised defensive assessment release candidate |
| Active phase | `NEXT` — scope overlap deny, squash-merge CI, DOM fixture inventory |
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
- Out-of-band HMAC signer via `argus signer` (PR #18). In-process remains the
  isolated-lab default when `ARGUS_SIGNER_SOCKET` is unset.
- Experimental V2 proposal→collect→persist path. No supported continuous CLI.

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
| Out-of-band HMAC signer | Operational with in-process fallback | `signer.py`; `UnixSocketSigner`; `argus signer --socket`; issue #4 | Supported when `ARGUS_SIGNER_SOCKET` is set; in-process remains the isolated-lab default |
| V2 `BaseAgent.run_authorized()` lifecycle | Operational inside the experimental gate | Authorizes, then collects, then records Observations | Experimental; not a supported CLI product |
| V2 `ReconAgent` | Operational inside the experimental gate | Proposes `nmap` with operator-supplied targets; idempotent after network evidence | Experimental |
| V2 host, AD, and web specialized agents | Operational inside the experimental gate | `propose()` fills targets from evidence and stops once that kind exists | Experimental |
| V2 `ContinuousRunner` | Implemented but not integrated, now explicitly gated | Skips targetless proposals, propagates collector failures, and has no supported CLI entry | Experimental and unsupported |
| V2 EvidenceGraph | Implemented but not release-grade | In-memory NetworkX graph with deterministic path identifiers | Experimental |
| V2 correlation | Asset-bound under the experimental gate | Nodes must share a target before a path is emitted | Experimental |
| V2 graph persistence | Atomic, schema-versioned, checksummed JSON | Temp file + `os.replace`; checksum mismatch loads empty | Experimental; not WORM |
| V2 delta/closed-path lifecycle | Operational inside the experimental gate | `close_node` + delta/continuous report closed path identifiers | Experimental |
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
- PR #18 squash-merged as `025492456d4e3ca8363d7210abd43d605373b663`:
  Unix-socket HMAC signer and bounded operational V2 agents.
- Layer-1 overlap deny and packed-integer IPv4 refusal (this increment).
- DOM fixture inventory and static-console contract (this increment).

## Priority gaps

### P0

No unresolved P0 blocker exists for the supervised V1 release candidate.
`main` CI is red after the PR #18 squash-merge because control-docs topology
required a two-parent merge. This increment restores one-parent squash
acceptance.

### P1

- Independently administered external/WORM anchoring before any higher-trust
  deployment claim. Issue #4 (signer process) is closed by PR #18.
- Keep V2 continuous mode experimental until a supported CLI contract exists.

### P2

- Playwright execution of the DOM fixture inventory against a live localhost
  console. Source/ASGI/static contract tests are in this increment.
- CI package-build and wheel-install smoke gate.
- Event-level audit idempotency for uncertain commit recovery.
- Cross-platform audit-writer design if Windows controller support is required.

## Repository and security state

- Release pull request: PR #17, merged.
- Signer / V2 foundation: PR #18, squash-merged.
- Open issues at start of this increment: issue #4 only (closes with this PR).
- Open CodeQL alerts after PR #18: none (CodeQL run 32844334313 passed).
- `main` CI after PR #18: failed (run 32844334226) on squash-merge topology.
- Local Python 3.12 hash-locked collection recorded in STATUS.json: 315.
- Final evidence is recorded in [`STATUS.json`](STATUS.json)
  and [`CHANGELOG.md`](CHANGELOG.md).

## Next exact action

Land this branch. Close issue #4. Supercede draft PRs #19, #20, and #21.
Do not enable unattended continuous mode or weaken scope, approval, or
sandbox boundaries. Playwright DOM execution is the next UI-focused gate.
