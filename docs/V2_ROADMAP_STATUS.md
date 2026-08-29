# Argus V2 Roadmap Status

> **Status: experimental, explicitly gated and unsupported.**
> The canonical active roadmap is [`control/ROADMAP.md`](control/ROADMAP.md).

**Last reconciled:** 2026-08-29

## Binding status

Argus 1.0 uses Path A: supervised V1 is the release candidate. V2 remains
importable for isolated development, but `ContinuousRunner` requires explicit
`experimental=True`, no supported CLI command exposes it, and no unattended or
scheduled operation is approved.

## Verified scaffold inventory

| Area | Classification | Release evidence |
|---|---|---|
| EvidenceGraph | Implemented but not release-grade | NetworkX graph and proof tags exist; path identity is deterministic |
| Specialized-agent framework | Operational inside the experimental gate | `run_authorized` collects and records; Host, AD, and Web propose from evidence and are idempotent |
| Recon agent | Operational inside the experimental gate | initial proposal uses operator-supplied targets |
| ContinuousRunner | Implemented but not integrated | targetless proposals are skipped; broad exception suppression was removed and collector failures propagate; closed-path reports land on `DeltaReport` |
| CorrelationAgent | Asset-bound under the experimental gate | paths require a shared target |
| DeltaAgent | Operational inside the experimental gate | set delta plus `close_node` closed-path lifecycle |
| Graph persistence | Atomic, schema-versioned, checksummed JSON | temp + `os.replace`; checksum mismatch loads empty |
| V2 UI | Operator console in the App Builder workspace | lab-sim is fixture-backed and labeled; not a live packet source |
| DOM fixture inventory | Landed as pytest contract | `tests/test_dom_suite.py`; Playwright live-page execution remains LATER |

## Re-entry gate

The next V2 milestone must complete, in one bounded increment:

```text
typed proposal
→ explicit operator targets
→ guardrail authorization
→ existing collector execution
→ normalized observations
→ EvidenceGraph update
→ asset-bound correlation
→ deterministic path identity
→ delta (new / changed / closed)
→ durable graph persistence
```

That increment already exists as experimental code. Remaining before any
supported continuous command: independently administered WORM storage, a
supported CLI contract, and an operator-facing runbook.

## Non-goals carried forward

- Unattended 24/7 sensing
- Model-generated shell commands
- Weakening scope, tool, approval, or sandbox boundaries
- Claiming the local JSON file is WORM
