# Argus V2 Experimental Feature Inventory

> This is a claim-classified inventory. “Exists in source” does not mean
> integrated, operational, or supported.

## Reused operational V1 controls

- Fail-closed scope, tool, argument, budget, time, audit, and output controls.
- Docker sandbox by default and exact approval for the local exception.
- Network, host, AD, and web collectors.
- Optional Claude, local Ollama, and offline heuristic analysis.
- Phase 2A transactional audit log and local non-WORM consistency anchor.

These controls are operational in supervised V1. Their existence does not
complete the V2 lifecycle.

## Experimental V2 modules

| Module | What exists | What is missing |
|---|---|---|
| `evidence.py` | NetworkX graph, observations, proof tags | deterministic identity, asset model, release-grade persistence |
| `agents/base.py` | proposal interface and authorization call | collector execution and observation recording |
| `agents/recon.py` | one initial proposal | explicit targets and normalized collector adapter |
| `agents/host.py`, `ad.py`, `web.py` | class skeletons | proposals and execution lifecycle |
| `agents/correlation.py` | category-based theoretical paths | asset relationships, dedupe, deterministic IDs |
| `agents/delta.py` | node-set subtraction | truthful path lifecycle and durable baseline |
| `continuous.py` | gated cycle/loop scaffold | supported CLI, error contract, integration, safe scheduling |
| `persistence.py` | direct JSON save/load | schema, lock, atomic replace, checksum, strict decode, corruption recovery |

## Explicit non-features

- no supported continuous command;
- no unattended or 24/7 service;
- no production or regulated readiness;
- no interactive V2 evidence/path UI;
- no out-of-band signer;
- no external/WORM anchor;
- no demonstrated closed-path lifecycle;
- no claim that local Ollama alone makes regulated data handling compliant.

The complete next milestone is specified in
[`control/ROADMAP.md`](control/ROADMAP.md).
