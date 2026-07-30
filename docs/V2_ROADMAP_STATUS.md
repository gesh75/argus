# Argus V2 Roadmap Status

> **Status: experimental scaffolding, explicitly gated and unsupported.**
> The canonical active roadmap is [`control/ROADMAP.md`](control/ROADMAP.md).

**Last reconciled:** 2026-07-30

## Binding status

Argus 1.0 uses Path A: supervised V1 is the release candidate. V2 remains
importable for isolated development, but `ContinuousRunner` requires explicit
`experimental=True`, no supported CLI command exposes it, and no unattended or
scheduled operation is approved.

## Verified scaffold inventory

| Area | Classification | Release evidence |
|---|---|---|
| EvidenceGraph | Implemented but not release-grade | NetworkX graph and proof tags exist; path identity is random |
| Specialized-agent framework | Scaffold only | base authorization hook exists; Host, AD, and Web agents propose nothing |
| Recon agent | Scaffold only | initial proposal has no explicit target |
| ContinuousRunner | Implemented but not integrated | targetless proposals are skipped; broad exceptions are suppressed; no collector lifecycle |
| CorrelationAgent | Implemented but incorrect for operational use | globally combines categories instead of asset-bound relationships |
| DeltaAgent | Scaffold only | set delta exists; closed-path lifecycle is not demonstrated |
| Graph persistence | Scaffold only | direct JSON overwrite; no schema, lock, checksum, atomic durability, strict recovery, or typed timestamp restoration |
| V2 UI | Documentation only | no interactive evidence/path product |

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
→ transactional persistence
→ truthful new / changed / closed delta
```

It must pass save→reload→rerun→delta tests, be idempotent, expose only a bounded
dry-run-first command, and remain opt-in. Until that binary gate passes, V2 is
not operational, autonomous, continuous, production-ready, regulated-ready, or
safe to leave running.
