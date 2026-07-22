# Argus V2 Roadmap Status — Best-in-Class Free AI Defensive Intelligence Tool

> **Status: roadmap and scaffold inventory, not production behavior.** “Complete” below means
> the scoped scaffold or document exists; it does not mean the V2 continuous service is
> integrated, operationally durable, or safe for production/regulated/24/7 deployment.

**Last updated:** 2026-07-20

## Goal
Long-term target: become a free, open-source continuous self-defense sensor with the controls
required for separately authorized production and regulated-network evaluation.

## Phase Status

### Phase 0 — Foundation (Complete)
- [x] EvidenceGraph with proof tags
- [x] ContinuousRunner skeleton
- [x] Specialized agent framework under Guardrail
- [x] Core V2 documentation

### Phase 1 — Intelligence (In Progress / Advanced)
- [x] CorrelationAgent that walks EvidenceGraph and emits multi-step paths
- [x] Observed vs theoretical proof discipline
- [ ] Deeper LLM-assisted hypothesis generation (still Guardrail-gated)
- [ ] BloodHound-style read-only AD path synthesis

### Phase 2 — Continuous Mode Hardening
- [x] ContinuousRunner with delta reporting
- [ ] Graph persistence between runs
- [ ] Scheduled execution + alerting on new critical paths
- [ ] History and trend views

### Phase 3 — UI (Next High Priority)
- [ ] Interactive attack-path graph (React + React Flow / Cytoscape)
- [ ] Live agent activity stream
- [ ] Delta timeline
- [ ] Evidence drill-down
- Current: Enhanced static architecture page exists

### Phase 4 — Production Hardening
- [ ] Out-of-band HMAC signer process
- [ ] Real WORM / external anchor
- [ ] Stronger sandbox isolation

### Phase 5 — Fabric Integration
- [ ] Native hooks for netlog-ai, multivendor lab, Aegis validator
- [ ] SIEM / ticketing emission for new critical paths

### Phase 6 — Remediation Loop
- [ ] Actionable remediation suggestions (still under Guardrail)
- [ ] Optional PR / ticket generation

## Design Principle (Never Broken)
> The agent proposes. The Guardrail disposes.

This is the unique advantage that allows Argus to be left running continuously.
