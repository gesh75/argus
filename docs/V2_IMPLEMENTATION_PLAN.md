# Phased Implementation Plan — Argus Defender Fabric V2

> **Status: roadmap.** Checked items may be scaffolding or documentation only. The continuous
> V2 service is not production-ready and is not approved for unattended or 24/7 operation.

## Phase 0 — Foundation (this branch)
- [x] Create branch `feature/argus-defender-fabric-v2`
- [x] EvidenceGraph core scaffold
- [x] Multi-agent skeleton under existing Guardrail
- [ ] Continuous mode design + CLI entrypoint
- [ ] Updated architecture docs + animated page
- [ ] Branding cleanup notes

## Phase 1 — Intelligence
- Expand deterministic chains into graph-based reasoning
- LLM hypothesis generation (structured output) still forced through Guardrail
- Specialized agents (Recon / Host / AD / Web / Correlation)

## Phase 2 — UI
- React + Tailwind + Cytoscape.js attack-path graph
- Live WebSocket evidence stream
- Session history + multi-operator support

## Phase 3 — Production Hardening
- Out-of-band HMAC signer process
- Real WORM anchor (S3 Object Lock / KMS)
- Continuous scheduler + delta reporting
- SARIF + compliance mappings

## Phase 4 — Fabric Integration
- Native hooks for netlog-ai, multivendor lab, Aegis validator
