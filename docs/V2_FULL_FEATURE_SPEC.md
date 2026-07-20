# Argus V2 Full Feature Specification

**Best-in-class free AI defensive intelligence tool — Continuous Self-Defense Sensor for the gesh75 Network AI Defender Fabric.**

## Core Philosophy
> The agent proposes. The Guardrail disposes.

## Features Implemented

### Safety
- 7-layer fail-closed Guardrail (Scope, Tool Firewall, Arg Hygiene, Budget, HMAC+Anchor, Output Sanitizer)
- Read-only by default
- Triple-gated PoC only for isolated lab
- HMAC-SHA256 chained audit log

### Intelligence Plane
- EvidenceGraph (NetworkX) with Observation nodes and proof-tagged paths
- Specialized Agents: Recon, Host, AD, Web, Correlation, Delta
- CorrelationAgent derives multi-step paths from existing evidence only
- DeltaAgent computes what is new / closed between runs

### Continuous Mode
- ContinuousRunner with interval + max-runs
- JSON graph persistence between cycles
- Delta reports

### Domains Covered
Network · Linux Host · Windows/WinRM · AD/LDAP · Web/API · Shadow-AI · Segmentation · Credential-exposure paths

### AI Options
Claude · Local Ollama · Fully offline heuristic

### UI
- FastAPI web console
- Animated architecture pages (v1 + v2)
- Future: React + React Flow attack-path graph

### Lab & Isolation
Isolated Docker lab + verify-isolation.sh

## What Still Makes It Best-in-Class
Safety model that commercial tools often lack, free and open, designed for continuous authorized self-defense near regulated systems.
