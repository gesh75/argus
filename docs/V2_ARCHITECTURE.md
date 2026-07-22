# Argus V2 — Continuous Self-Defense Sensor Fabric

> **Status: experimental architecture/scaffolding.** This document describes the V2 target
> state, not current production behavior. Argus is not approved for unattended, production,
> regulated, or 24/7 operation.

**Status:** Implementation started on branch `feature/argus-defender-fabric-v2`  
**Principle (inviolable):** The agent proposes. The Guardrail disposes.

## Elevated Purpose

The target architecture is a **Continuous Authorized Self-Defense Sensor** for the gesh75
Network AI Defender Fabric. That target has not yet been achieved.

## High-Level Architecture

```mermaid
flowchart TB
    subgraph Operator
        CLI[CLI]
        UI[Real-time UI<br/>React + Cytoscape]
    end

    subgraph Guardrail[7-Layer Fail-Closed Guardrail]
        G1[Scope] --> G2[Tool Firewall] --> G3[Arg Hygiene]
        G3 --> G4[Budget] --> G5[HMAC + Anchor] --> G6[Sanitizer]
    end

    subgraph Agents[Specialized Agents]
        RA[Recon Agent]
        HA[Host Agent]
        ADA[AD/Identity Agent]
        WA[Web/API Agent]
        CA[Correlation Agent]
        DA[Delta / Continuous Agent]
    end

    EG[(Evidence Graph<br/>NetworkX / Shared Store)]

    CLI & UI --> Guardrail
    Guardrail --> Agents
    Agents --> EG
    EG --> CA
    CA --> Guardrail
    DA --> Guardrail
```

## Evidence Graph Model
Every observation is a node. Attack paths are edges with proof tags (`observed` | `theoretical`).

## Continuous Mode
Scheduled runs produce a delta graph: new paths, closed paths, changed confidence.

## Safety Contract
All agents still call `Guardrail.authorize()` before any collector runs.  
No agent can ever bypass the 7 layers.
