# Argus V2 — Complete Feature Documentation

**Extensive explanation of every major feature with diagrams.**

---

## 1. 7-Layer Fail-Closed Guardrail (The Sacred Core)

```mermaid
flowchart LR
    A[Agent Proposal] --> B[1. Scope Guard]
    B --> C[2. Tool Firewall]
    C --> D[3. Arg Hygiene]
    D --> E[4. Budget / Time]
    E --> F[5. HMAC + Anchor Audit]
    F --> G[6. Output Sanitizer]
    G --> H{Authorized?}
    H -- No --> I[Deny + Audit Log]
    H -- Yes --> J[Execute in Sandbox]
```

**Why it exists**  
Autonomy without a hard reference monitor is dangerous near regulated systems. Every single action is re-authorized. Ambiguity always equals denial. This is the reason Argus can be left running as a continuous sensor.

---

## 2. Evidence Graph

Central shared knowledge plane used by all agents.

- Nodes = Observations (network, host, AD, web, exposure, segmentation, ai-service, path)
- Edges = causal / chaining relationships
- Every attack path carries a mandatory proof tag: `observed` or `theoretical`

This is the primary defense against LLM hallucination.

---

## 3. Specialized Multi-Agent System

| Agent              | Responsibility                                   | Under Guardrail |
|--------------------|--------------------------------------------------|-----------------|
| ReconAgent         | Network scanning, segmentation, shadow-AI        | Yes             |
| HostAgent          | Linux & Windows read-only audits                 | Yes             |
| ADAgent            | Anonymous LDAP / identity surface                | Yes             |
| WebAgent           | Web / API surface discovery                      | Yes             |
| CorrelationAgent   | Builds multi-step attack paths from the graph    | Yes             |
| DeltaAgent         | Continuous mode change detection                 | Yes             |

---

## 4. Continuous / Delta Mode

```mermaid
sequenceDiagram
    participant CS as ContinuousSensor
    participant GR as Guardrail
    participant EG as EvidenceGraph

    loop Every interval
        CS->>GR: authorize proposed actions
        GR-->>CS: allowed / denied + audit
        CS->>EG: write new Observations
        CS->>CS: compute delta vs previous graph
        CS->>CS: emit new_paths / closed_paths
    end
```

Turns Argus from a one-shot scanner into a true continuous self-defense sensor for the gesh75 fabric.

---

## 5. Proof Annotation Discipline

Every attack path must be tagged:

- **observed** → every link is backed by collected evidence
- **theoretical** → plausible but not yet demonstrated

This single rule is the antidote to hallucinated findings.

---

## 6. Privacy Options

- Claude (cloud) for non-sensitive work
- Local Ollama for PHI / regulated networks
- Fully offline heuristic engine as fallback

---

## 7. Tamper-Evident Audit

HMAC-SHA256 chained log + optional external WORM anchor.  
The entire history can be verified with `argus audit`.

---

## Design Principle (Never Broken)

> **The agent proposes. The Guardrail disposes.**

This is what makes Argus safe enough to be the continuous eyes of the gesh75 Network AI Defender Fabric.
