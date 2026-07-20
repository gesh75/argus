# Argus V2 Safety Contract (Inviolable)

This document is the binding safety contract for the Continuous Self-Defense Sensor.

## Core Invariant

> **The agent proposes. The Guardrail disposes.**

No specialized agent, LLM, or human operator may execute a tool call that has not first been authorized by the 7-layer fail-closed Guardrail.

## Non-Negotiable Rules

1. Every tool invocation must call `Guardrail.authorize()` (or the host equivalent).
2. Fail-closed is absolute — ambiguity is denial.
3. Credentials and PHI are never written to the audit log in the clear.
4. The PoC verifier remains triple-gated (armed + lab-net + confirm-isolated).
5. Continuous mode does not relax any safety layer.
6. Evidence Graph nodes carry mandatory proof tags (`observed` | `theoretical`).

## Operator Checklist (before any live use)

- [ ] Written authorization + CIDR scope + exclusion list on file
- [ ] `PENTEST_AUDIT_HMAC_KEY` set to a strong secret
- [ ] Scope policy matches the authorized range exactly
- [ ] Prefer local Ollama for any system that may contain PHI
- [ ] Dedicated read-only audit accounts only

Violating this contract voids the safety claims of the system.
