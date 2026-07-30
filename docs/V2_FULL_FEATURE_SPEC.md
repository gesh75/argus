# Argus V2 Target Feature Specification

> **Status: deferred target specification.** Current V2 source is incomplete
> experimental scaffolding. The supported release is supervised V1.

## Inviolable rule

> The agent proposes. The Guardrail disposes.

Every future V2 action must have explicit operator targets and pass the existing
guardrail immediately before the existing collector executes.

## Required bounded foundation

1. Typed proposal and result models.
2. Explicit operator targets; no model-generated target or shell command.
3. Existing collector/orchestrator reuse.
4. One normalized observation adapter with structured denial/error results.
5. EvidenceGraph update with stable asset identity.
6. Asset-bound correlation with deterministic path identity and deduplication.
7. Versioned, locked, atomic, checksummed persistence with strict decoding,
   corruption refusal, typed timestamp restoration, and explicit recovery.
8. Truthful `new`, `changed`, and `closed` delta semantics.
9. Bounded dry-run-first CLI; any loop remains separate and opt-in.
10. End-to-end save→reload→rerun→delta and idempotence tests.

## Explicit exclusions

The bounded foundation does not include unattended scheduling, production or
regulated deployment, multi-user service, network exposure, remediation,
external signing, or an external anchor. Those require separate threat models
and authorization.

The canonical scope and exit gate are maintained in
[`control/ROADMAP.md`](control/ROADMAP.md). The current source classification is
maintained in [`control/PROJECT_CONTROL.md`](control/PROJECT_CONTROL.md).
