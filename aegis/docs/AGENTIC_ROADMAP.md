# ECP Aegis — Agentic Evolution Roadmap

Turns Aegis from an automated scanner framework into an **agentic AI pentester** that
reasons, chains, and adapts — without breaking the read-only / fail-closed contract that
makes it safe in a HIPAA/clinical network.

## Design principle
> The agent **proposes**, the guardrail **disposes**. Every action an LLM (or chaining
> engine) wants still flows through the existing 7-layer fail-closed guardrail. Autonomy is
> bounded by scope + tool firewall + budget + audit. New offensive capability is read-only
> *inference over observed evidence*; the only code that emits packets beyond read-only recon
> is the PoC runner, hard-gated to the `--arm` flag **and** the isolated lab network.

## Modules

| # | Module | Package | Posture | Status |
|---|--------|---------|---------|--------|
| 1 | Web / API recon | `recon/web.py` | read-only HTTP GET/HEAD | ✅ |
| 4 | Shadow-AI discovery | `recon/shadow_ai.py` | read-only banner/port match | ✅ |
| 5 | Segmentation validator | `recon/segmentation.py` | read-only reachability inference | ✅ |
| 2 | Credential **exposure** | `recon/cred_exposure.py` | read-only (detect, never collect) | ✅ |
| 3 | Chaining / reasoning engine | `agent/chains.py` | read-only inference | ✅ |
| 3b | Agentic planner loop | `agent/planner.py` | read-only, per-step guardrail auth | ✅ |
| PoC | Lab-only PoC verifier | `agent/poc_runner.py` | armed + lab-net ONLY | ✅ |

## Posture decisions (locked)
- **Read-only everywhere** except the PoC runner.
- **Credential modules detect EXPOSURE, never exfiltrate the secret** — the value is
  redacted by the Layer-7 sanitizer; findings record the *path*, not the credential.
- **PoC runner** refuses to run unless: (a) tool armed via `--arm poc`, and (b) the target
  is inside the declared lab network (`AEGIS_LAB_NET`), never the live/clinical scope.
- New `Observation.kind` values: `exposure`, `ai-service`, `segmentation`.

## Evidence → reasoning model
Collectors emit `Observation`s into a shared evidence set. The chaining engine
(`agent/chains.py`) runs deterministic decision-trees over that set to derive multi-step
attack paths, each annotated `proof: observed | theoretical`. The planner loop
(`agent/planner.py`) uses the same evidence to choose the next read-only collector to run,
re-planning until budget/depth/no-new-info — every chosen action re-authorized by the
guardrail.
