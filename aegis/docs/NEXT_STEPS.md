# Argus — Recommended Next Steps

Prioritized, best-practice-grounded roadmap for hardening the **process** around Argus
(an agentic, read-only pentest orchestrator operated against a HIPAA/PHI network). Each
item cites the external guidance it is grounded in. The guardrail architecture itself is
already strong and maps cleanly onto the reference-monitor pattern these sources describe —
so this list is about closing **process / operational** gaps, not redesigning what works.

Legend: ✅ done in this pass · 🔭 tracked as a GitHub issue.

---

## P0 — Supply-chain & CI (the biggest process hole)

### ✅ 1. Security CI pipeline (`.github/workflows/ci.yml`)
The repo previously had **zero CI** — for a tool that ships offensive capability and a
`--sandbox local` host-exec path, that was the highest-leverage gap. Added blocking gates:
- **pytest** — the 81-test suite is now enforced on every PR.
- **Bandit (medium+)** — AST SAST for the `subprocess` / `shell` / partial-path classes
  this codebase lives in.
- **pip-audit** — dependency CVEs (informational until deps are pinned, see P0.3).
- **detect-secrets** — secret scan (informational).

> *Best practice:* the 4-gate Python DevSecOps pattern (SAST + secret-scan + AST + dep-audit)
> is the consensus baseline; CI is "the authoritative gate" because pre-commit can be skipped
> with `--no-verify`. — `thunderstornX/secure-python-pipeline-template`,
> `developmentseed/action-python-security-auditing`.

### ✅ 2. Workflow supply-chain hardening
Every GitHub Action is **pinned to a full commit SHA** (never `@v4`/`@main`); jobs use
least-privilege `permissions: contents: read`; no long-lived secrets.

> *Best practice:* OpenSSF post-`tj-actions`/`reviewdog` guide — mutable tags were the root
> cause of those 2025 supply-chain compromises. — OpenSSF Maintainers' Guide (2025).

### 🔭 3. Pin dependencies + generate an SBOM
`requirements.txt` still uses `>=` ranges. Move to a hash-pinned lockfile
(`pip-compile --generate-hashes` or `uv lock`), emit a Syft SBOM as a CI artifact, then flip
the `pip-audit` job from informational to **blocking**. For a security tool, reproducible
builds are table stakes.

---

## P1 — Audit-integrity & authorization, to best-of-breed

### 🔭 4. Move the HMAC signing key out-of-band from the tool runner
The merged fix stopped the key leaking into *child* tools, but the **orchestrator process
still holds the key** while it spawns offensive tools. Short term: enforce `SECURITY.md`'s
own guidance in code — refuse to start if the audit key path is owned by the same uid as the
runner or has loose perms (fail-to-start, don't bypass). Longer term: a tiny out-of-band
signer the orchestrator talks to but never holds the key for.

> *Best practice:* "the agent never touches the signing keys" (ROE Gate, reference-monitor /
> Anderson 1972); "the key sits outside the log volume so an attacker who can write the log
> can't read or rotate the key" (`bernstein` audit-log operations doc).

### 🔭 5. External anchoring + WORM for the audit chain
HMAC chaining alone does not survive a key compromise. On a timer, write the latest chain
tip to a destination the runner can't rewrite (S3 Object Lock compliance mode, or a
KMS-signed artifact) and have the verifier cross-check it.

> *Best practice:* "HMAC alone does not defend against a compromised app — layer append-only
> storage and external anchoring on top." — Tracehold; SystemsHardening audit-logging
> architecture (CloudTrail-style log-file validation).

### 🔭 6. Risk-tiered approval gate for `--sandbox local` / `--arm`
Replace the current warning banner with a real, parameter-bound acknowledgment: bind
approval to the exact action (actor + tool + normalized target + expiry), fail closed on
missing approval, and forbid wildcard grants for the un-isolated local path.

> *Best practice:* "system-prompt guardrails don't guard anything… agents take risky actions
> 23.9% of the time even with explicit safety instructions" (ROE Gate); "bind approval to the
> exact action… fail closed when approval validation fails" (OWASP AI Agent Security Cheat
> Sheet); avoid wildcard trust grants (AWS Well-Architected, agentic-AI lens).

### 🔭 7. Network-layer egress control for the local path
`--sandbox local` now relies *solely* on the app-layer scope guard (the container boundary is
gone). Best-of-breed pentest agents enforce scope at the **network/DNS layer** too, so a
guardrail bug or HTTP redirect can't reach an out-of-scope host. Even a documented
`nftables` egress-allowlist helper (matching the project's own two-node disposable-host
guidance) adds the missing second layer.

> *Best practice:* "we don't rely on prompts or humans for scope enforcement — we enforce at
> the network layer, intercepting HTTP and DNS" (Aikido); "exclusions beat authorizations;
> DNS failures are blocks" (IntegSec agentic-pentest proxy).

---

## P2 — Correctness & polish

### ✅ 8. Fix the orchestrator exit-code `127` conflation
`ExecResult` now carries a `tool_missing` flag set only when the sandbox *knows* a binary was
never launched. A tool that runs and genuinely exits 127 is no longer mislabeled
"not installed" — it parses and observes normally. DockerSandbox keeps its 127 heuristic
(`docker exec` can't distinguish), LocalSandbox flags only synthesized-missing. Covered by
new tests in `tests/test_sandbox.py`.

### ✅ 9. Centralize tool config + pre-commit
Added `aegis/pyproject.toml` (Bandit / Ruff / pytest config) and `.pre-commit-config.yaml`
mirroring the CI gates for shift-left feedback.

### 🔭 10. Pre-flight "is this production?" checks
Before a `--sandbox local` run, validate reachability and surface "this resembles production"
warnings early — "configuration mistakes are more likely than malicious behaviour." — Aikido
pre-flight checks.

---

## Suggested sequencing
`P0 (CI + pinning)` → `P1.6 approval gate + P2.8 127-fix (done)` → `P1.4/5 key isolation +
anchoring` → `P1.7 network egress` → `P2 polish`.

_Tracking issues are linked from each 🔭 item once opened._
