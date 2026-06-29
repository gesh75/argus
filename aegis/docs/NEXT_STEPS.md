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

### ✅ 3. Pin dependencies + generate an SBOM
`requirements.txt` remains the human-edited input; `requirements.lock`
(`pip-compile --generate-hashes`) is the fully hash-pinned tree CI installs with
`pip install --require-hashes`. CI now emits a **CycloneDX SBOM** (`argus-sbom.cdx.json`)
as an artifact, and the `pip-audit` job is **blocking** against the locked tree (currently
0 known CVEs). Regenerate the lock after editing `requirements.txt` with
`pip-compile --generate-hashes -o requirements.lock requirements.txt`.

---

## P1 — Audit-integrity & authorization, to best-of-breed

### 🔭 4. Move the HMAC signing key out-of-band from the tool runner
The merged fix stopped the key leaking into *child* tools, but the **orchestrator process
still holds the key** while it spawns offensive tools. Short term: enforce `SECURITY.md`'s
own guidance in code — refuse to start if the audit key path is owned by the same uid as the
runner or has loose perms (fail-to-start, don't bypass). Longer term: a tiny out-of-band
signer the orchestrator talks to but never holds the key for.

**✅ Short-term landed:** `AuditLog` now **fails closed on a weak audit key** (`MIN_AUDIT_KEY_LEN
= 32`) — a placeholder/short key can no longer sign a "tamper-evident" chain (`guardrail.py`).
**🔭 Remaining:** the full out-of-band signer process (orchestrator never holds the key).

> *Best practice:* "the agent never touches the signing keys" (ROE Gate, reference-monitor /
> Anderson 1972); "the key sits outside the log volume so an attacker who can write the log
> can't read or rotate the key" (`bernstein` audit-log operations doc).

### ✅ 5. External anchoring + WORM for the audit chain
`AuditLog` mirrors the chain tip `{seq, tip, ts}` to an out-of-band **anchor file** after every
entry (`anchor.py`); `aegis audit` **cross-checks** the live chain against it, so a full-log
rewrite (even with a leaked key) is detectable. Enabled by setting `audit.anchor_path` in the
policy. **🔭 Operational:** point that path at a real write-once store (S3 Object Lock compliance
mode / KMS-signed object / WORM volume) owned by a different uid — the file format is ready.

> *Best practice:* "HMAC alone does not defend against a compromised app — layer append-only
> storage and external anchoring on top." — Tracehold; SystemsHardening audit-logging
> architecture (CloudTrail-style log-file validation).

### ✅ 6. Risk-tiered approval gate for `--sandbox local`
`--sandbox local` now requires a **parameter-bound, fail-closed approval token** (`approval.py`):
an HMAC over `(mode, canonical-sorted-targets, expiry)` keyed by the audit key. Mint with
`aegis approve local <targets> [--ttl N]`; pass via `--approval`/`ARGUS_APPROVAL_TOKEN`. A token
cannot be replayed against different targets or after expiry, and wildcard grants are impossible
(every token names its targets). The banner alone is gone — no token, no run.

> *Best practice:* "system-prompt guardrails don't guard anything… agents take risky actions
> 23.9% of the time even with explicit safety instructions" (ROE Gate); "bind approval to the
> exact action… fail closed when approval validation fails" (OWASP AI Agent Security Cheat
> Sheet); avoid wildcard trust grants (AWS Well-Architected, agentic-AI lens).

### ✅ 7. Network-layer egress control for the local path
`aegis egress-rules` generates a deterministic **nftables egress allow-list** from the scope
policy (`egress.py`): default-drop, allow only the policy's in-scope CIDRs (denied ranges carved
out first). Apply it with `nft -f` on the disposable recon host before `--sandbox local`, so a
guardrail bug or HTTP redirect can't reach an out-of-scope host — the packet never leaves the box.

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

### ✅ 10. Pre-flight "is this production?" checks
Before a `--sandbox local` run, `preflight.check()` (`preflight.py`) surfaces warnings to stderr
— public-IP targets on the un-isolated path, an over-broad allow-list (> a /24), `resolve_dns`
enabled — so a human catches the misconfiguration at setup time rather than after packets fly.

> *Best practice:* "catch human error before execution starts, rather than relying on runtime
> controls to fix avoidable setup mistakes." — Aikido pre-flight checks.

---

## Status
**Done:** P0 (CI + supply-chain), P1.5/6/7, P2.8/9/10, and the P1.4 short-term key-strength gate.
**Remaining:** P1.4 full out-of-band signer process, and the P1.5 production WORM target
(the in-repo anchor format + cross-check are ready; pointing it at S3 Object Lock / KMS is an
operational step).

## Suggested sequencing (remaining)
`P1.4 out-of-band signer` → wire `audit.anchor_path` to a real WORM store in production.

_Tracking issues are linked from each 🔭 item once opened._
