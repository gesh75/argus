# Argus — Recommended Next Steps

Historical hardening record for Argus. The active, evidence-gated roadmap is
[`../../docs/control/ROADMAP.md`](../../docs/control/ROADMAP.md). Argus currently supports
only supervised, explicitly authorized isolated-lab V1 assessment; it is not approved for
regulated, production, unattended, or network-exposed operation.

Legend: ✅ done in this pass · 🔭 tracked as a GitHub issue.

---

## P0 — Supply-chain & CI (the biggest process hole)

### ✅ 1. Security CI pipeline (`.github/workflows/ci.yml`)
The repo previously had **zero CI** — for a tool that ships offensive capability and a
`--sandbox local` host-exec path, that was the highest-leverage gap. Added blocking gates:
- **pytest** — the Python 3.12 hash-locked suite is enforced on every PR. Current counts live
  in `docs/control/STATUS.json`, not in this historical milestone description.
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
The merged child-environment fix stopped the key leaking into tool subprocesses, but the
**orchestrator process still holds the key** while it coordinates collectors. The remaining
work is a separately authenticated out-of-band signer with explicit availability, failure,
recovery, operations, and rollback semantics. It is tracked in GitHub issue #4.

**✅ Short-term landed:** `AuditLog` now **fails closed on a weak audit key** (`MIN_AUDIT_KEY_LEN
= 32`) — a placeholder/short key can no longer sign a "tamper-evident" chain (`guardrail.py`).
**🔭 Remaining:** the full out-of-band signer process (orchestrator never holds the key).

> *Best practice:* "the agent never touches the signing keys" (ROE Gate, reference-monitor /
> Anderson 1972); "the key sits outside the log volume so an attacker who can write the log
> can't read or rotate the key" (`bernstein` audit-log operations doc).

### ✅ 5. Transactional local consistency anchor
`AuditLog` durably mirrors the chain tip `{seq, tip, ts}` to a strict local **anchor file**
after every entry (`anchor.py`); `argus audit` classifies missing, stale, ahead, divergent,
and malformed states. This ordinary JSON file is not itself external or WORM and cannot
resist an attacker who controls both the log and anchor. A separately authenticated,
independently administered external anchor remains future work.

> *Best practice:* "HMAC alone does not defend against a compromised app — layer append-only
> storage and external anchoring on top." — Tracehold; SystemsHardening audit-logging
> architecture (CloudTrail-style log-file validation).

### ✅ 6. Risk-tiered approval gate for `--sandbox local` / `--arm`
Both high-risk modes now require a **parameter-bound, fail-closed approval token** (`approval.py`):
an HMAC over `(canonical-modes, canonical-sorted-targets, expiry)` keyed by the audit key.
`--sandbox local` requires a `local`-scoped token; `--arm` (exploit-capable tools) requires an
`arm`-scoped token in any sandbox; using both requires a token authorizing both. Mint with
`aegis approve <targets> [--mode local] [--mode arm] [--ttl N]`; pass via
`--approval`/`ARGUS_APPROVAL_TOKEN`. A token cannot be replayed against different targets/modes
or after expiry, and wildcard grants are impossible (every token names its exact targets +
modes). Dry-runs need no token (they execute nothing). The banner alone is gone — no token, no run.

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
**Remaining:** P1.4 full out-of-band signer process and P1.5 independently administered
WORM integration. The local JSON consistency anchor is not a remote-object adapter.

## Suggested sequencing (remaining)

Use the binary gates in `docs/control/ROADMAP.md`: close the supervised V1 release candidate,
then separately design the out-of-band signer and a bounded operational V2 foundation. An
independently administered external anchor remains a later higher-trust deployment gate.

_Tracking issues are linked from each 🔭 item once opened._
