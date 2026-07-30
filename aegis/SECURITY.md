# Argus — Security Posture (STRICT)

Argus is an offensive-capable tool intended only for supervised defensive assessment in an
explicitly authorized, separately verified lab. It is not approved for healthcare, regulated,
production, unattended, or network-exposed deployment. This document is the contract.

## 1. Authorization (hard gate)
- **No live (non-lab) scan without:** written authorization from leadership, a defined
  CIDR scope, and an explicit exclusion list (sensitive/regulated systems/PHI-bearing systems).
- The scope guard is **default-deny**: any target that is unparseable, obfuscated
  (decimal/hex/octal), a hostname (no DNS), a CIDR broader than /24, or outside the
  allow-list is refused **before** anything executes.

## 2. Read-only by construction
- No exploitation, credential spraying, writes, persistence, or DoS.
- Network tools are curated read-only; credentialed host checks are **audit/enumeration
  mode only** (PrivescCheck `-Audit`, Lynis, `sudo -l`, anonymous LDAP).
- Exploit-capable tools (mitm6, responder, Metasploit modules) are **armed-only** and require
  an explicit signed `--arm` token — never reachable by an LLM prompt.

## 3. Isolation
- Lab targets are configured on an `--internal` Docker network. Independently verify the
  effective host/runtime routing before use; `scripts/verify-isolation.sh` is a diagnostic,
  not proof against every route or runtime configuration.
- Tool execution is **argv-only** (never `shell=True`); shell metacharacters are rejected.
- Production operation is unsupported. A future authorized evaluation should use a separate
  disposable worker and must pass a separately approved deployment review.

## 4. Least privilege & strict transport
- Use a **dedicated read-only audit account**, not a domain admin.
- **WinRM defaults to HTTPS (5986) with server-cert validation.** HTTP/5985 and
  cert-skip are opt-in only (`--winrm-http` / `--winrm-insecure`) and are discouraged.
- **SSH:** prefer key-based auth; password auth is for the lab only. Avoid passwords in
  process args in production (use keys / a secrets store).

## 5. Credentials & data handling
- **Credentials are never written to the audit log** — only the check key + target are logged.
- The **output sanitizer** (Layer 7) redacts secrets and PHI (passwords, SSN, MRN) from all
  captured output before it is stored or shown.
- Local Ollama avoids sending model prompts to a cloud provider; the offline heuristic sends
  no model prompt at all. Neither choice alone makes a workflow PHI-safe or compliant.

## 6. Tamper-evident audit
- Phase 2A uses strict V1/V2 replay and a domain-separated, sequence-bound V2 HMAC.
- Each outer operation takes one in-process lock and one POSIX `flock`, replays the
  complete history, appends a complete record, and `fsync`s before returning.
- `argus audit` is read-only and classifies log and anchor states without constructing
  the operational guardrail. It never prints records, event values, or HMAC tips.
- `PENTEST_AUDIT_HMAC_KEY` is **required** — Aegis refuses to run unaudited.
- Audit and optional anchor parents must be pre-provisioned, owned by the Argus uid,
  and not group/world writable; final files are owner-only `0600`.
- The local JSON anchor is a consistency check, not an external WORM control.
- The orchestrator process still holds the HMAC key. Child tool environments are scrubbed,
  but issue #4's out-of-band signer remains required for a stronger trust boundary.
- A Phase 1 writer cannot verify V2 signatures and must never open a log containing V2.
- See `docs/PHASE2A_AUDIT_OPERATIONS.md` for deployment, recovery, and rollback.

## 7. Budgets & fail-safes
- Wall-clock + token + dollar ceilings on a monotonic ledger; breach kills the run.
- Tools that are missing are surfaced (`tool unavailable`) — never a silent no-op.
- Everything fails **closed**: ambiguity is denial.

## Operator checklist (future separately authorized evaluation)
- [ ] Written authorization + CIDR scope + exclusion list on file
- [ ] `scope-policy.yaml allowed_cidrs` matches the authorized scope exactly
- [ ] `PENTEST_AUDIT_HMAC_KEY` set to a real secret (not the demo value)
- [ ] `ANTHROPIC_API_KEY` rotated if ever exposed; or use local Ollama for PHI systems
- [ ] Dedicated read-only audit account; WinRM over HTTPS; SSH keys
- [ ] Maintenance window coordinated for any host touching clinical systems
