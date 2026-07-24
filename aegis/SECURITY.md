# Argus — Security Posture (STRICT)

Aegis is an offensive-capable tool operated against a **healthcare (HIPAA/PHI)** network.
It is built to be strict by default. This document is the contract.

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
- Lab targets run on an `--internal` Docker network with **no route to the host LAN or
  internet** (proven by `scripts/verify-isolation.sh`).
- Tool execution is **argv-only** (never `shell=True`); shell metacharacters are rejected.
- Production guidance: run offensive workers on a **separate disposable host** (two-node).

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
- **PHI-safe AI:** use the **local Ollama** provider for anything touching live systems;
  cloud Claude is reserved for offline report-writing. No raw host data leaves the machine
  when the local provider is selected.

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
- A Phase 1 writer cannot verify V2 signatures and must never open a log containing V2.
- See `docs/PHASE2A_AUDIT_OPERATIONS.md` for deployment, recovery, and rollback.

## 7. Budgets & fail-safes
- Wall-clock + token + dollar ceilings on a monotonic ledger; breach kills the run.
- Tools that are missing are surfaced (`tool unavailable`) — never a silent no-op.
- Everything fails **closed**: ambiguity is denial.

## Operator checklist (before any live run)
- [ ] Written authorization + CIDR scope + exclusion list on file
- [ ] `scope-policy.yaml allowed_cidrs` matches the authorized scope exactly
- [ ] `PENTEST_AUDIT_HMAC_KEY` set to a real secret (not the demo value)
- [ ] `ANTHROPIC_API_KEY` rotated if ever exposed; or use local Ollama for PHI systems
- [ ] Dedicated read-only audit account; WinRM over HTTPS; SSH keys
- [ ] Maintenance window coordinated for any host touching clinical systems
