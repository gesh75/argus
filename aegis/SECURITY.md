# ECP Aegis — Security Posture (STRICT)

Aegis is an offensive-capable tool operated against a **healthcare (HIPAA/PHI)** network.
It is built to be strict by default. This document is the contract.

## 1. Authorization (hard gate)
- **No live (non-lab) scan without:** written authorization from ECP leadership, a defined
  CIDR scope, and an explicit exclusion list (clinical/EHR/PACS/PHI-bearing systems).
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
- Every authorize / exec / deny is written to an **HMAC-SHA256 chained** log.
- `aegis audit` replays and verifies the chain; any edit/reorder/truncation → `TAMPERED`.
- `PENTEST_AUDIT_HMAC_KEY` is **required** — Aegis refuses to run unaudited.
- Production hardening (documented, not yet wired): move the HMAC key to a separate signer
  process; make the log OS-append-only (`chattr +a` / WORM) under a different uid; anchor
  the chain head externally.

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
