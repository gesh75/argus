# ECP Aegis — AI-Driven Internal Pentest Orchestrator

Authorized, **sandbox-first** AI pentest tool for ECP (healthcare / HIPAA). Read-only recon by
default, a hardened 7-layer guardrail, cost-aware two-pass AI analysis, and reports that drop
straight into ECP's remediation tracker. CLI **and** web GUI.

> ⚠️ Authorized internal security testing only. Run against the isolated lab (`../targets`) first.
> Live use requires written authorization, a defined CIDR scope, and the clinical/EHR/PACS exclusion list.

## Install
```bash
cd aegis
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
export PENTEST_AUDIT_HMAC_KEY=$(openssl rand -hex 32)   # required — refuses to run unaudited
```
Optional AI: `export ANTHROPIC_API_KEY=...` (without it, a deterministic heuristic analyzer runs offline).

## CLI
```bash
python -m aegis verify                                   # print loaded policy
python -m aegis scan 172.30.0.10 172.30.0.11 --dry-run   # policy test, no execution
python -m aegis scan 172.30.0.10                         # live recon against the lab
python -m aegis audit                                    # verify HMAC audit chain
```
Out-of-scope / obfuscated targets are refused before anything executes:
```
$ python -m aegis scan 10.0.0.5 --dry-run
REFUSED target 10.0.0.5: scope: 10.0.0.5/32 outside allowed scope
$ python -m aegis scan 167772165 --dry-run     # decimal-encoded 10.0.0.5
REFUSED target 167772165: scope: 10.0.0.5/32 outside allowed scope
```

## Web GUI
```bash
uvicorn aegis.web:app --host 127.0.0.1 --port 8800
# open http://127.0.0.1:8800
```
Launch scans, view KPIs (findings, high/crit, AI $ cost, audit status), attack paths, PHI exposure,
and a sortable findings table — all behind the same guardrail.

## Architecture
```
cli.py / web.py ──> orchestrator.py ──> guardrail.py (7 layers, fail-closed)
                                  │              └─ audit.ndjson (HMAC-chained)
                                  ├──> sandbox.py (docker exec, argv-only, OS timeout)
                                  ├──> tools.py   (read-only recon + parsers, defusedxml)
                                  └──> ai_analyzer.py (Haiku triage → Sonnet correlate, offline fallback)
                                                 └──> reporting.py (CSV/MD/JSON → ECP tickets)
```

## Guardrail (Phantom 7-layer, hardened by adversarial review)
1. **Scope guard** — targets canonicalized (decimal/hex/octal/leading-zero) then `subnet_of` the
   allowed `/24`; CIDRs must be ≥/24 with no host bits; **default-deny** on anything unparseable.
2. **Tool firewall** — `default: deny`; dangerous flags (`--script`, `-iL`, `-x`, `--config`, `@file`)
   and armed-only tools (mitm6/responder/exploit) blocked unless `--arm`.
3. **Sandbox** — argv-only exec (never a shell) in the `--internal` lab network; OS-level timeouts.
4–5. **Budget** — wall-clock + token + $ ceilings, monotonic ledger.
6. **HMAC audit** — SHA-256 chained, tamper-evident (`aegis audit` verifies).
7. **Output sanitizer** — redacts secrets/PHI (passwords, SSN, MRN) before findings are stored.

Tested: `python -m pytest -q` (16 tests prove the bypass holes are closed).

## Production hardening TODO (documented, not yet wired)
- Move the HMAC key to a separate signer process; make `audit.ndjson` OS-append-only (`chattr +a`/WORM)
  owned by a different uid; anchor the chain head externally.
- Two-node isolation: run offensive workers on a separate disposable Docker host.
- Curated NSE allowlist if `nmap --script` recon is needed (currently armed-only).
