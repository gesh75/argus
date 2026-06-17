# ECP Aegis — Build & Test Log

Complete record of what was built and how it was validated. Companion to `README.md`
(usage), `SECURITY.md` (posture), and the animated `/architecture` page (overview).

**Status:** ✅ 39/39 tests passing · all modules validated live in the sandbox lab.
**Stack:** Python 3.14 · FastAPI · Docker (Apple Silicon, native arm64) · Anthropic SDK / Ollama.

---

## 1. What Aegis does (in one paragraph)
An authorized, **sandbox-first**, AI-driven penetration-testing platform for ECP (healthcare /
HIPAA). It discovers security gaps across the **network**, **Linux/Windows hosts**, and
**Active Directory**, strictly **read-only**, behind a **7-layer fail-closed guardrail**, with
**tamper-evident HMAC audit**, and turns findings into **platform-specific step-by-step
mitigations** via a **switchable AI engine** (cloud Claude · local Gemma/Ollama · offline heuristic).

---

## 2. Modules built (package: `aegis/aegis/`)

| File | Responsibility |
|---|---|
| `config.py` | Loads/validates `scope-policy.yaml` (immutable `Policy`); anchors audit path to repo root |
| `guardrail.py` | **7-layer guardrail**: scope canonicalization, tool/command firewall, arg hygiene, budget, HMAC-chained audit, output sanitizer; `authorize()` (network) + `authorize_host()` (credentialed) |
| `tools.py` | **16 read-only network tools** across **9 profiles**; nmap/nuclei/whatweb/sslscan parsers (defusedxml) |
| `sandbox.py` | `DockerSandbox` (argv-only `docker exec`, OS timeout) + `DryRunSandbox` |
| `ai_analyzer.py` | Cost-aware 2-pass AI (triage→correlate); 3 providers; Ollama JSON-schema enforcement; offline heuristic (CVE/SMB/SNMP/TLS/privesc/config/AD rules) |
| `mitigations.py` | Platform playbooks: Meraki/Juniper/Arista/Cisco · Windows-SMB/AD/privesc · Linux-privesc/SSH/Samba · Apache/PHP/TLS — HIPAA-framed |
| `orchestrator.py` | Network scan orchestration (profile → plan → guardrail → sandbox → parse → AI), tool-unavailable surfacer |
| `reporting.py` | CSV/MD/JSON into ECP ticket format + step-by-step playbook section + `collapse_errors()` |
| `cli.py` / `__main__.py` | `aegis scan · host · ad · audit · verify` |
| `web.py` | FastAPI console: `/`, `/architecture`, `/api/{policy,models,scan,host,ad}` |
| `static/index.html` | Polished GUI with scan-type tabs (network/host-linux/host-windows/AD) |
| `static/architecture.html` | Animated architecture document |
| **`host/audits.py`** | 12 read-only **Linux/SSH** checks; `host-linux` / `host-linux-quick` profiles |
| **`host/parsers.py`** | SUID→GTFOBins, NOPASSWD sudo, weak sshd, world-writable → Observations |
| **`host/runner.py`** | `HostOrchestrator` — SSH collection via sandbox helper, reuses AI analyzer |
| **`host/windows.py`** | 12 read-only **Windows/WinRM** PowerShell checks; `host-windows` profiles |
| **`host/win_parsers.py`** | SMB signing, AlwaysInstallElevated, unquoted service, WDigest, UAC, LLMNR, RDP-NLA, LAPS |
| **`host/winrm_collector.py`** | `WinRMCollector` (HTTPS/5986 + cert validation **default**), `DryRunWinRM`, `WinHostOrchestrator` |
| **`host/win_fixtures.py`** | `FixtureWinRM` + vulnerable-Windows fixture — full Windows pipeline with no Windows host |
| **`host/ad.py`** | AD/LDAP anonymous-enumeration (`ADOrchestrator`): RootDSE, anon bind, user enum |

---

## 3. Sandbox lab (`targets/`)

| Target | IP | Purpose |
|---|---|---|
| `juiceshop` | 172.30.0.10 | modern web/API |
| `dvwa` | 172.30.0.11 | classic web (SQLi/XSS) |
| `samba` | 172.30.0.12 | SMB service |
| **`linuxhost`** | 172.30.0.20 | **misconfigured Linux SSH host** (SUID rootbash, NOPASSWD sudo, weak sshd, world-writable, Lynis) |
| **`openldap`** | 172.30.0.21 | **anonymous-bind LDAP** + 3 seeded users (`dc=ecp,dc=lab`) |
| `attacker` | — | Kali tool box (network scans) |
| `sshhelper` | — | Debian SSH/LDAP client (host+AD audits; Kali-mirror-independent) |

All on an `internal: true` Docker network → **no route to host LAN or internet** (proven by
`scripts/verify-isolation.sh`). Windows can't run as a container on macOS/arm → the
**FixtureWinRM** path covers the Windows pipeline; a real Windows VM exercises live WinRM.

---

## 4. Coverage & profiles

- **Network (9 profiles):** `default · discovery · network · web · tls · ad-smb · snmp · vuln · full`
  → nmap, masscan, fping, nbtscan, whatweb, wafw00f, nikto, sslscan, nuclei, enum4linux-ng,
  smbmap, ldapsearch, onesixtyone, snmpwalk, snmp-check.
- **Host · Linux:** `host-linux · host-linux-quick` (SUID/SGID, sudo, sshd, world-writable, cron, sockets, Lynis).
- **Host · Windows:** `host-windows · host-windows-quick` (SMB signing, AlwaysInstallElevated,
  unquoted services, WDigest, UAC, LLMNR, RDP-NLA, Defender, LAPS, local admins).
- **AD:** `ad-ldap` (anonymous bind, RootDSE, user enumeration).

---

## 5. Test suite — 39 tests, all passing

Run: `PENTEST_AUDIT_HMAC_KEY=test python -m pytest -q`

### `test_guardrail.py` (21) — scope, firewall, audit
IP canonicalization (decimal/hex/octal), out-of-scope + decimal-obfuscated denial, broad-CIDR
denial, hostname/file-input/NSE-script/shell-metachar/no-target denial, per-tool flags
(`ldapsearch -x` allowed vs `nmap --script` denied), URL host extraction, binary-name-with-dot
not flagged, denied-tool, clean-scan authorized, **HMAC chain valid→tampered**.

### `test_heuristic.py` (4) — offline analysis
SNMP default community, SMB guest share, SMB user enum, **every finding has platform + steps**.

### `test_host.py` (6) — Linux host audit
SUID GTFOBins flagged, NOPASSWD sudo flagged, weak sshd flagged, `authorize_host` in-scope OK /
out-of-scope denied / unknown-check denied.

### `test_winad.py` (8) — Windows + AD
Win SMB-signing/AlwaysInstallElevated/WDigest parsers, **WinRM HTTPS+cert-validation default**,
AD anonymous-users + RootDSE parsers, Windows check authorized, AD unknown-check denied.

---

## 6. Live validations (in the sandbox)

| Scan | Command | Result |
|---|---|---|
| Network (full) | `aegis scan .11 .12 --profile full` | 5 findings, audit ✅, no errors |
| Linux host | `aegis host 172.30.0.20` | **2 Critical** (NOPASSWD sudo, SUID shell) + 3 High + 2 Medium, $0.045 |
| AD/LDAP | `aegis ad 172.30.0.21` | Anonymous bind (High) + RootDSE (Medium), 3 users leaked, $0.025 |
| Windows fixture | `aegis host .30 --os windows --fixture` | SMBv1, AlwaysInstallElevated, unquoted svc, WDigest, UAC, LLMNR, RDP-NLA (20 findings via Claude) |
| Isolation | `verify-isolation.sh` | lab peer reachable · internet **blocked** · no default route ✅ |
| Audit tamper | `aegis audit` (after edit) | clean=VALID, tampered=**TAMPERED** ✅ |
| AI matrix | same scan × 3 brains | Claude $0.034 · Gemma $0 · heuristic $0 — all audit ✅, all with mitigation steps |

---

## 7. Bugs found & fixed during build (notable)

1. **`_NOISE` regex matched every line** — an all-optional group silently discarded *all*
   output from 9 `_lines`-based tools. Rewrote to match only separator lines; added ANSI/`\r`
   strip. (This was hiding real scan data.)
2. **`testssl.sh` binary name denied as a hostname** — the dotted binary name tripped the scope
   guard, blocking the tool entirely. Fixed by skipping `argv[0]` in the host rescan.
3. **Global `-x` denylist blocked benign `ldapsearch -x`** — moved to **per-tool** dangerous-flag
   denylists (`nmap --script` still denied).
4. **Port-number-as-IP false positive** (`--top-ports 200` read as a decimal IP) — only treat
   integers > 65535 as packed-IP candidates.
5. **HMAC chain fork under web concurrency** — serialized scans with a lock.
6. **nmap `3000/tcp ppp` mislabel** — corrected common dev ports to `http(dev)`.
7. **Silent missing tools** — added a `tool unavailable (exit 127)` surfacer; revealed nuclei
   wasn't installed (now baked into the image).
8. **Heuristic over-collapse** — detail-specific finding titles so distinct config/privesc
   findings don't merge.

---

## 8. Resilience decisions

- **Kali apt mirror outages** (recurrent 503) broke the attacker rebuild. Created a Debian-based
  `sshhelper` container (SSH + LDAP clients) so host/AD audits don't depend on the Kali mirror.
- **No Windows kernel on Mac/arm** → `FixtureWinRM` covers the Windows pipeline; real WinRM is a
  config-only switch to a Windows VM.

---

## 9. How to run

```bash
cd aegis && python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
export PENTEST_AUDIT_HMAC_KEY=$(openssl rand -hex 32)
# optional AI: export ANTHROPIC_API_KEY=...   or   export AEGIS_OLLAMA_MODEL=qwen2.5:7b-instruct

uvicorn aegis.web:app --host 127.0.0.1 --port 8800      # GUI + /architecture
# or CLI:
python -m aegis scan 172.30.0.10 172.30.0.11 --profile full
python -m aegis host 172.30.0.20                        # Linux
python -m aegis host 172.30.0.30 --os windows --fixture # Windows (no host needed)
python -m aegis ad   172.30.0.21                        # AD/LDAP
python -m aegis audit                                   # verify HMAC chain
```

---

## 11. Agentic evolution (2026-06-16) — 6 new modules

Turned the scanner framework into an **agentic pentester** (reason · chain · adapt) while
keeping the read-only / fail-closed contract. See `docs/AGENTIC_ROADMAP.md`.

| # | Module | File | Posture | Tests |
|---|--------|------|---------|-------|
| 1 | Web / API recon | `recon/web.py` | read-only (GET/HEAD, curated paths) | `test_webrecon.py` (8) |
| 4 | Shadow-AI discovery | `recon/shadow_ai.py` | read-only port/banner match | `test_recon_modules.py` (4) |
| 5 | Segmentation validator | `recon/segmentation.py` | read-only reachability inference | `test_recon_modules.py` (4) |
| 2 | Credential **exposure** | `recon/cred_exposure.py` | read-only (detect, never collect) | `test_agent.py` |
| 3 | Chaining / reasoning | `agent/chains.py` | read-only inference (`proof: observed\|theoretical`) | `test_agent.py` |
| 3b | Agentic planner loop | `agent/planner.py` | read-only, per-step guardrail auth | `test_agent.py` |
| PoC | Lab-only PoC verifier | `agent/poc_runner.py` + `poc_probes.py` | **armed + lab-net + isolation-attest** (3 gates) | `test_agent.py` |

**Design principle:** *the agent proposes, the guardrail disposes* — every planner action is
re-authorized by the existing 7-layer guardrail, so autonomy can never escape scope, arm an
exploit, or hit a denied tool. New `Observation.kind`s: `exposure`, `ai-service`, `segmentation`.

**Integration:** `Orchestrator.run` now auto-enriches every scan with shadow-AI +
segmentation + cred-exposure passes and appends proof-annotated attack chains to the
correlation. New CLI verbs: `aegis web`, `aegis agent`. Web recon reaches `internal:` lab
nets via a `SandboxTransport` (curl through the attacker container).

**PoC gates (fail-closed, all three required):** `--arm poc` · target inside `AEGIS_LAB_NET`
(default 172.30.0.0/24) · `AEGIS_POC_CONFIRM_ISOLATED=1`. Probes are connect/read-only from a
closed catalog — never payloads or writes. Never runnable against live/clinical scope.

### Live validations (sandbox, 2026-06-16)
| Run | Command | Result |
|---|---|---|
| Web recon (live, via sandbox) | `aegis web 172.30.0.11` | found PROTECTED Apache `/server-status` (403) — real |
| Agentic loop (NetBIOS pivot) | `aegis agent 172.30.0.11 --seed discovery` | discovery → auto-pivot `ad-smb`, 32 obs, each step authorized |
| Agentic loop (port-driven pivot) | `aegis agent 172.30.0.11 --seed network` | network → auto-pivot `web`, 37 obs |
| Enrichment + chains | `Orchestrator.run` integration test | shadow-AI + segmentation surfaced, chain paths with `proof` |
| PoC gates | `test_agent.py` | refuses unarmed / out-of-lab / no-isolation / uncatalogued ✅ |

### Test suite — now **72 tests** (was 39)
`test_guardrail.py` 21 · `test_agent.py` 15 · `test_winad.py` 8 · `test_webrecon.py` 8 ·
`test_recon_modules.py` 8 · `test_host.py` 6 · `test_heuristic.py` 4 ·
`test_integration_agentic.py` 2. Verified deterministic across repeated runs.

---

## 10. Outstanding (optional next)
- Real Windows/AD live target (cloud VM or UTM Windows-on-ARM) for end-to-end WinRM.
- PingCastle / BloodHound integration for full AD attack-path scoring.
- Production audit hardening (separate HMAC signer, OS-append-only/WORM log, two-node worker isolation).

> ⚠️ Before any live (non-lab) use: written authorization + CIDR scope + clinical/EHR/PACS
> exclusions; rotate the Anthropic key; change the demo HMAC key. See `SECURITY.md`.
