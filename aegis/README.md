<p align="center"><img src="docs/assets/hero.svg" alt="Argus — agentic AI penetration testing" width="100%"></p>

# Argus

> **Point it at an internal network. It reasons, chains, and adapts — read-only by default, behind a fail-closed guardrail.** An agentic AI pentester that turns raw recon into proof-annotated attack paths, strictly inside an authorized scope.

![tests](https://img.shields.io/badge/tests-134%20passing-brightgreen)
![python](https://img.shields.io/badge/python-3.12-3776ab)
![posture](https://img.shields.io/badge/posture-read--only%20%C2%B7%20fail--closed-2ea44f)
![audit](https://img.shields.io/badge/audit-HMAC%20chained-8a5cf6)
![ai](https://img.shields.io/badge/AI-Claude%20%C2%B7%20Ollama%20%C2%B7%20offline-e3b341)
![scope](https://img.shields.io/badge/scope-network%20%C2%B7%20host%20%C2%B7%20AD%20%C2%B7%20web-1f6feb)

Argus V1 is an alpha, supervised security-assessment pipeline built around deterministic authorization and sandboxed collectors. V2 agent, continuous, and evidence-graph modules are experimental scaffolding, not a production continuous service.

> **Deployment boundary:** the web console is localhost-only, ignores proxy identity headers, and defaults to server-enforced dry-run. Host and AD web execution are denied unless live mode is enabled in server startup configuration. Do not expose it as a network or multi-user service.

---

## Why it exists

If you have watched an "AI security tool" hallucinate a critical finding with no evidence, or refuse to run anywhere near production because it might break something — this is the antidote.

- **The agent proposes, the guardrail disposes.** Every step the planner chooses is re-authorized by the guardrail: scope, tool firewall, budget, audit. Autonomy can never escape the authorized CIDR, arm an exploit, or touch a denied tool — no matter what the model "reasons."
- **Read-only by default.** No exploitation, credential spraying, writes, or DoS. Credentialed checks use null/guest/audit-mode only. The one component that can emit beyond recon — the PoC verifier — is triple-gated to an isolated lab.
- **Evidence or it didn't happen.** Every attack path is tagged `proof: observed` (every link backed by collected evidence) or `proof: theoretical` (plausible, not yet demonstrated). No silent guesses.
- **Your data stays put.** Switchable AI brain: cloud Claude, local Ollama (PHI-safe, $0), or a fully offline heuristic engine that always works with no network.
- **Tamper-evident.** Every authorize / exec / deny is written to an HMAC-SHA256 chained audit log; `argus audit` replays and verifies the whole chain.

## How it works

```
targets ─▶ guardrail ─▶ sandbox ─▶ collectors ─▶ AI triage ─▶ chain reasoning ─▶ report
           (fail-       (internal  (network·host  (Haiku→      (observed |        (CSV·MD·
            closed)      Docker)    ·AD·web)        Sonnet)      theoretical)       JSON)
                 ▲                                                   │
                 └────────────── agentic re-plan loop ◀──────────────┘
                        observe → decide next action → AUTHORIZE → collect → repeat
```

The agent only ever proposes a profile to run next; the guardrail authorizes it before anything executes. That single rule is what makes autonomy safe in a sensitive network.

## Architecture

```mermaid
flowchart TD
    OP["🎛️ Operator Console — CLI + FastAPI GUI"] --> GR
    subgraph GR["🛡️ Guardrail — 7 layers, fail-closed"]
      direction LR
      G1[Scope guard] --> G2[Tool firewall] --> G3[Arg hygiene] --> G4[Budget/time] --> G5[HMAC audit] --> G6[Output sanitizer]
    end
    GR --> SB["📦 Sandbox — internal Docker net, argv-only exec"]
    SB --> CO["🔬 Collectors, read-only — network · Linux/SSH · Windows/WinRM · AD/LDAP · web"]
    CO --> EN["✨ Enrichment — shadow-AI · segmentation · cred-exposure"]
    EN --> AI["🧠 AI triage to correlation — Claude · Ollama · offline"]
    AI --> CH["🔗 Chaining engine — proof: observed or theoretical"]
    CH --> RP["📊 Report — CSV · Markdown · JSON"]
    AI -. re-plan .-> PL["🤖 Planner loop"]
    PL -. next action .-> GR
```

## The agentic loop

```mermaid
flowchart LR
    O["observe — evidence set"] --> D["decide — next read-only profile"]
    D --> A{"🛡️ guardrail authorize?"}
    A -- denied --> X["skip + audit"]
    A -- allowed --> C["collect in sandbox"]
    C --> R{"new evidence? budget? depth?"}
    R -- continue --> O
    R -- stop --> F["chain + report"]
    X --> R
```

## Capabilities

| Domain | What Argus does |
|---|---|
| 🌐 **Network** | 16 read-only tools across 9 profiles — nmap, masscan, nuclei, sslscan, whatweb, enum4linux-ng, smbmap, snmp, ldapsearch |
| 🐧 **Host · Linux** | credentialed SSH audit — SUID/GTFOBins, NOPASSWD sudo, weak sshd, world-writable, Lynis |
| 🪟 **Host · Windows** | WinRM audit — SMB signing, AlwaysInstallElevated, unquoted services, WDigest, UAC, LAPS |
| 🗂️ **Active Directory** | anonymous LDAP enumeration — RootDSE disclosure, null-bind, user enum |
| 🕸️ **Web / API** | curated read-only probe — `.env`, `.git`, actuator, Swagger/OpenAPI surface |
| 🧩 **Segmentation** | flags database / management / directory planes reachable from a user VLAN |
| 🤖 **Shadow-AI** | discovers ungoverned local LLMs/notebooks — Ollama, Jupyter, Gradio, vLLM, vector DBs |
| 🔑 **Credential exposure** | detects GPP cpassword, exposed secrets — reports the **path**, never the secret |
| 🔗 **Chain reasoning** | deterministic decision-trees derive multi-step attack paths with proof annotations |

## Why it's different

| | Typical "AI scanner" | **Argus** |
|---|---|---|
| Safety model | run, then hope | **fail-closed guardrail authorizes every action** |
| Autonomy | linear checklist | **agent re-plans from evidence, still guardrail-bounded** |
| Findings | isolated, often unverified | **chained attack paths, tagged observed/theoretical** |
| AI privacy | cloud-only | **Claude · local Ollama · fully offline** |
| Exploitation | active by default | **read-only; PoC is triple-gated to an isolated lab** |
| Auditability | logs, maybe | **HMAC-chained, tamper-evident, self-verifying** |

## Quickstart

```bash
cd aegis
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
export PENTEST_AUDIT_HMAC_KEY=$(openssl rand -hex 32)   # required — refuses to run unaudited
# optional AI: export ANTHROPIC_API_KEY=…   or   export AEGIS_OLLAMA_MODEL=qwen2.5:7b-instruct

# Web console + animated architecture page
uvicorn aegis.web:app --host 127.0.0.1 --port 8800      # http://127.0.0.1:8800

# Or the CLI
python -m aegis scan  172.30.0.10 172.30.0.11 --profile full   # network recon + AI
python -m aegis web   172.30.0.11                              # web/API recon
python -m aegis agent 172.30.0.11 --seed network              # agentic loop
python -m aegis host  172.30.0.20                             # Linux host audit
python -m aegis ad    172.30.0.21                            # AD/LDAP
python -m aegis audit                                       # verify the HMAC chain
```

Out-of-scope or obfuscated targets are refused before anything executes:

```
$ python -m aegis scan 10.0.0.5 --dry-run
REFUSED target 10.0.0.5: scope: 10.0.0.5/32 outside allowed scope
$ python -m aegis scan 167772165 --dry-run     # decimal-encoded 10.0.0.5
REFUSED target 167772165: scope: 10.0.0.5/32 outside allowed scope
```

## Security posture

> **Default posture:** V1 is sandbox-first and dry-run capable, but explicitly selected profiles and PoC paths can emit traffic or execute remote checks. Use only with written authorization, exact scope, separately verified isolation, and non-production credentials. See [`SECURITY.md`](SECURITY.md).

## Tests

Current Phase 1 collection: **134 tests** on Python 3.12. Older totals in `BUILD_AND_TEST_LOG.md` are retained as labeled historical snapshots.

```bash
PENTEST_AUDIT_HMAC_KEY=$(openssl rand -hex 32) python -m pytest -q
```

## Docs

- [`docs/AGENTIC_ROADMAP.md`](docs/AGENTIC_ROADMAP.md) — the agentic design and module map
- [`BUILD_AND_TEST_LOG.md`](BUILD_AND_TEST_LOG.md) — full build + live-validation record
- [`SECURITY.md`](SECURITY.md) — the strict posture contract
- `/architecture` — animated architecture page (served by the web console)

---

<p align="center"><sub>Argus · authorized internal security testing only · the agent proposes, the guardrail disposes</sub></p>
