# Argus full-repository architecture, security, and production-readiness audit

**Audit date:** 2026-07-22

**Repository:** `https://github.com/gesh75/argus`

**Audited revision:** `634e99f94b0da73a0a8770b6a6008bce15f2832e` (`origin/main`)

**Audit mode:** source review and safe local verification only; no product-code fixes

**Authoritative machine-readable findings:** `docs/ARGUS_AUDIT_FINDINGS.json`

## 1. Executive verdict

Argus is a credible defensive-security prototype with unusually thoughtful first-pass controls: literal-IPv4 default-deny scope checks, argv-only subprocess execution, a constrained tool registry, process-group timeouts, an environment allowlist for local execution, a hash-pinned Python lockfile, SHA-pinned GitHub Actions, and a strong body of guardrail tests. Those strengths are real and should be preserved.

It is **not production ready**. The current release should be treated as an **alpha/prototype for supervised use in a separately verified lab**. It is not suitable for unattended internal scanning, 24/7 operation, multi-user/network-exposed deployment, regulated environments, or production credential handling.

The audit found **1 Critical, 7 High, 12 Medium, and 4 Low findings**. The Critical issue is a confirmed scope escape in direct web reconnaissance: authorization covers the initial target, but Python's HTTP client follows redirects to a different destination without another guardrail decision. High-risk clusters are the unauthenticated live-control API, browser-side injection, unsafe SSH argument/credential handling, incomplete secret/PHI redaction, non-concurrent audit logging, misleading isolation checks, and evidence that overstates what was actually observed.

The largest documentation/code inconsistency is Argus V2's representation as an implemented continuous self-defense fabric. The V2 agent and evidence modules are mostly disconnected scaffolding: there is no continuous CLI/API entry point, proposed actions commonly have no executable targets, `BaseAgent.run_authorized()` authorizes but does not collect or persist evidence, and state persistence lacks the durability, concurrency, alerting, recovery, and lifecycle controls required for 24/7 operation.

### Suitability by use case

| Use case | Verdict | Conditions |
|---|---|---|
| Bundled lab | **Conditional only** | Verify isolation independently; do not rely on `scripts/verify-isolation.sh`; use a disposable host/VM and no real credentials. |
| Authorized internal testing | **Not yet** | Requires scope-safe redirects, hardened/authenticated control plane, reliable isolation, correct evidence semantics, and operational controls. |
| 24/7 operation | **No** | Continuous mode is scaffold-level and has no production scheduler, durable state, recovery, observability, or multi-instance safety. |
| Regulated production | **No** | Secret/PHI redaction, audit durability, access control, retention, privacy, and evidence provenance are insufficient. |

### Top five risks and first remediation phase

1. **ARGUS-001 — redirect-driven scope escape (Critical):** re-authorize every redirect hop and the final connected address; use a redirect-disabled transport by default.
2. **ARGUS-002 — unauthenticated live-control API (High):** bind to loopback by enforcement, add authentication/authorization and approval verification, separate read-only dry-run from live actions, and apply bounded request schemas.
3. **ARGUS-003 — DOM XSS in the console (High):** replace untrusted `innerHTML` rendering with text-node/DOM construction, sanitize structured output, and add a restrictive CSP.
4. **ARGUS-004 — SSH option injection and credential exposure (High):** validate usernames as data, insert an option terminator/use a library API, eliminate `sshpass -p`, and restore host-key verification.
5. **ARGUS-005 — incomplete secret/PHI control (High):** adopt structured field-aware redaction, cover headers/JSON/XML/multiline/encoded secrets, sanitize model output and errors, and add negative assertions that secrets never persist.

**Recommended Phase 1:** freeze claims and live exposure first. Disable direct redirects and unauthenticated live endpoints, remove unsafe SSH credential transport, replace the isolation verifier, and add regression tests for each confirmed bypass. In parallel, correct the README/V2 maturity claims. Do not add new collectors until these foundations are closed.

## 2. Audit scope and limitations

All **102 tracked files** at the audited revision were inventoried. Every meaningful Python source file, test, workflow, configuration, Dockerfile/Compose file, shell script, HTML/JavaScript file, and Markdown/roadmap file was inspected. Images and the demonstration video were inventoried but their media content was not security-audited; generated caches/build artifacts were excluded.

The audit traced source-to-sink behavior, compared documented claims with enforcing code and tests, ran tests on Python 3.12 and 3.14, built from source, installed from the hash lock in a fresh environment, ran lint/type/security/dependency/secret checks, validated Compose configuration, exercised CLI dry-runs, and used only temporary files and loopback listeners for adversarial regression probes.

No public IP, external network, production resource, live credential, exploitation path, or armed mode was used. The bundled lab was **not started** because the supplied isolation checker cannot prove the claimed boundary. Runtime behavior that depends on real Nmap/Nuclei/LDAP/SSH/WinRM targets, Docker packet routing, cloud LLM APIs, host firewalls, WORM storage, browser deployment topology, or long-running multi-process operation remains unverified.

**Unavailable tooling:** `shellcheck` was not installed. The normal `pip-audit` invocation crashed inside its temporary Python 3.13 environment; the scanner completed successfully with `--disable-pip`. No unavailable tool was installed into or persisted in the repository.

### Commands and results

| Check | Result |
|---|---|
| `python3 -m pytest -q` with a 32+ character synthetic audit key, Python 3.14.6 | **99 passed** in 1.54 s |
| Same suite, Python 3.12.12 in an existing development environment | **99 passed** in 1.39 s |
| Fresh venv + `pip install --require-hashes -r requirements.lock` + tests | **97 passed, 2 failed**; `networkx` is absent from the lock |
| Exact documented `PENTEST_AUDIT_HMAC_KEY=test python3 -m pytest -q` | **87 passed, 12 failed**; documented key violates the 32-character floor |
| Coverage | **54% total**; CLI, continuous, persistence, reporting, PoC probes, `__main__`, web UI, and Linux host runner have major or total gaps |
| `ruff check .` | **Failed: 27 errors** |
| `mypy aegis` | **Failed: 34 errors in 9 files** |
| Bandit 1.8.6, CI threshold (`-lll -iii`) | **Passed** |
| Bandit all severities | 6 Low findings, including swallowed exceptions, subprocess use, and unsafe-XML fallback |
| `pip-audit --disable-pip -r requirements.lock` | **No known vulnerabilities**; the normal local invocation crashed in its temporary Python 3.13 environment |
| `detect-secrets scan aegis targets` and whole-repository scan | **No candidate secrets** |
| `docker compose -f targets/docker-compose.yml config --quiet` | **Passed** |
| `python -m build` after removing runtime-generated output | **Built**, but as incomplete `aegis 0.0.0` with no dependencies, CLI entry point, static UI, policy, or Compose assets |
| Current GitHub Actions run for audited commit | **Failed** in pytest because of missing `networkx`; audit, Bandit, SBOM, and secret-scan jobs completed |
| Safe CLI in-scope dry-run | **Passed**, no execution |
| Safe CLI out-of-scope dry-run (`8.8.8.8`) | **Refused with exit 2** |
| Focused loopback/temp-file regression probes | Confirmed redirect follow, truncation acceptance, two-writer audit corruption, approval replay, and eight sanitizer misses |

## 3. Architecture map

| Module/path | Responsibility; inputs → outputs | Trust/security boundary and dependencies | Failure behavior, coverage, and coupling |
|---|---|---|---|
| `aegis/aegis/cli.py`, `__main__.py` | CLI parsing and dispatch → scan/host/AD/web/report actions | Operator input enters policy, approval, guardrail, sandbox, and orchestrators | Broad orchestration coupling; `__main__` untested; docs/key/profile drift; no continuous or PoC entry point |
| `config.py`, `targets/scope-policy.yaml` | YAML policy → typed-ish `Policy` object | Security configuration boundary; PyYAML, filesystem, environment | Missing schema/version/unknown-key validation; `strict=False` network parsing; config behavior partially covered |
| `guardrail.py` | Scope, tool, argument, budget, audit, sanitization | Primary authorization boundary | Good literal-IPv4 fail-closed tests; redirects, executable identity, concurrency, IPv6, host credentials, and structured redaction incomplete |
| `approval.py` | HMAC token over modes, target set, expiry | Operator approval boundary; reuses audit key | Canonical target binding is good; replay/context/policy binding and web enforcement are absent; unit coverage is narrow |
| `anchor.py` | Mirror sequence/tip to JSON path | Intended external integrity boundary | Plain non-atomic file, no authentication/locking/WORM integration; security depends entirely on operator storage |
| `sandbox.py` | Docker/local/dry-run argv execution → `ExecResult` | Process/network boundary; subprocess, Docker CLI, host PATH | No shell and good group timeout; unbounded output, PATH identity, resource limits, per-run isolation, and cancellation gaps |
| `tools.py` | Fixed tool/profile registry and parsers | Converts authorized profile to argv | Strong closed registry in the normal V1 path; metadata is unenforced; several active tools exceed read-only assumptions; parser robustness is thin |
| `orchestrator.py` | Plan → authorize → execute → parse → sanitize → AI | Central V1 execution pipeline | Continues through many nonzero/timeout cases; executes original rather than canonical target; no EvidenceGraph integration |
| `agent/planner.py` | Deterministic profile plans; optional ranking | AI ranking is advisory in V1 | Good separation from authorization; unknown profiles fall back; no true re-planning loop or evidence-driven stopping |
| `agents/base.py` and V2 agents | V2 action proposal abstractions | Intended agent/guardrail boundary | `run_authorized()` only authorizes; host/AD/web/delta agents are skeletal; no collector/persistence connection |
| `evidence.py` | Node/edge graph for observations/findings/paths | Evidence provenance boundary; NetworkX | Dependency missing from lock; caller-supplied/random IDs, weak dedupe, ordering-sensitive parent edges; only two focused tests |
| `agents/correlation.py`, `chains.py` | Convert evidence/findings into attack paths | Claims evidence-backed chaining | V2 creates duplicate random paths; V1 uses global substring co-occurrence and overstates cross-asset chains; adversarial topology tests absent |
| `agent/poc_runner.py`, `poc_probes.py` | Three-gate PoC verification → socket probes/results | Packet-emitting boundary | No CLI integration; environment-based lab attestation; direct host sockets; two probes claim protocol evidence from TCP reachability only |
| `continuous.py`, `persistence.py` | Repeated agents, prior graph load/save, deltas | Long-lived state and scheduling boundary | No entry point/locking/atomicity/schema/recovery/alerts/metrics; exceptions swallowed; proposal targets usually empty; little meaningful coverage |
| `recon/web.py` | Curated HTTP GET probes → observations | Untrusted network data; urllib or sandbox curl | Direct transport follows unvalidated redirects; errors collapse to status 0; limited body cap; fixture-heavy tests |
| `host/runner.py`, `host/audits.py` | SSH Linux checks → observations/findings | Credentials and remote-command boundary; sshpass/SSH/Docker | Username option injection, password argv exposure, host-key checks disabled, Lynis writes remotely; no direct runner coverage |
| `host/winrm_collector.py`, `win_audits.py` | WinRM/PowerShell checks → findings | Credentials/TLS/remote execution boundary; pywinrm | HTTPS verification defaults are strong; insecure HTTP/cert skip are opt-in but unapproved; broad exception fallback and limited live coverage |
| `host/ad.py` | LDAP catalog and parsing → AD findings | Credential/network/directory-data boundary; ldapsearch | Missing/nonzero tool outcomes can become silent empty results; unbounded subtree queries; fixture-dominant tests |
| `ai_analyzer.py` | Offline/Ollama/Anthropic triage and correlation | Untrusted scanner data crosses into model; untrusted model data returns | Prompts warn about untrusted input and provider fallback exists; weak schema/provenance, post-model sanitization, preflight budget, and failure audit |
| `reporting.py` | Findings/correlation/errors → JSON/CSV/Markdown | Persistent disclosure boundary | Fixed shared filenames, non-atomic writes, no CSV/Markdown formula/content defense, no per-run ownership; no focused tests |
| `web.py`, `static/index.html` | FastAPI synchronous control surface and console | Remote/browser/operator credential boundary | No auth/rate limit/CSRF/security headers/ownership; `innerHTML` XSS; process-only lock; web backend has limited route tests and frontend none |
| `targets/*`, `verify-isolation.sh` | Bundled target lab and attacker images | Container-to-host/LAN/internet boundary | Internal network/no socket/host mounts are strengths; images mutable, attacker overprivileged, no limits; verifier produces false assurance |
| `.github/workflows/ci.yml`, lock/config | Test, audit, Bandit, SBOM, secret scan, Pages | Supply-chain and release boundary | SHA-pinned actions/hash lock are strong; current CI fails; no lint/type/coverage/build/container scan/license/release gates; secret scan informational |
| `README.md`, `aegis/README.md`, `docs/*`, `NEXT_STEPS.md` | Product, operation, roadmap, and claims | Operator decision and authorization boundary | Test counts, maturity, isolation, audit-truncation, privacy, read-only, packaging, and naming claims conflict with behavior |

### Architectural conflicts, duplication, dead/legacy surfaces

- V1 uses `tools.Observation` and a linear `Orchestrator`; V2 introduces a separate `evidence.Observation`/NetworkX graph but the two paths are not integrated.
- `BaseAgent.run_authorized()` is described as the legal agent path but performs no execution or evidence update. Most V2 agents are proposal scaffolds; `continuous.py` has no public entry point.
- The package, command, policy variables, tickets, and comments remain `aegis`/`AEGIS_*` while product docs brand the project Argus; roadmap/test counts conflict across files.
- `tool_allowed` includes names not present in the registry, while `read_only` and `needs_root` registry metadata are never enforced.
- Pentagi notes are reference/legacy material, not an integrated subsystem, and include deployment practices inconsistent with Argus's current safety story.
- Direct web transport, host authorization, web `arm`, PoC functions, and V2 helpers do not all pass through the same complete approval/authorization/execution/evidence pipeline.

## 4. Repository scorecard

Scores are 0–100 and represent the audited revision, not the potential of the design.

| Category | Score | Evidence-based rationale |
|---|---:|---|
| Product completeness | 43 | V1 dry-run/collect/report works; V2 continuous/PoC/package paths are incomplete or disconnected. |
| Architecture | 48 | Strong intent around layered controls; duplicate V1/V2 models and alternate bypassing paths weaken coherence. |
| Code quality | 55 | Clear modules/type hints in many areas; Ruff 27 and mypy 34, broad exceptions, weak schemas. |
| Security guardrails | 58 | Good literal-IPv4 fail-closed core; redirect, canonical-execution, host, and direct-helper gaps are material. |
| Sandbox isolation | 44 | Internal Docker network/no socket/host mounts are positive; verifier invalid, long-lived privileged container and no bounds. |
| Authorization and approvals | 42 | Exact target/mode HMAC basics; replay/context binding and interface-wide enforcement absent. |
| Audit integrity | 35 | HMAC chaining/weak-key floor are useful; truncation, concurrency, durability and anchor semantics fail production needs. |
| AI-agent safety | 45 | Model cannot directly authorize V1 tools; schema, provenance, prompt-output and budget controls are weak. |
| Evidence correctness | 30 | Two graphs/models, global keyword chains, false PoC proof and no durable provenance contract. |
| Collector/parser reliability | 44 | Useful fixed catalogs and fixtures; live failure semantics, bounds, secure XML, protocol truth and coverage gaps. |
| Web/API security | 20 | No access control/control-plane hardening and confirmed XSS; suitable only as an enforced-local demo after fixes. |
| Continuous-mode maturity | 14 | Scaffold without entry point, real collection integration, durability, recovery, alerts, health or multi-instance safety. |
| Privacy and sensitive-data handling | 24 | Sanitization exists in intent but confirmed to miss common secret formats and downstream sinks. |
| Test quality | 49 | 99 fast tests and strong guardrail cases; 54% coverage, fixture dominance, weak negative assertions/adversarial system tests. |
| CI and supply chain | 60 | SHA-pinned actions, hash lock, audit/Bandit/SBOM are strong; main fails and containers/packages/releases are not gated. |
| Observability | 15 | Audit/result files exist; no metrics, health, traces, alerts, run store, recovery, or lifecycle controls. |
| Documentation accuracy | 27 | Extensive and useful intent, but security/maturity/test/install claims materially exceed or differ from code. |
| Deployment readiness | 23 | Compose lab exists; no secure service deployment, functional package, hardened images, upgrade/backup/retention plan. |
| Maintainability | 46 | Reasonable module separation; naming drift, duplicate architecture, dead metadata/config and missing type/lint gates. |
| **Overall production readiness** | **28** | **Alpha/prototype: supervised, separately verified lab use only.** |

### Actual execution paths

### CLI scan

`argparse input` → `Policy.load()` → `Guardrail`/audit key initialization → optional approval verification for CLI `local`/`arm` → `default_plan()` → fixed registry `ToolSpec` → `Guardrail.authorize(tool, argv, targets)` → selected dry-run/Docker/local sandbox → subprocess → parser → regex sanitizer → heuristic/cloud triage → correlation → fixed report files → audit record.

The normal V1 path has a meaningful control stack, but the exact canonical network approved is not substituted into argv; authorization validates one representation and execution retains the caller's original string. Parser/model evidence is not placed into the V2 graph.

### Web/API scan

`HTTP JSON` → Pydantic model with few constraints → **no authentication/authorization** → process-local lock → immediate synchronous scan → global fixed output directory → entire result response → unsafe `innerHTML` rendering. There is no durable run ID, queue, ownership, background task, state store, progress stream, cancellation, retention rule, or cross-process lock. `/api/scan` accepts `arm` and live mode without verifying an approval token; `/api/host` and `/api/ad` accept credentials and invoke live collectors.

### Planner/agent flow

V1 planning is deterministic and AI is at most a profile ranker: model output cannot directly select arbitrary binaries, which is a strong design choice. It is not an evidence-driven agent loop. The V2 flow is `graph → agent.propose() → optional guardrail authorize`, but proposed actions frequently have empty targets and `run_authorized()` does not execute a collector, update the graph, or define a stop/re-plan contract.

### Continuous mode

`ContinuousRunner.run_forever()` loads JSON state → proposes actions → skips those without targets → calls authorization only → runs correlation/delta → writes JSON → sleeps. There is no CLI/API/supervisor integration, durable transaction, schema migration, signal handling, restart checkpoint, alert sink, health check, metrics, retention, backup, tenancy, or multi-instance coordination. Exceptions are swallowed.

### Armed PoC

The library function checks guardrail scope, a check name, an `AEGIS_LAB_NET` address match, and an armed set, then calls a direct host socket prober. It is not exposed through the documented CLI, it does not enter Docker, and the environment-based “lab” gate is not technical isolation. The SMB and LDAP probes equate an open TCP port with write access/anonymous bind, so the resulting proof labels are false.

## 5. Security-invariant verification matrix

| Claimed invariant | Documented source | Enforcing code | Relevant tests / bypasses considered | Result | Required fix |
|---|---|---|---|---|---|
| Default deny, allowed IPv4 only | READMEs, policy | `guardrail.py:71-94, 223-244` | IPv4/CIDR, decimal, hex, leading zero, host bits, allow/deny overlap, out-of-scope CLI | **Enforced for literal IPv4** | Preserve and property-test normalization |
| IPv6/mapped IPv6/DNS are safe | Guardrail docstring/readmes | IPv4-only `canon_network`; `resolve_dns` unused | IPv6, mapped IPv6, hostnames, DNS/rebinding, multi-address | **Partially enforced by denial** | Either explicitly document unsupported or implement resolve-once/all-address policy |
| Canonical authorized target is executed | Security narrative | Check only; original argv retained | Alternate numeric forms, URL host parsing, user-info, ports | **Contradicted** | Return a canonical target object and build argv/audit from it |
| Redirects cannot escape scope | “every action” claim | Initial `authorize_host()` only | Confirmed two-loopback-server cross-host redirect | **Contradicted** | Disable redirects or authorize each hop and connected IP |
| Only approved tools/profiles execute | Tool firewall docs | registry + `_check_tool()` | Unknown tools/profiles, arbitrary armed names, direct helper calls | **Partially enforced** | Bind authorization to immutable ToolSpec/profile/action IDs |
| Binary identity cannot be substituted | Sandbox/firewall docs | `shutil.which`, inherited PATH for Docker CLI | absolute/relative path, symlink/PATH/env/wrapper threat review | **Documentation only** | Resolve/validate realpath or image digest and pass trusted paths/env |
| Arguments cannot add dangerous behavior | Guardrail docstring | metachar/flag deny lists | shell metacharacters, files, `ProxyCommand`, SSH username path | **Partially enforced** | Validate every user-derived field and use per-tool positive schemas |
| No shell execution and timeout kills children | Sandbox docs | `Popen(argv)`, new session, killpg | Static review and tests | **Enforced** | Preserve; add cancellation/output-limit tests |
| Docker is isolated from LAN/internet | README/script | Compose `internal: true` | Docker config review; verifier logic reviewed; lab deliberately not run | **Partially enforced / unverified at runtime** | Replace verifier and test host/LAN/internet/IPv6/DNS/TCP paths |
| Sandbox limits blast radius | Sandbox docs | long-lived attacker container | caps, user, mounts, socket, host net, limits, concurrent runs | **Partially enforced** | Per-run non-root containers, cap drop, read-only FS, limits, profiles |
| High-risk modes require explicit approval | Approval docs | CLI verification only | Web `arm`, host/AD/direct web, direct PoC calls | **Contradicted across interfaces** | Central approval middleware/service for every high-risk action |
| Approval is exact and non-replayable | Approval docs | HMAC of modes/targets/expiry | Same token accepted twice; policy/action/context changes | **Partially enforced** | Add nonce ledger, action/profile/sandbox/policy binding, max TTL |
| Audit log detects modification/reorder/removal/truncation | SECURITY/docs | HMAC chain, optional anchor | Mutation, middle deletion, prefix truncation, malformed lines, two writers | **Contradicted for truncation/concurrency** | Locked atomic append, durable sequence, external authenticated anchor |
| External anchor is WORM/out-of-band | Security docs | JSON file `anchor.py:24-29` | Storage/auth/crash/race review | **Operator expectation** | Define and implement immutable remote anchor protocol |
| Scanner output is sanitized before AI/reporting | Guardrail/web docs | regex replacement | JSON, auth header, cookie, API key, URI, multiline, private key | **Partially enforced** | Structured redaction and secret-detector tests; sanitize errors/model output |
| PHI/secrets never leave or persist | Product claims | three regexes | Eight confirmed misses; cloud/report paths | **Contradicted** | Privacy classification, minimization, field policies, retention, egress tests |
| AI cannot authorize arbitrary actions | Architecture docs | deterministic V1 plan + registry + guardrail | model output/control flow review | **Enforced in normal V1 path** | Preserve separation; extend same contract to V2 |
| AI findings are evidence-backed | AI/evidence docs | permissive JSON parse | fabricated assets/evidence, invalid severity/schema, prompt injection | **Partially enforced** | Strict schema and provenance IDs; reject unsupported claims |
| “Observed” attack paths reflect prerequisites | V2/chains docs | substring/global graph logic | cross-asset relay/privesc/segmentation/shadow-AI scenarios | **Contradicted** | Typed per-asset prerequisite DAG with confidence/proof state |
| PoC proves behavior only in lab | PoC docs | env address check + sockets | isolation, mapped IPv6, SMB/LDAP semantics | **Contradicted** | Run inside attested sandbox and implement protocol-level safe proofs |
| Host audit is read-only | README/catalog | closed commands | Lynis file writes, masscan/nuclei semantics, metadata usage | **Contradicted in parts** | Classify side effects per command and enforce allowed impact |
| Errors fail closed and remain visible | General security claims | mixed exception handling | missing LDAP tool, nonzero exit, timeout, provider failure, continuous exceptions | **Partially enforced** | Typed failure states, stop conditions, audit/alert every degradation |
| Reports are isolated and safe to render | UI/report docs | fixed files + direct HTML | XSS, Markdown/CSV injection, concurrent runs, partial writes | **Contradicted** | Per-run atomic store, escaping, CSP, ownership and retention |
| CI validates release readiness | badges/workflow | pytest/audits/Bandit/SBOM | current main run, fresh lock/build/lint/type | **Contradicted** | Make install/test/build/lint/type/coverage/package/container gates blocking |

## 6. Critical and high-severity findings

| ID | Severity | Finding | Confirmed evidence | Immediate outcome |
|---|---|---|---|---|
| ARGUS-001 | Critical | Direct web redirects escape scope | Loopback regression reached a second, non-authorized server | Disable redirects/direct mode until hop authorization exists |
| ARGUS-002 | High | Web console is an unauthenticated live-control plane | Live scan/host/AD routes have no identity or approval middleware | Enforce loopback-only demo mode; disable network exposure/live actions |
| ARGUS-003 | High | Scanner/model output reaches `innerHTML` | Multiple unescaped result fields are rendered as HTML | Switch to safe DOM rendering and CSP |
| ARGUS-004 | High | SSH username option injection and credential exposure | User concatenated into SSH argv; password passed with `sshpass -p`; host keys disabled | Suspend live SSH collection until redesigned |
| ARGUS-005 | High | Secret/PHI sanitizer misses common formats | Seven common sensitive formats bypassed in safe probes | Prevent cloud/report persistence pending structured redaction |
| ARGUS-006 | High | Audit chain fails concurrency/truncation guarantees | Prefix truncation verifies; two writers fork the chain | Serialize writes and require real external anchoring before compliance use |
| ARGUS-007 | High | Isolation verifier can false-pass | Missing test tools/network-denied installation are treated as isolation | Do not start armed lab based on current script |
| ARGUS-008 | High | “Observed” attack paths are not evidence-correct | Cross-asset keywords and open ports can be promoted to proof | Downgrade proof labels and introduce typed provenance |

## 7. Complete findings register

The JSON report is the authoritative severity/title/evidence/remediation register. The expanded records below add operational context and acceptance criteria.

### ARGUS-001 — Direct web redirects escape the authorized scope

- **Severity / category / priority:** Critical / Scope enforcement and SSRF / P0
- **Affected components:** `aegis/aegis/recon/web.py:75-97, 189-203`; CLI `web --direct` flow.
- **Evidence:** `WebReconOrchestrator.run()` authorizes only `target`, while `HttpTransport.get()` uses the default `urllib` redirect handler. A safe test with two loopback listeners authorized the first endpoint and observed the client reach the second (`redirect_followed=True`).
- **Impact and scenario:** A service on an allowed IP can redirect Argus to a public, link-local, loopback, cloud-metadata, or otherwise denied address. The resulting request occurs after no scope decision and may return sensitive content to AI/reporting.
- **Root cause / confidence:** Authorization is target-string based and disconnected from HTTP connection/redirect resolution. **Confirmed.**
- **Recommended fix:** Disable redirects by default. If redirects are required, resolve once under policy, reject mixed/multiple unauthorized addresses, re-authorize every hop and final peer, bound hop count, and audit the canonical chain.
- **Acceptance criteria / regression tests:** Cross-host, cross-scheme, user-info, IPv4-mapped, link-local, hostname, rebinding, and multi-address redirects are denied before connection; same-host safe redirects are explicitly tested; audit records every approved hop.
- **Documentation update:** State the exact redirect and DNS policy; remove the claim that initial URL validation covers redirected traffic.

### ARGUS-002 — The web console is an unauthenticated live-control plane

- **Severity / category / priority:** High / Access control and agent control plane / P0
- **Affected components:** `aegis/aegis/web.py:18-183`, deployment documentation, static console.
- **Evidence:** No authentication, authorization, rate limiting, CSRF control, enforced bind address, run ownership, or approval-token field exists. `/api/scan` accepts caller-controlled `arm` and `dry_run=false`; `/api/host` and `/api/ad` accept credentials and invoke live collectors.
- **Impact and scenario:** Any client that can reach the service can launch scans, enable armed-listed tools, submit credentials, consume AI budget, overwrite reports, and read results. Browser-origin requests can also be driven by ARGUS-003.
- **Root cause / confidence:** A local single-user demo endpoint is presented as a product control plane without a deployment-enforced trust boundary. **Confirmed.**
- **Recommended fix:** Split demo and service modes; enforce loopback in demo mode. For service mode add strong operator auth, role/action authorization, CSRF/origin controls, centralized approval verification, request/rate/concurrency limits, durable run IDs/ownership, and safe secret input.
- **Acceptance criteria / regression tests:** Unauthenticated requests cannot start or read runs; live/armed/credentialed requests require action-bound approval; non-loopback bind fails closed unless secure service configuration is complete; authorization and cross-user isolation tests pass.
- **Documentation update:** Explicitly limit the current console to loopback single-operator demonstration use.

### ARGUS-003 — Untrusted scanner and model output executes as browser script

- **Severity / category / priority:** High / Stored and reflected DOM XSS / P0
- **Affected components:** `aegis/aegis/static/index.html:125-213`, FastAPI result responses.
- **Evidence:** Errors, summaries, attack paths, findings, assets, and evidence are interpolated into `innerHTML` without escaping. These fields can originate from banners, webpages, parsers, or LLM output.
- **Impact and scenario:** A malicious in-scope service or injected model response can execute JavaScript in the operator's console, read displayed results/password fields, and issue same-origin live scan requests.
- **Root cause / confidence:** Presentation treats untrusted data as HTML and the server supplies no CSP/security-header backstop. **Confirmed by source; browser exploit not executed.**
- **Recommended fix:** Render through `textContent`/safe DOM APIs, allowlist any necessary markup through a maintained sanitizer, and add strict CSP plus response security headers.
- **Acceptance criteria / regression tests:** Payloads in every response field render literally and never create elements/events/scripts; CSP blocks inline and external injection; automated browser tests cover scanner and LLM payloads.
- **Documentation update:** Document scanner/model output as hostile input and the console's rendering guarantees.

### ARGUS-004 — SSH host collection permits option injection and exposes credentials

- **Severity / category / priority:** High / Command argument and credential security / P0
- **Affected components:** `aegis/aegis/host/runner.py:22-42`, `guardrail.py:303-318`, `/api/host`.
- **Evidence:** The command is `sshpass -p <password> ssh ... <user>@<target> <command>`. `authorize_host()` validates target/check only and intentionally skips argument hygiene. Username is unvalidated, so a leading SSH option can be introduced; the password appears in process arguments. Host-key checking and known-host storage are disabled.
- **Impact and scenario:** A reachable unauthenticated console can supply a crafted username that changes SSH behavior, including command-capable SSH options, within the helper container. Other container processes can observe the password; MITM is accepted.
- **Root cause / confidence:** User-controlled identity is concatenated into argv outside the positive-schema guardrail. **High confidence from argv semantics; end-to-end command execution was not attempted.**
- **Recommended fix:** Use a maintained SSH library or protected file descriptor/agent for credentials, strict username validation, explicit option termination, fixed SSH configuration, and verified host keys/pins.
- **Acceptance criteria / regression tests:** Option-like/control-character usernames are rejected; secrets never appear in argv/log/report/error; host-key mismatch fails closed; adversarial SSH argument tests run without network access.
- **Documentation update:** Remove “read-only implies safe credential transport”; specify trust-on-first-use/pinning policy.

### ARGUS-005 — Secret and PHI sanitization does not support the product claims

- **Severity / category / priority:** High / Privacy and sensitive-data handling / P0
- **Affected components:** `targets/scope-policy.yaml:68-72`, `guardrail.py:329-333`, orchestrators, AI, reports, web errors.
- **Evidence:** Only simple password, SSN, and MRN regexes are configured. Safe probes showed misses for JSON passwords, Authorization Bearer, cookies, API keys, connection URIs, multiline passwords, and private-key markers; only `password=value` was redacted.
- **Impact and scenario:** Credentials, session tokens, directory data, PHI, cloud keys, or private material can be sent to cloud models, persisted in JSON/CSV/Markdown/audit/errors, or displayed to another operator.
- **Root cause / confidence:** Flat regex replacement is being used as a data-loss-prevention boundary without structured parsing, classification, minimization, encoding handling, or post-model/error sanitation. **Confirmed.**
- **Recommended fix:** Introduce structured typed observations, field-level sensitivity labels, header/JSON/XML/URI/PEM/credential detectors, bounded normalization/decoding, secret fingerprints, post-model/error/report redaction, retention controls, and a protected evidence store where raw data is truly required.
- **Acceptance criteria / regression tests:** A comprehensive adversarial corpus produces no plaintext sensitive values at every egress/persistence sink; tests assert absence, not merely presence of findings; cloud submission defaults to minimum necessary data.
- **Documentation update:** Downgrade “never leaves” claims until end-to-end enforcement and assurance evidence exist.

### ARGUS-006 — Audit logging is not durable, concurrent, or truncation-evident by default

- **Severity / category / priority:** High / Audit integrity and non-repudiation / P0
- **Affected components:** `guardrail.py:102-186`, `anchor.py:24-29`, all writers.
- **Evidence:** Prefix truncation of a valid two-entry log still verifies true without an anchor. Two independently initialized writers fork the HMAC chain and verification fails. Malformed lines are skipped when initializing state; append and anchor replacement have no lock, transaction, fsync, atomic protocol, restrictive creation mode, or symlink defense. The “anchor” is an unauthenticated local JSON overwrite unless an operator separately supplies WORM storage.
- **Impact and scenario:** Concurrent web/process runs corrupt the log; crashes desynchronize log and anchor; valid suffix deletion is undetected by default; a same-privilege attacker can replace both files. Audit validity therefore cannot support regulated or forensic claims.
- **Root cause / confidence:** An in-memory previous hash is treated as a serialization primitive and a pathname as a WORM service. **Confirmed.**
- **Recommended fix:** Use one transactional append service/store with monotonic sequence, locking, atomic durable commits, strict permissions/link checks, recovery, rotation, and an independently authenticated append-only remote anchor/receipt.
- **Acceptance criteria / regression tests:** Multi-process stress produces a single valid ordered chain; prefix/suffix/middle deletion, malformed records, rollback, crash between writes, permission/link attacks, and anchor outage fail closed and alert.
- **Documentation update:** Distinguish HMAC chaining from external immutability and list the required anchor backend.

### ARGUS-007 — The bundled isolation verifier can report success without testing isolation

- **Severity / category / priority:** High / Sandbox and lab safety / P0
- **Affected components:** `scripts/verify-isolation.sh:16-23`, `targets/docker-compose.yml`, attacker image.
- **Evidence:** The script starts Alpine only on the internal network and then tries `apk add`; internet denial prevents installing its test tools. Failures and missing `ping`/`nslookup` are suppressed/interpreted as blocked, and the script does not aggregate assertions into a failing exit status. It does not test host gateway/`host.docker.internal`, TCP, IPv6, DNS rebinding, shared networks, or container escape surfaces.
- **Impact and scenario:** Operators can accept a green-looking result even when the intended assertions were never executed, then run packet-emitting tools under a false safety assumption.
- **Root cause / confidence:** Test prerequisites depend on the route being denied and command absence is conflated with network denial. **Confirmed by script analysis; lab intentionally not started.**
- **Recommended fix:** Build a pinned verifier image containing tools, assert explicit destinations/protocols from the actual attacker container, inspect effective networks/routes/capabilities, fail on any missing prerequisite or unexpected result, and test from a disposable VM.
- **Acceptance criteria / regression tests:** Deliberately introducing internet, host, LAN, DNS, or IPv6 reachability makes the verifier exit nonzero; missing commands also fail; clean isolated configuration passes with auditable evidence.
- **Documentation update:** Replace “proven isolated” with “designed as internal-only” until the new test passes in CI/on supported platforms.

### ARGUS-008 — Attack-path “observed” status is not evidence-correct

- **Severity / category / priority:** High / Evidence provenance and defensive accuracy / P0
- **Affected components:** `aegis/aegis/chains.py`, `agents/correlation.py`, `evidence.py`, reports.
- **Evidence:** V1 chain rules use global substring/co-occurrence logic rather than typed, ordered, same-asset/topology prerequisites. TLS on host A, SMB on B, and AD on C can produce an “observed” relay path; foothold and privilege evidence on different assets can produce observed privilege escalation. Shadow-AI and segmentation paths can be marked observed without abuse/pivot proof. V2 creates new random path nodes on repeated cycles.
- **Impact and scenario:** Reports can assert exploit chains that were never demonstrated, drive false remediation priorities, and turn model/parser mistakes into authoritative “proof.” Continuous runs can accumulate duplicates.
- **Root cause / confidence:** Narrative keyword matching substitutes for a provenance-constrained attack graph and proof-state model. **Confirmed by source and adversarial scenarios.**
- **Recommended fix:** Define typed evidence IDs, asset identities, edges, prerequisite DAGs, temporal/run boundaries, confidence, and explicit states (`hypothesis`, `supported`, `verified`). Only collectors/protocol checks may advance proof state.
- **Acceptance criteria / regression tests:** Cross-asset and missing-prerequisite scenarios remain hypotheses; repeated runs deduplicate; every reported edge links immutable source evidence and collector/run metadata; model text cannot create verified proof.
- **Documentation update:** Reserve “observed/verified/proven” for mechanically supported states.

### ARGUS-009 — Approval tokens are replayable and insufficiently action-bound

- **Severity / category / priority:** Medium / Authorization semantics / P1
- **Affected components:** `approval.py`, CLI approval flow, web/PoC interfaces.
- **Evidence:** Tokens bind mode set, canonical targets, and expiry with HMAC, but have no nonce/consumption ledger, operator/run/action/profile/sandbox/policy hash, issued-at, maximum TTL, or key separation. The same token verified twice in a safe probe. Enforcement exists only in selected CLI paths.
- **Impact and scenario:** A captured token can be reused until expiry and remains valid after relevant policy/profile changes; it can authorize a broader action class than the operator reviewed.
- **Root cause / confidence:** Approval models a time-limited capability class rather than a single reviewed execution. **Confirmed.**
- **Recommended fix:** Use a dedicated signing key, immutable action digest (targets, tool/profile, args/options, sandbox, policy hash), nonce, issuer/operator, issued-at/max TTL, and atomic one-time consumption where single-use is intended.
- **Acceptance criteria / regression tests:** Replay, policy/profile/argument/sandbox changes, long/future TTL, wrong operator, and concurrent consumption fail closed; all high-risk interfaces use the same verifier.
- **Documentation update:** Define whether tokens are single-use or reusable and exactly what they authorize.

### ARGUS-010 — Continuous mode is non-operational scaffolding

- **Severity / category / priority:** Medium / Reliability and product completeness / P1
- **Affected components:** `continuous.py`, `persistence.py`, `agents/*`, CLI/API/docs.
- **Evidence:** There is no public invocation path. Agent proposals often contain no targets and are skipped; authorization is not collection. State is a non-atomic schema-less JSON overwrite, timestamps are not faithfully restored, exceptions are swallowed, and there are no locks, signals, alerts, metrics, health, recovery, retention, backup, or migrations.
- **Impact and scenario:** A purported 24/7 sensor can silently stop useful collection, lose/corrupt state, duplicate paths, miss alerts, or have multiple processes overwrite one another.
- **Root cause / confidence:** A conceptual loop and data structures are documented as an operating subsystem before integration and lifecycle engineering. **Confirmed.**
- **Recommended fix:** Reclassify as experimental; first define durable run/evidence state, scheduler/supervisor contract, idempotency, leases, recovery, alert delivery, retention, health/metrics, and end-to-end collectors.
- **Acceptance criteria / regression tests:** Restart/crash/corruption/multi-instance/clock/delta/backpressure tests pass; a public supported entry point performs real guarded collection and emits durable deduplicated alerts.
- **Documentation update:** Move V2 continuous claims to roadmap until acceptance criteria are met.

### ARGUS-011 — PoC gates do not technically isolate execution and two probes fabricate proof

- **Severity / category / priority:** Medium / Armed verification safety and correctness / P1
- **Affected components:** `agent/poc_runner.py:75+`, `agent/poc_probes.py:7-31`.
- **Evidence:** The lab gate is an environment-variable network comparison; probes open sockets from the host. IPv4-mapped IPv6 parsing is broken by colon splitting. `smb_share_writable` and `anon_ldap_bind` only test TCP connect while details claim write permission and anonymous LDAP bind.
- **Impact and scenario:** Direct callers can emit packets outside a technically attested sandbox, and reports can upgrade an open port into proof of access that never occurred.
- **Root cause / confidence:** Environmental intent is used as isolation, and reachability is conflated with protocol authorization. **Confirmed.**
- **Recommended fix:** Execute through an attested sandbox/action manifest, central approval service, and protocol-specific non-destructive verification that can distinguish reachable, authenticated, authorized, and proven states.
- **Acceptance criteria / regression tests:** Host socket use is impossible; mapped IPv6 and non-lab routes fail; open-only SMB/LDAP fixtures never report writable/anonymous; every gate is audited.
- **Documentation update:** Remove documented CLI/PoC claims until an entry point and real probes exist.

### ARGUS-012 — Tool authorization is not bound to executable identity

- **Severity / category / priority:** Medium / Tool firewall and supply chain / P1
- **Affected components:** `guardrail.py:247-301`, `sandbox.py:65-126`, registry/config.
- **Evidence:** The firewall checks the caller-provided logical tool string, while execution trusts `argv[0]` and PATH; Docker itself is also resolved from inherited PATH. No invariant binds logical tool, immutable ToolSpec, resolved realpath/image digest, and executed binary. `armed` names can be allowed even if not in `armed_only`; `read_only`/`needs_root` metadata are unused.
- **Impact and scenario:** A malicious PATH entry/symlink/wrapper or direct internal caller can create a mismatch between the audited tool name and executed program; metadata cannot enforce privilege/impact assumptions.
- **Root cause / confidence:** Authorization and execution exchange mutable strings rather than a sealed action object. **Reasonable concern, confirmed design gap; no hostile PATH was installed.**
- **Recommended fix:** Authorize immutable registry action IDs, construct argv only after authorization, resolve/pin trusted executable/image identity, use a fixed minimal environment, and enforce metadata/capabilities.
- **Acceptance criteria / regression tests:** PATH/symlink/absolute/relative/wrapper substitutions and tool/argv mismatches fail; arbitrary armed names fail; audit records verified binary/image identity.
- **Documentation update:** Describe executable identity guarantees rather than binary-name allowlisting alone.

### ARGUS-013 — Collector errors and tool absence are frequently converted into empty evidence

- **Severity / category / priority:** Medium / Failure behavior and observability / P1
- **Affected components:** `orchestrator.py`, `host/ad.py`, `recon/web.py`, `ai_analyzer.py`, `continuous.py`.
- **Evidence:** Parsers may process stdout after nonzero/timeout; stderr is usually excluded from structured outcomes; AD ignores missing/nonzero tool states; direct web collapses all transport exceptions to status 0; model provider failure silently falls back; continuous exceptions are swallowed.
- **Impact and scenario:** “No findings” can mean clean, tool missing, authentication failure, timeout, parser failure, or provider outage. Reports and deltas can therefore be falsely reassuring.
- **Root cause / confidence:** Absence of typed execution/evidence quality states and inconsistent fail/degrade policies. **Confirmed.**
- **Recommended fix:** Model success, partial, timeout, missing, auth failure, parse failure, and unsupported explicitly; stop or mark coverage incomplete; sanitize/audit actionable errors; expose health and completeness.
- **Acceptance criteria / regression tests:** Each failure mode has distinct report/audit/API state; no failed collector yields a clean result; provider fallback is visible and configurable.
- **Documentation update:** Define completeness and degradation semantics.

### ARGUS-014 — Sandbox execution lacks resource bounds and per-run isolation

- **Severity / category / priority:** Medium / Availability and containment / P1
- **Affected components:** `sandbox.py`, Compose attacker/sshhelper services, collectors.
- **Evidence:** `communicate()` buffers unlimited stdout/stderr; the attacker is long-lived/root with `NET_RAW`/`NET_ADMIN`, no read-only FS, cap drop, no-new-privileges, pids/CPU/memory/output/file limits, and no per-run container. Multiple runs share state. `max_body` truncates only after curl output is captured.
- **Impact and scenario:** A verbose/hung/malicious tool can exhaust host memory or disk, contaminate later runs, retain artifacts, or increase container-escape impact.
- **Root cause / confidence:** Network topology is treated as the complete sandbox boundary. **Confirmed configuration/design gap.**
- **Recommended fix:** Ephemeral non-root per-run containers, minimal capabilities, read-only root, tmpfs quotas, seccomp/AppArmor, no-new-privileges, pids/CPU/memory limits, streaming byte caps, cancellation, and cleanup verification.
- **Acceptance criteria / regression tests:** Output bombs, forks, timeouts, cancellation, concurrent runs, and stale artifacts stay within limits and leave no processes/data.
- **Documentation update:** Separate network isolation from process/resource containment.

### ARGUS-015 — AI output lacks strict schema and evidence provenance enforcement

- **Severity / category / priority:** Medium / AI-agent safety / P1
- **Affected components:** `ai_analyzer.py:215-267`, prompts, report/correlation paths.
- **Evidence:** `_parse_findings()` accepts aliases, single objects, defaulted values, invalid severities/confidence/assets/evidence, and extra content; some non-dict shapes can crash. `correlate()` accepts any JSON object and labels it trusted. Model output is not post-sanitized or linked to immutable observation IDs.
- **Impact and scenario:** Prompt-injected or malformed output can fabricate assets/evidence, change severity, inject report/UI content, or produce unsupported attack paths. It does not directly authorize tools in V1, which limits impact.
- **Root cause / confidence:** Prompt instructions substitute for schema/provenance validation. **Confirmed.**
- **Recommended fix:** Strict versioned schemas, enumerations/bounds, reject-unknown fields, observation-ID citations, asset/scope validation, deterministic evidence reconciliation, post-model sanitation, and explicit untrusted status.
- **Acceptance criteria / regression tests:** Malformed/fabricated/out-of-scope/injected outputs are rejected or downgraded; only cited existing evidence can support findings; no output alters authorization.
- **Documentation update:** State that models propose interpretations, never facts or authorization.

### ARGUS-016 — Reports are shared, non-atomic, and injection-prone

- **Severity / category / priority:** Medium / Reporting and data integrity / P1
- **Affected components:** `reporting.py:38-66`, `web.py`, JSON/CSV/Markdown outputs.
- **Evidence:** Each run overwrites fixed filenames using direct writes; no run ID, ownership, lock across processes, atomic rename, permissions policy, retention, or model-output redaction exists. CSV cells are not protected from spreadsheet formulas; Markdown is unescaped.
- **Impact and scenario:** Concurrent/crashed runs can mix or truncate reports; one user can see another run; opening CSV/Markdown in downstream tools can execute formulas or active content.
- **Root cause / confidence:** Report serialization is treated as a local demo helper rather than a security-sensitive persistence boundary. **Confirmed.**
- **Recommended fix:** Per-run immutable storage, atomic write/rename and integrity metadata, ownership/access control, safe serializers, formula neutralization, sanitization, retention, and encryption where required.
- **Acceptance criteria / regression tests:** Concurrent/crash tests never mix data; hostile cell/Markdown payloads remain inert; users can access only their runs; raw/model secrets never persist.
- **Documentation update:** Define report lifecycle, trust, and safe-opening guidance.

### ARGUS-017 — Container and tool supply chain is mutable and weakly verified

- **Severity / category / priority:** Medium / Software supply chain / P1
- **Affected components:** `targets/*.Dockerfile`, `targets/docker-compose.yml`, CI.
- **Evidence:** Kali rolling and multiple `:latest` images are used; apt packages are unpinned; Nuclei is downloaded without checksum/signature and install failure is tolerated. Templates and tool behavior are not version-locked. No container build/scan/SBOM/signing gate exists.
- **Impact and scenario:** Identical source revisions can execute different scanners/templates or inherit a compromised dependency; “read-only” behavior and findings are not reproducible.
- **Root cause / confidence:** Python dependencies are pinned well, but that discipline does not extend to images, OS packages, binaries, or templates. **Confirmed.**
- **Recommended fix:** Pin image digests, package/tool/template versions and hashes/signatures; fail installation closed; build/scan/SBOM/sign images in CI; record all component identities per run.
- **Acceptance criteria / regression tests:** Rebuilds resolve identical verified artifacts; tampered downloads fail; vulnerability/license policy gates releases; reports contain tool/template/image versions.
- **Documentation update:** Publish supported/pinned toolchain and update process.

### ARGUS-018 — Dependency, packaging, and current CI state are not release-valid

- **Severity / category / priority:** Medium / Build and release engineering / P1
- **Affected components:** `requirements*.txt`, `pyproject.toml`, CI, package layout.
- **Evidence:** Fresh hash-locked install yields 97 pass/2 fail because `networkx` is missing, matching the current main CI failure. Build initially discovers runtime `aegis/output` as a package; when cleaned, it produces `aegis 0.0.0` without dependencies, CLI entry point, static UI, default policy, or Compose files.
- **Impact and scenario:** A clean developer/CI/user install cannot run the full suite or receive a functional package; a successful wheel build gives false confidence.
- **Root cause / confidence:** `pyproject.toml` is tool configuration, not project/package metadata, and dependency sources are inconsistent. **Confirmed.**
- **Recommended fix:** Choose one authoritative project metadata/lock workflow, declare runtime/optional dependencies and package data/entry points, exclude runtime outputs, and install/test the built artifact in CI.
- **Acceptance criteria / regression tests:** Clean locked install passes all tests; wheel metadata/version/dependencies/assets/CLI are correct; smoke tests run solely from installed wheel; main CI is green.
- **Documentation update:** Replace source-tree commands/badges with verified install instructions and current status.

### ARGUS-019 — Scope/policy parsing has representation and validation gaps

- **Severity / category / priority:** Medium / Configuration and target normalization / P1
- **Affected components:** `config.py`, `guardrail.py:39-94, 235-301`, policy YAML.
- **Evidence:** URL host extraction is delimiter-based and mishandles IPv6/user-info; IPv6 and DNS are unsupported despite a `resolve_dns` setting; policy networks use non-strict parsing and lack schema/version/default validation; network/broadcast/special addresses inside an allowed CIDR are accepted; canonical checked targets are not propagated to execution/audit.
- **Impact and scenario:** Operator intent can differ from effective policy, future feature changes can reopen ambiguity, and unsupported formats fail inconsistently across layers.
- **Root cause / confidence:** Target identity is repeatedly reconstructed from strings rather than represented by one validated value object. **Confirmed.**
- **Recommended fix:** Versioned strict policy schema and a single canonical `AuthorizedTarget` with parsed scheme/host/port/network/resolved peers/special-address policy used by approval, guardrail, execution, and audit.
- **Acceptance criteria / regression tests:** Property/fuzz tests cover all requested encoding, URL, IPv6, DNS, port, Unicode, overlap, and special-address cases; the executed/audited target equals the authorized object.
- **Documentation update:** Precisely document supported target grammar and special-address policy.

### ARGUS-020 — Parsers and output handling are insufficiently bounded and hardened

- **Severity / category / priority:** Medium / Parser security and robustness / P2
- **Affected components:** tool parsers, `sandbox.py`, web/LDAP/host parsing.
- **Evidence:** Full subprocess output is buffered before field truncation; parsers process arbitrary untrusted version/localization/size input; stdlib XML parsing is a silent fallback when `defusedxml` is unavailable; exit status and stderr are inconsistently incorporated. There are few fuzz/size/binary/malformed tests.
- **Impact and scenario:** Crafted output can exhaust memory, crash parsing, create false evidence, or invoke unsafe XML behavior in a degraded environment.
- **Root cause / confidence:** Output size and parser trust are addressed at presentation rather than ingestion. **Confirmed design gap; no resource-exhaustion payload executed.**
- **Recommended fix:** Streaming hard byte/record limits, fail-closed secure parser dependencies, parser-specific schemas, encoding policy, typed parse errors, and fuzz/property corpora.
- **Acceptance criteria / regression tests:** Oversize/binary/malformed/XML-entity/localized/partial/nonzero outputs remain bounded and produce explicit incomplete/error states without findings inflation.
- **Documentation update:** Publish collection/output limits and incomplete-result semantics.

### ARGUS-021 — Documentation and test-count claims are materially stale

- **Severity / category / priority:** Low / Documentation accuracy / P2
- **Affected components:** root/aegis READMEs, `NEXT_STEPS.md`, build log, badges.
- **Evidence:** Counts claim 39/72/75/81 tests while 99 collect; the documented short audit key causes 12 failures; current clean locked run fails two; read-only, privacy, isolation, truncation, continuous, and PoC claims exceed enforcement.
- **Impact and scenario:** Operators and reviewers make unsafe deployment decisions and cannot reproduce advertised checks.
- **Root cause / confidence:** Documentation is updated as milestones accumulate without an executable claims inventory. **Confirmed.**
- **Recommended fix:** Make claim/test/install snippets executable CI checks and attach each security claim to an invariant test/evidence link.
- **Acceptance criteria / regression tests:** README commands pass from clean checkout; badges derive from current CI; every security/maturity claim has an owner and automated/explicit verification status.
- **Documentation update:** This finding is the update: reconcile all affected documents in one release.

### ARGUS-022 — Aegis/Argus and V1/V2 duplication obscures the supported architecture

- **Severity / category / priority:** Low / Maintainability and architecture clarity / P2
- **Affected components:** package/CLI/env names, V1/V2 observation/correlation paths, tickets/docs.
- **Evidence:** Product is Argus, package/CLI/env/tickets remain Aegis; two Observation models and two correlation approaches coexist; V2 modules are disconnected; policy allows tools absent from registry.
- **Impact and scenario:** Contributors fix or extend the wrong path, security properties diverge, and operators cannot identify stable interfaces.
- **Root cause / confidence:** Rebranding and V2 scaffolding were layered onto V1 without an architecture decision/migration boundary. **Confirmed.**
- **Recommended fix:** Publish an ADR choosing supported execution/evidence paths, mark experimental namespaces, define a staged migration, and remove dead configuration only after compatibility review.
- **Acceptance criteria / regression tests:** One documented path owns authorization, evidence, correlation, and reporting; experimental APIs are isolated/versioned; names and configuration map unambiguously.
- **Documentation update:** Add current-state architecture and deprecation/migration table.

### ARGUS-023 — CI omits important quality and security gates

- **Severity / category / priority:** Low / DevSecOps assurance / P2
- **Affected components:** `.github/workflows/ci.yml`, pre-commit/tool configs.
- **Evidence:** Current workflow runs tests, dependency audit, Bandit, SBOM, and informational secrets, but not Ruff, mypy, coverage threshold, built-wheel smoke tests, container build/scan/SBOM, license checks, SAST result publishing, or a Python matrix. Local Ruff has 27 and mypy 34 errors.
- **Impact and scenario:** Main can be broken or unreleasable while several green security jobs imply readiness; type/quality drift accumulates.
- **Root cause / confidence:** Checks are split between optional local hooks and CI, with no defined release gate. **Confirmed.**
- **Recommended fix:** Add staged blocking lint/type/coverage/package/container/license gates, matrix supported Python versions, and publish artifacts/SARIF; keep secret scanning history-aware and blocking on verified secrets.
- **Acceptance criteria / regression tests:** A clean PR must install from lock, test matrix, lint/type, build/install wheel, build/scan images, enforce coverage and supply-chain policies; branch protection requires them.
- **Documentation update:** Define required checks and supported runtime matrix.

### ARGUS-024 — Open-source and release-governance claims lack required artifacts

- **Severity / category / priority:** Low / Product governance / P3
- **Affected components:** repository root and release process.
- **Evidence:** No LICENSE, changelog, release/version policy, artifact signing/provenance, or documented support/security disclosure lifecycle exists; built metadata defaults to version `0.0.0`.
- **Impact and scenario:** Users lack legal permission clarity, trustworthy upgrade history, provenance, and a vulnerability-reporting contract.
- **Root cause / confidence:** Repository publication preceded release governance. **Confirmed.**
- **Recommended fix:** Select an approved license, add security/support/changelog/version policies, reproducible signed releases and provenance, and dependency/license review.
- **Acceptance criteria / regression tests:** Release artifacts have declared license/version/changelog/SBOM/signature/provenance and a verified installation; disclosure contacts and supported versions are published.
- **Documentation update:** Add the governance files and remove “open source/free” language until licensing is explicit.

### Required finding metadata

This table completes the affected execution path, current-protection analysis, effort, and compatibility fields for every record above.

| ID | Affected execution path | Existing protection → why insufficient | Effort | Compatibility |
|---|---|---|---:|---|
| ARGUS-001 | CLI direct web → authorize initial target → urllib GET → redirects | Literal initial target is scoped → redirect destinations/peers are not checked | M | Breaking for cross-host redirects |
| ARGUS-002 | HTTP request → live scan/host/AD → shared reports | Pydantic and scope check → no caller identity/action authorization/approval | L | Breaking for existing web clients |
| ARGUS-003 | Tool/model result → API JSON → console DOM | Some source text is regex-sanitized → HTML metacharacters/content are trusted | S | Backward-compatible except intentional HTML |
| ARGUS-004 | `/api/host` → SSHCreds → sshpass/ssh in helper | Closed remote-command catalog/target scope → username and credential transport are outside it | M | Breaking credential/host-key workflow |
| ARGUS-005 | Collector → sanitizer → AI/report/audit/UI | Three regexes → not structured, comprehensive, encoded, multiline, or post-model | L | Breaking observation/report schema likely |
| ARGUS-006 | authorize/record → append HMAC → optional anchor | Per-record HMAC → no serialized durable history/external receipt | L | Breaking audit format/storage |
| ARGUS-007 | operator → verifier script → lab decision | Compose internal network → verifier cannot prove its effective routes | M | Backward-compatible script replacement |
| ARGUS-008 | observations → chain/correlation → “observed” report | Rules/models exist → prerequisites lack asset/topology/provenance constraints | L | Breaking report/evidence semantics |
| ARGUS-009 | approve → token verify → CLI action | HMAC/target/expiry → reusable and not bound to exact action/policy/context | M | Breaking existing tokens |
| ARGUS-010 | loop → load graph → propose → authorize → save/sleep | Guardrail calls and JSON state → no actual collector/durability/operability | XL | Breaking experimental V2 interfaces |
| ARGUS-011 | direct PoC function → env gate → host socket → proof | Scope/armed/check gates → no technical sandbox and probes do not prove claims | L | Breaking PoC result semantics |
| ARGUS-012 | registry/logical name → guardrail → argv/PATH → exec | Allowlisted logical name/argv-only → binary identity is not bound | L | Internal API/deployment breaking |
| ARGUS-013 | subprocess/provider → parser/fallback → result | Timeouts/tool-missing fields exist → consumers flatten/ignore outcomes | M | Breaking API/report error schema |
| ARGUS-014 | action → shared attacker container → buffered process | Internal network/group timeout → no resource/per-run containment | L | Deployment behavior breaking |
| ARGUS-015 | sanitized observations → LLM → permissive JSON → reports | Defensive prompt and deterministic authorization → no output schema/provenance | M | Breaking model-output contract |
| ARGUS-016 | result → fixed JSON/CSV/MD → browser/downstream tools | Standard serializers → no atomic run isolation or active-content defense | M | Breaking output paths/schema likely |
| ARGUS-017 | Docker build/start → mutable images/tools/templates | Hash-locked Python and SHA-pinned actions → does not cover container stack | M | Operationally compatible; reproducibility changes |
| ARGUS-018 | clean install/build → tests/CLI/assets | Hash checking and CI exist → dependency set and package metadata incomplete | M | Backward-compatible pre-release packaging |
| ARGUS-019 | input/policy → parse/canonical check → original argv/audit | Ambiguous IPv4 forms denied → no unified target identity/schema | L | Breaking unsupported/ambiguous grammar |
| ARGUS-020 | untrusted stdout/XML → in-memory parser → evidence | Some display/body truncation and optional defusedxml → ingestion remains unbounded/fail-open | M | Large-output behavior breaking |
| ARGUS-021 | docs/badges/commands → operator decision | Extensive documentation → claims are not executable/release-gated | S | Backward-compatible documentation |
| ARGUS-022 | contributor/API → V1 or V2/Aegis or Argus path | Modules are separated → supported authority is not defined | L | Staged breaking migration |
| ARGUS-023 | PR → CI → merge/release | Tests/audit/Bandit/SBOM → quality/package/container gates absent | M | Backward-compatible, stricter merges |
| ARGUS-024 | source → package/release → user | Public repository/SBOM → no license/version/provenance/support contract | S | Backward-compatible after license approval |

### Evidence-correctness adversarial scenarios

The following scenarios should become mandatory regression tests before any “evidence-backed” claim is restored:

1. TLS weakness on asset A, SMB signing weakness on B, and AD evidence on C must **not** become an observed relay chain.
2. A foothold on asset A and local privilege indicator on B must **not** become observed privilege escalation.
3. An open TCP/445 or TCP/389 socket without protocol authorization must remain “reachable,” never “writable” or “anonymous bind verified.”
4. Re-running the same continuous cycle must not create a new random attack-path node or duplicate evidence.
5. Adding a child before its parent must either create the edge later or fail explicitly; it must not silently lose provenance.
6. Missing tool, authentication failure, timeout, parse failure, and empty clean output must remain distinct states.
7. A model-proposed asset or evidence string absent from collected observation IDs must be rejected, not promoted to trusted evidence.
8. State from a previous target/run/tenant must never satisfy the current run's prerequisites unless an explicit scoped continuity relation exists.

## 8. Documentation-versus-code discrepancies

| Documented or implied claim | Code/reproducible evidence | Disposition |
|---|---|---|
| V2 is a continuous self-defense sensor fabric suitable for 24/7 operation | No public entry point, agents largely scaffolded, proposals skipped, authorization without collection, fragile JSON state, no operational lifecycle | Move to roadmap/experimental status |
| Every action passes the seven-layer guardrail | Redirect hops, web arm/live routes, SSH credential/username construction, direct PoC sockets, and V2 helper calls do not pass the same full flow | Qualify claim and centralize action execution |
| Scope is preserved through web reconnaissance | Default urllib redirects leave the initial authorized host | Contradicted; ARGUS-001 |
| Lab isolation is proven | Verifier can treat missing commands/prerequisite-install failure as successful blocking | Contradicted; ARGUS-007 |
| Audit detects any truncation/removal | Valid prefix truncation verifies without a real external anchor; concurrent writers corrupt the chain | Contradicted; ARGUS-006 |
| Sensitive data/PHI never leaves or persists | Common structured/header/multiline secrets bypass sanitizer and can reach AI/reports/UI | Contradicted; ARGUS-005 |
| Operations are predominantly/read-only | Lynis writes remote files; masscan and Nuclei have active/load/template semantics; `read_only` metadata is unused | Partially contradicted |
| PoC gates prove writable SMB/anonymous LDAP in a lab | Library-only direct host sockets; probes test TCP reachability only | Contradicted; ARGUS-011 |
| Findings and paths are evidence-backed/observed | Global cross-asset keywords and permissive model data can create unsupported proof | Contradicted; ARGUS-008/015 |
| Project is installable/release-ready | Clean lock misses NetworkX; wheel is 0.0.0 without dependencies/CLI/assets; current CI fails | Contradicted; ARGUS-018 |
| Tests/badges represent current status | Documents cite 39/72/75/81; 99 collect, but clean lock is 97/2 and documented key is invalid | Stale; ARGUS-021 |
| Argus is the coherent product/API name | Package/CLI/env/tickets remain Aegis; V1/V2 data paths coexist | Inconsistent; ARGUS-022 |
| Open-source/free distribution | No repository LICENSE or release governance | Legally ambiguous; ARGUS-024 |

## 9. Missing capabilities and architectural gaps

### Missing product capability

- Supported installed CLI/package and versioned release artifacts.
- A real evidence-driven planner/re-planning contract and operational continuous entry point.
- Correct protocol-level, non-destructive PoC verification and supported alert destinations.
- Run history, comparison, ownership, cancellation, export, and retention management.

### Missing engineering foundation

- One authoritative target/action/evidence model shared by every interface and collector.
- Strict schemas for policy, tool args, execution outcomes, model output, evidence, reports, and persisted state.
- Atomic run store, migrations, idempotency/deduplication, concurrency control, and recovery.
- Reproducible project/package/container/tool/template metadata and supported-runtime matrix.

### Missing security control

- Redirect/DNS/connected-peer scope enforcement and executable identity binding.
- Authenticated/authorized control plane with centralized action-bound approvals.
- Structured data classification/redaction, post-model sanitation, and protected raw evidence.
- Trustworthy lab attestation, sandbox resource policy, immutable external audit anchoring, and host-key-safe credential transport.

### Missing operational control

- Health, metrics, traces, alerting, error budgets, completeness indicators, and operator-visible degradation.
- Scheduler/supervisor integration, leases, graceful shutdown, backpressure, retries, recovery, backup/restore, retention, and capacity limits.
- Release, vulnerability response, upgrade/rollback, key rotation, audit rotation, and incident procedures.

### Missing user experience

- Safe login/roles, run ownership/status/history, progress, cancel/retry, and actionable error states.
- Explicit safe-mode/live-mode boundaries, approval review screen, credential-vault integration, and proof-quality labels.
- Consistent Argus naming and documentation that distinguishes stable, experimental, and roadmap functions.

### Missing test coverage

- Redirect/DNS/canonical execution, hostile PATH/symlink, approval replay/context, multi-process audit and crash recovery.
- Browser XSS/access control/tenancy, secret egress, report injection/concurrency, SSH argument/credential handling.
- Realistic parser failure/fuzz/size/version corpora, container route/escape/resource assertions, and protocol-semantic PoCs.
- Continuous restart/multi-instance/delta/dedupe/alerts and clean installed-wheel/container end-to-end tests.

## 10. Prioritized remediation roadmap

### P0 — Immediate safety or correctness

| Outcome | Files/modules | Dependencies | Tests required | Migration concern | Complexity |
|---|---|---|---|---|---:|
| No HTTP request can leave authorized scope | `recon/web.py`, guardrail target model, CLI | Canonical target/redirect policy decision | Hop/peer/DNS/rebinding/scheme regression suite | Cross-host redirects stop working | M |
| Web cannot expose live actions to an unidentified caller | `web.py`, deployment config, static UI | Identity/approval design; secure bind default | AuthN/Z, CSRF/origin, live-mode, rate/ownership E2E | Existing API clients must authenticate | L |
| Browser treats all scanner/model data as text | `static/index.html`, headers/middleware | None | Playwright hostile-field corpus + CSP | Intentional result HTML removed | S |
| SSH credentials and usernames cannot alter argv/leak | `host/runner.py`, web host route | SSH library/vault/host-key policy | Offline arg corpus; secret-sink; host-key integration | Credential and known-host workflow changes | M |
| Sensitive data is blocked at every egress | policy, observations, AI, errors, reports, web | Data classification/schema | End-to-end secret corpus with absence assertions | Report/observation schema changes | L |
| Audit remains valid under concurrency/crash/truncation | guardrail audit, anchor, run store | Transactional store + external receipt design | Multi-process/crash/rollback/link/anchor tests | Audit format and storage migration | L |
| Lab verifier cannot false-pass | verifier, Compose, verifier image | Pinned test image and platform matrix | Deliberate route leak/missing-tool negative tests | None beyond stricter failure | M |
| Reports stop labeling unsupported paths as observed | chains, evidence, correlation, reporting | Proof-state/provenance vocabulary | Cross-asset/missing-prereq/repeat tests | Report semantics/schema changes | L |

### P1 — Production hardening

| Outcome | Files/modules | Dependencies | Tests required | Migration concern | Complexity |
|---|---|---|---|---|---:|
| One action/target object binds approval through audit | config, approval, guardrail, tools, orchestrators | P0 redirect lessons/ADR | Property/fuzz/replay/policy/action identity | Tokens/internal APIs invalidated | L |
| Executed program equals authorized ToolSpec | tools, sandbox, images | Trusted path/image identity | PATH/symlink/wrapper/mismatch tests | Tool/image deployment change | L |
| Every collector reports explicit completeness | orchestrators, host/AD/web, parsers, API/report | Typed execution outcome schema | timeout/missing/auth/parse/provider tests | API/report schema additions | M |
| Runs are isolated, atomic, owned, and retained | reporting, web, persistence | Durable store/identity | concurrency/crash/tenancy/retention tests | Existing output paths migrate | L |
| Sandbox is ephemeral and resource-bounded | sandbox, Compose/images | Container policy/runtime support | fork/output/CPU/memory/cancel/cleanup | Operational/container changes | L |
| AI output is strictly evidence-linked | AI, evidence, schemas | Stable observation IDs | malformed/injection/fabrication/out-of-scope corpus | Model prompt/response contract | M |
| Tool/image/template supply chain is reproducible | Dockerfiles, Compose, CI | Approved pins/signing/scanners | rebuild/tamper/scan/SBOM checks | Pin/update process | M |
| Clean install and built wheel are authoritative | pyproject, lock, package data, CI | Packaging decision | clean matrix + installed-wheel smoke | Source-tree users adopt CLI package | M |

### P2 — Capability and architecture

| Outcome | Files/modules | Dependencies | Tests required | Migration concern | Complexity |
|---|---|---|---|---|---:|
| One evidence graph and provenance-aware attack DAG | V1/V2 observations, evidence, chains, correlation | P1 schemas/run store | topology/temporal/dedupe/migration tests | Historical evidence migration | XL |
| Continuous service is durable and operable | continuous, agents, persistence, CLI/API | Unified graph, run store, observability | restart/lease/multi-instance/backpressure/alert tests | Experimental state discarded/migrated | XL |
| Supported safe protocol PoCs | PoC runner/probes/sandbox | Action kernel + isolation attestation | protocol positive/negative/side-effect tests | Old proof values invalid | L |
| CI becomes release assurance | workflow/config/releases | Packaging/container/supply-chain work | required-gate self-tests | Stricter PR merge policy | M |

### P3 — Polish and optimization

| Outcome | Files/modules | Dependencies | Tests required | Migration concern | Complexity |
|---|---|---|---|---|---:|
| Consistent Argus naming and documented stable APIs | package/docs/config | Architecture/deprecation ADR | compatibility/import/CLI docs checks | Staged aliases/deprecations | L |
| Accurate automated claims/badges/docs | docs/README/CI | Stable commands/features | docs command/link/claim checks | None | S |
| Complete license/release/support governance | root docs/release | Legal/product decision | release artifact verification | License choice | S |
| Performance/cost tuning after correctness | parsers/AI/continuous | Metrics and stable workloads | benchmark/cost regression | None | M |

## 11. Quick wins

- Disable redirects in `HttpTransport` or temporarily remove `--direct`; add the confirmed two-server test first.
- Fail web startup on non-loopback binding until authenticated service mode exists; default every route to dry-run.
- Replace result-field `innerHTML` interpolation with `textContent`/DOM nodes and add a minimal CSP.
- Reject SSH usernames outside a strict documented grammar and stop displaying/echoing credential-bearing errors while the transport is redesigned.
- Change the verifier to fail immediately when a prerequisite command is absent; stop calling the result “proven.”
- Rename open-port PoC outputs to reachability observations so they cannot claim SMB write/LDAP bind proof.
- Add `networkx` to the authoritative dependency metadata/lock and make a clean locked test run the CI source of truth.
- Correct the README audit-key example and generate all test-count badges from collection/CI.
- Make provider fallback, missing tools, timeouts, and parser failures visible in reports instead of empty success.
- Add CSV formula neutralization and per-run temporary output directories before a durable run store is built.

## 12. Proposed implementation phases

### Phase 1 — Safety freeze and boundary closure

- **Goal:** eliminate known scope/access/browser/SSH violations and stop overstated safety claims.
- **Exact scope:** ARGUS-001–004 and documentation flags for ARGUS-005–008; disable unsafe paths when full fixes are not ready.
- **Out of scope:** new collectors, continuous features, UI redesign, evidence-graph migration.
- **Files expected to change:** `recon/web.py`, `web.py`, `static/index.html`, `host/runner.py`, CLI/deployment docs, focused tests.
- **Acceptance criteria:** no redirect leaves the authorized action; service cannot expose live routes anonymously; hostile output is inert; SSH input/secrets cannot alter/leak argv.
- **Tests:** loopback redirect matrix, API auth/bind/approval E2E, browser XSS/CSP, offline SSH argv/secret corpus.
- **Rollback:** feature flags remove direct/live/SSH functions; retain old behavior only on a non-default quarantined branch, never as silent fallback.
- **Dependencies:** identity/approval and SSH host-key decisions; no dependency on later architecture work.

### Phase 2 — Audit, privacy, and lab trust

- **Goal:** create trustworthy security evidence and a defensible lab boundary.
- **Exact scope:** ARGUS-005–007, structured redaction at all sinks, transactional audit/anchor design, pinned verifier image and negative route tests.
- **Out of scope:** regulated certification, full SIEM integration, production multi-tenancy.
- **Files expected to change:** policy/config, guardrail/audit/anchor, AI/report/error sinks, Compose/Dockerfiles/verifier, tests/docs.
- **Acceptance criteria:** secret corpus absent from all egress; audit survives concurrent/crash/truncation tests; every deliberate route leak makes isolation verification fail.
- **Tests:** end-to-end DLP corpus, multi-process/property/crash audit suite, Docker host/LAN/internet/DNS/IPv6/TCP matrix.
- **Rollback:** dual-read old audit records during a bounded migration; sanitizer can run in report-only shadow mode before enforcement, but no unsafe fallback after cutover.
- **Dependencies:** storage/anchor backend and supported Docker-platform decision.

### Phase 3 — Unified action and evidence kernel

- **Goal:** make the exact authorized action the exact executed/audited/evidenced action.
- **Exact scope:** ARGUS-008/009/011/012/013/015/019/020; immutable target/action, executable identity, typed outcomes, strict AI/evidence schemas and proof states.
- **Out of scope:** continuous scheduling and product UI features.
- **Files expected to change:** approval, config, guardrail, tools, sandbox, all orchestrators/parsers, AI, evidence/chains/correlation/PoC, schemas/tests.
- **Acceptance criteria:** all interfaces use one kernel; no representation drift; every finding cites immutable evidence; failures cannot look clean; model output never promotes proof or authorization.
- **Tests:** property/fuzz target/arg/parser suites, replay/context/PATH tests, cross-asset/provenance/model-injection scenarios.
- **Rollback:** version action/evidence schemas, retain read-only migration adapters, and make old writers unavailable after migration validation.
- **Dependencies:** Phases 1–2, architecture ADR, stable run IDs.

### Phase 4 — Reproducible runtime and run platform

- **Goal:** deliver an installable, isolated, observable, reproducible supervised scanner.
- **Exact scope:** ARGUS-014/016/017/018/023/024; per-run storage/containers, package metadata, pinned supply chain, installed-artifact CI, baseline telemetry/governance.
- **Out of scope:** 24/7 continuous mode and regulated-production claim.
- **Files expected to change:** sandbox/Compose/images, reporting/web/persistence, `pyproject.toml`/lock, CI/release/governance docs.
- **Acceptance criteria:** clean wheel/container install passes E2E; concurrent runs are isolated; images/tools are pinned/scanned/signed; required CI is green; run health/completeness is visible.
- **Tests:** installed-wheel smoke, container/resource/concurrency/cancel, rebuild/tamper/SBOM, release verification.
- **Rollback:** immutable versioned artifacts and schema migrations with backup/restore; keep previous signed release deployable.
- **Dependencies:** unified kernel and data schema from Phase 3.

### Phase 5 — Continuous service and product UX

- **Goal:** earn the 24/7 defensive-sensor claim.
- **Exact scope:** ARGUS-010/022 plus scheduler, leases, durable deltas, alerts, health/metrics, retention, backup, tenancy, run history/cancel/retry and naming migration.
- **Out of scope:** adding offensive/destructive tooling and any regulated certification not separately scoped.
- **Files expected to change:** continuous/agents/evidence/persistence, CLI/API/UI, observability/deployment/docs.
- **Acceptance criteria:** real guarded collectors run continuously; restart/multi-instance behavior is correct; alerts/deltas are durable/deduplicated; operators see ownership, progress, completeness, health and failures.
- **Tests:** days-compressed soak, crash/restart/lease/clock/backpressure, alert delivery/idempotency, tenant isolation and upgrade/rollback drills.
- **Rollback:** supervisor stops new leases, in-flight actions cancel safely, state schema supports rollback or forward-only restore from backup.
- **Dependencies:** all previous phases; an explicit production SLO/threat model.

## 13. Top 20 recommended GitHub issues

These are issue-ready drafts; no issues were created.

| Title | Problem and evidence | Acceptance criteria | Testing requirements | Priority | Suggested labels |
|---|---|---|---|---|---|
| Re-authorize every HTTP redirect and connected peer | Initial target is scoped, `urllib` follows another host; loopback probe confirmed | No denied hop/peer is contacted; hop chain audited | Redirect/DNS/rebinding/scheme matrix | P0 | `security`, `scope`, `ssrf` |
| Lock the web control plane to authenticated operators | Live scan/host/AD and `arm` lack identity/approval | Enforced local demo or authenticated role/action service | API auth/CSRF/rate/ownership E2E | P0 | `security`, `web`, `access-control` |
| Eliminate DOM XSS in result rendering | Untrusted result fields reach `innerHTML` | All hostile fields render inert; CSP active | Browser payload corpus | P0 | `security`, `frontend`, `xss` |
| Redesign SSH credential and argument handling | Username joins argv; password in `sshpass -p`; host keys disabled | Positive identity schema, secret-safe transport, verified host keys | Offline argv/secret + host-key tests | P0 | `security`, `ssh`, `credentials` |
| Implement structured sensitive-data controls | Seven common secret forms bypass current regexes | No sensitive corpus item reaches AI/report/audit/UI | End-to-end absence assertions | P0 | `security`, `privacy`, `dlp` |
| Make audit writes transactional and externally anchored | Truncation verifies; two writers fork; local anchor overwrites | Concurrent/crash-safe chain with immutable authenticated receipts | Multi-process/crash/rollback/link suite | P0 | `security`, `audit`, `integrity` |
| Replace the lab isolation verifier | Missing tools/install failure can look blocked | Missing prerequisite or any route leak fails nonzero | Host/LAN/internet/DNS/IPv6/TCP negatives | P0 | `security`, `docker`, `testing` |
| Introduce typed evidence proof states and prerequisites | Cross-asset keywords become observed paths | Hypothesis/supported/verified tied to immutable evidence/topology | Eight adversarial evidence scenarios | P0 | `evidence`, `architecture`, `correctness` |
| Centralize one-time action-bound approvals | Token replays and web paths bypass it | Exact action/policy/sandbox/operator binding and consumption | Replay/concurrency/context tests | P1 | `security`, `authorization` |
| Define immutable AuthorizedTarget and AuthorizedAction | Check/execution/audit use different strings | Same sealed object flows through every layer | Target property/fuzz tests | P1 | `architecture`, `scope` |
| Bind ToolSpec to verified executable/image identity | Logical name is not tied to PATH-resolved binary | Mismatch/PATH/symlink/wrapper substitution fails | Hostile PATH identity suite | P1 | `security`, `tooling`, `supply-chain` |
| Model typed collector completeness and failures | Missing/timeout/auth/parse errors can look empty | Every degradation is explicit in audit/API/report | Failure-injection matrix | P1 | `reliability`, `observability` |
| Harden per-run sandbox resources and cleanup | Shared root container and unlimited output/resources | Ephemeral bounded non-root run leaves no state/process | fork/output/cancel/concurrency tests | P1 | `security`, `sandbox`, `reliability` |
| Enforce strict AI output schema and provenance | Permissive JSON can fabricate evidence/assets | Only valid cited in-scope evidence is accepted | Malformed/injection/fabrication corpus | P1 | `ai-safety`, `evidence` |
| Create atomic per-run reports and ownership | Fixed files overwrite and contain active CSV/Markdown | Atomic isolated owned reports with inert content | concurrency/crash/formula/tenancy tests | P1 | `reporting`, `security`, `data` |
| Pin and attest images, tools, and templates | Rolling/latest/unverified downloads make runs mutable | Digests/hashes/signatures/SBOM and fail-closed install | rebuild/tamper/container scan | P1 | `supply-chain`, `docker`, `devsecops` |
| Make the Python package and clean lock authoritative | NetworkX absent; wheel 0.0.0 lacks CLI/assets/deps | Clean lock tests and installed wheel E2E pass | Python matrix/package smoke | P1 | `packaging`, `ci`, `dependencies` |
| Build an operable continuous runner | No entry point/durable state/recovery/alerts/health | Guarded real collection, leases, durable deduped deltas/alerts | restart/multi-instance/soak tests | P2 | `continuous`, `architecture`, `observability` |
| Reconcile Argus/Aegis and V1/V2 architecture | Duplicate names/models obscure supported path | ADR, stable/experimental boundary, staged migration | compatibility/docs checks | P2 | `architecture`, `maintenance`, `docs` |
| Establish release, license, and required CI gates | No license/release policy; lint/type/package/container gates absent | Licensed signed versioned artifact with required green gates | release verification and policy tests | P2 | `governance`, `release`, `ci` |

## 14. Final recommendation

| Disposition | Major subsystems |
|---|---|
| **Keep** | Literal-IPv4 normalization and longest-prefix policy core; fixed V1 registry/deterministic authorization; argv-only subprocess/process-group timeout; local env allowlist; WinRM secure defaults; hash lock/SHA-pinned Actions/dependency audit/SBOM; valuable negative guardrail tests. |
| **Fix** | Redirect scope handling, web exposure/rendering, SSH credentials/args/host keys, sanitization, audit serialization/anchoring, lab verification, parser outcomes/bounds, packaging/CI, reports, image/tool pins and documentation. |
| **Redesign** | Shared authorized action/target kernel, approval lifecycle, evidence/proof model and attack DAG, durable run/audit store, per-run sandbox, control-plane identity/ownership, and continuous service lifecycle. |
| **Defer** | New collectors, additional offensive tools, performance/cost optimization, regulated deployment, advanced dashboards, and expansion beyond a verified supervised lab until P0/P1 close. |
| **Remove or quarantine** | Direct HTTP redirects, unauthenticated live/armed web actions, `sshpass -p`/disabled host-key flow, false SMB/LDAP “proof,” current isolation success claim, and obsolete Pentagi deployment guidance until safely replaced. |

### Strengths to preserve

- Literal IPv4 canonicalization rejects ambiguous leading-zero forms, validates host bits, constrains broad CIDRs, and applies longest-prefix allow/deny behavior.
- Normal V1 actions use a fixed registry and argv arrays; no `shell=True` path was found. Timeout cleanup targets the process group.
- Local subprocess environments are rebuilt from an allowlist, explicitly excluding the audit key and common model keys.
- AI is advisory in the normal V1 planner and cannot directly authorize arbitrary binaries; authorization remains deterministic code.
- The audit key has a meaningful minimum length and HMAC comparison/canonical target-set binding use appropriate primitives.
- Compose avoids Docker socket, host networking, privileged mode, and host mounts; an internal network is a sound starting boundary.
- WinRM defaults to HTTPS with certificate validation.
- GitHub Actions are pinned to commit SHAs, Python dependencies are hash locked, dependency audit and Bandit are blocking, and an SBOM is generated.
- The test suite is quick and contains valuable negative guardrail cases; the codebase is small enough to harden without a wholesale rewrite.

### Audit-only change set and unverified items

This audit changed only `docs/ARGUS_GPT56_SOL_FULL_REPOSITORY_AUDIT.md` and `docs/ARGUS_AUDIT_FINDINGS.json`. No product code, tests, configuration, dependency files, workflows, Docker assets, or runtime resources were modified.

The following remain unverified: actual Docker route isolation on this Mac; behavior against a real authorized lab; real Nmap/Nuclei/LDAP/SSH/WinRM command versions and parsers; cloud AI provider calls/data handling; WORM anchor integration; multi-hour/multi-process continuous execution; browser exploit execution; container escape resistance; deployment TLS/reverse proxy/identity integration; release artifact signing; and legal/regulatory compliance. These are not assumed safe.
