# Phase 1 Safety Freeze and Execution-Boundary Closure

Phase 1 starts from audited commit
`634e99f94b0da73a0a8770b6a6008bce15f2832e`. It closes the five targeted defects without
implementing Phase 2.

## Enforced behavior

- **Redirects:** all redirects are refused. The direct urllib transport returns 301, 302, 303,
  307, or 308 plus the `Location` metadata without a second connection. Relative and absolute
  locations behave identically. Sandbox curl explicitly uses `--max-redirs 0` and never `-L`.
- **Web boundary:** the application authorizes only an IPv4 loopback, IPv6 loopback, or
  IPv4-mapped loopback from the actual ASGI socket peer. `Host`, `Forwarded`,
  `X-Forwarded-For`, and `X-Real-IP` are ignored. Proxy deployment is unsupported; there is no
  trusted-proxy mode in Phase 1.
- **Execution mode:** live web execution is disabled by default. Request JSON cannot select
  live mode, dry-run mode, or armed tools. Network scans default to server-enforced dry-run.
  Host and AD web endpoints return 403 unless the server starts with
  `ARGUS_WEB_LIVE_ENABLED=1`. Even then, the service remains a localhost-only, single-operator
  console and is not approved for network or multi-user deployment.
- **Web input/output:** API bodies with a declared size over 64 KiB are rejected before reading,
  and an ASGI receive wrapper counts actual streamed bytes so missing, chunked, or false length
  headers cannot exceed the 64 KiB limit. Validation errors are generic and do not echo request
  fields. API responses use `Cache-Control: no-store`; browser output uses DOM construction and
  `textContent`, and severity classes come from a fixed allowlist.
- **Dependency and package:** `networkx>=3.2,<4` is a declared runtime dependency and is
  hash-locked as `networkx==3.6.1`. Package metadata is `argus-security 0.1.0`, declares all
  runtime dependencies, exposes the `argus` CLI, and includes the static console.

## Current verification command

Run from `aegis/` with Python 3.12:

```bash
python -m pip install --require-hashes -r requirements.lock
PENTEST_AUDIT_HMAC_KEY=$(openssl rand -hex 32) python -m pytest --collect-only -q
PENTEST_AUDIT_HMAC_KEY=$(openssl rand -hex 32) python -m pytest -q
ruff check .
bandit -c pyproject.toml -r aegis --severity-level medium --confidence-level medium
pip-audit -r requirements.lock --strict --desc
python -m build
```

The Phase 1 branch collects **139 tests**. Exact final pass counts and the immutable tested SHA
are recorded in the draft pull request and delivery report.

## Historical versus current results

- Older 39, 72, and 75-test totals in the build history are historical snapshots whose exact
  commit was not recorded; they are not current verification.
- At audited baseline `634e99f`, 99 tests collected. A fresh hash-locked Python 3.12 install
  passed 97 and failed the two EvidenceGraph tests because `networkx` was missing.
- Phase 1 current behavior is the V1 supervised alpha plus the boundary closures above.
  V2 continuous-agent and evidence-fabric documents describe experimental scaffolding and
  target architecture, not production-ready or 24/7 behavior.

## Deferred work

Phase 2 is not implemented here. Structured secret/PHI controls, transactional audit storage,
lab-isolation proof, authenticated multi-user service design, durable continuous operation, and
evidence-model redesign remain deferred.
