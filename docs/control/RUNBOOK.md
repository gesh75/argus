# Argus Release and Operations Runbook

## Safety prerequisites

This runbook uses synthetic keys and local files only. Do not run real scans,
send target traffic, use real credentials, start a production service, or
process regulated data.

Use Python 3.12 and the hash-locked dependency tree. Keep the Phase 1 V1 backup
read-only. A Phase 1 binary must never open a log after Phase 2A has written a
V2 record.

## Release verification

From the repository root:

```bash
python3.12 -m venv /tmp/argus-release-venv
/tmp/argus-release-venv/bin/python -m pip install --upgrade pip
/tmp/argus-release-venv/bin/python -m pip install \
  --require-hashes -r aegis/requirements.lock

cd aegis
PENTEST_AUDIT_HMAC_KEY=$(openssl rand -hex 32) \
  /tmp/argus-release-venv/bin/python -m pytest --collect-only -q
PENTEST_AUDIT_HMAC_KEY=$(openssl rand -hex 32) \
  /tmp/argus-release-venv/bin/python -m pytest -q

ruff check .
bandit -c pyproject.toml -r aegis \
  --severity-level medium \
  --confidence-level medium
pip-audit -r requirements.lock --strict --desc
```

Compare machine-readable Ruff results against a clean `origin/main` archive,
and run Ruff on every changed Python file. No new, changed, ignored, or
suppressed finding is accepted.

## Deterministic documentation

From the repository root:

```bash
python scripts/generate_control_dashboard.py --output /tmp/argus-index-1.html
python scripts/generate_control_dashboard.py --output /tmp/argus-index-2.html
shasum -a 256 /tmp/argus-index-1.html /tmp/argus-index-2.html
cmp /tmp/argus-index-1.html /tmp/argus-index-2.html
python -m json.tool docs/control/STATUS.json >/dev/null
```

The two hashes must match and the control-document tests must pass.

## Clean archive build and wheel smoke

```bash
repo_root=$(git rev-parse --show-toplevel)
package_root=$(mktemp -d)
smoke_root=$(mktemp -d)
git -C "$repo_root" archive HEAD aegis | tar -x -C "$package_root"
cd "$package_root/aegis"
python -m build
python3.12 -m venv "$smoke_root/venv"
"$smoke_root/venv/bin/python" -m pip install --upgrade pip
"$smoke_root/venv/bin/python" -m pip install dist/argus_security-*.whl
"$smoke_root/venv/bin/argus" --help
"$smoke_root/venv/bin/argus" audit --help
```

Smoke changed CLI behavior without live execution:

```bash
"$smoke_root/venv/bin/argus" --help
"$smoke_root/venv/bin/argus" audit --help
```

## Audit diagnosis and recovery

Plain diagnosis is read-only:

```bash
argus audit
```

- exit `0`: valid log and admissible anchor;
- exit `1`: integrity/consistency failure or unmet recovery precondition;
- exit `2`: usage, configuration, platform, trust, permission, lock, or I/O
  prevented reliable completion.

Bootstrap only a missing anchor for a valid populated log:

```bash
argus audit --bootstrap-anchor --confirm
```

Reconcile only a proven stale anchor:

```bash
argus audit --reconcile-anchor --confirm
```

Never truncate, rewrite, renumber, skip, or automatically repair an audit
record. Preserve malformed and divergent states for investigation.

## Rollback

1. Stop every Argus writer.
2. Determine whether the active log contains any V2 record.
3. If V2 exists, preserve the log and anchor read-only. Never point Phase 1 at
   them.
4. Restore the matched pre-upgrade V1 log/anchor pair, or configure Phase 1 to
   a separately recorded new empty audit path.
5. Never downgrade or remove V2 records.
6. For the release-closeout code itself, revert the merge commit only after
   preserving any audit state and re-run the complete release gate.

## Deployment boundary

No deployment is part of release closeout. A future supervised lab deployment
must independently verify Docker network isolation, written authorization,
exact CIDR scope, exclusions, non-production credentials, audit parent
ownership/modes, and server bind address before execution.

## Delivered closeout baseline

- PR: [#17](https://github.com/gesh75/argus/pull/17)
- Reviewed branch head:
  `8f1fed7d88c821f926c332ea691f151c58d73dbd`
- Merge commit:
  `b75af239c441204699114ce34970e37b394b3c21`
- Post-merge CI:
  [30523751828](https://github.com/gesh75/argus/actions/runs/30523751828)
- Post-merge CodeQL:
  [30523751784](https://github.com/gesh75/argus/actions/runs/30523751784)
- Deployment: no Argus runtime, live target, or unattended service deployed.

Preserve the feature branch temporarily for forensic comparison. Any future
increment starts from current `main` on a fresh branch and reruns this entire
gate.
