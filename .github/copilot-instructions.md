# argus

Agentic AI penetration tester. Reasons, chains, and adapts across network, host, Active Directory, and web targets. Read-only by default behind a fail-closed 7-layer guardrail, with proof-annotated attack paths and HMAC-audited findings.

**Stack.** Python 3.12 - main package in `aegis/`. Claude / Ollama / offline model backends. Docker for lab targets.

**Layout.** `aegis/` engine, `frrlab/` + `targets/` lab fixtures, `pentagi/` integration, `scripts/`, `docs/`

## Build and test

```bash
python -m pip install --upgrade pip
pip install --require-hashes -r requirements.lock
python -m pytest -q
```

Run the tests before proposing a change is done. If you cannot run them, say so explicitly
rather than claiming the change is verified.

## Engineering conventions (non-negotiable)

- **Type hints on every function signature.** No bare `def f(x):`.
- **async/await for all I/O.** Never block the event loop with sync network or disk calls.
- **Immutable data.** Return new objects; do not mutate arguments in place.
- **Tests first.** Write the failing test, watch it fail, then implement. Target 80%+ coverage.
- **Small files.** 200-400 lines typical, 800 hard max. Extract modules rather than growing a file.
- **Small functions.** Under 50 lines. Nesting no deeper than 4 levels - use early returns.
- **Handle every error explicitly.** Never swallow an exception silently. Log context server-side,
  return a friendly message user-side.
- **Validate at boundaries.** Never trust user input, API responses, or file contents.
- **No hardcoded secrets, ever.** Environment variables or a secret manager only. No credentials
  in code, comments, logs, tests, or fixtures.
- **Conventional Commits**: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`, `perf:`, `ci:`.
  Imperative mood, lower case, no trailing period. Do **not** add `Co-authored-by` trailers.

## Before you propose a change

1. Read the surrounding code and match its idiom, naming, and comment density.
2. Prefer a battle-tested library over hand-rolled utility code.
3. If you touch auth, user input, DB queries, file paths, or external calls, re-read the
   security rules above before finishing.

## Safety model - read this before changing anything under `aegis/`

This is offensive-security tooling. The guardrail layers are the product, not overhead.

- **Read-only by default.** Any code path that can write, modify, or disrupt a target must be
  gated behind an explicit opt-in flag *and* the existing guardrail chain. Never add a
  bypass, a "just for testing" escape hatch, or a default-on destructive action.
- **Fail closed.** If a guardrail check errors or is indeterminate, the action is denied.
  Never convert a guardrail failure into a warning.
- **Audit integrity.** Findings are HMAC-signed. Do not weaken, skip, or make optional any
  signing or audit-trail write.
- **Scope enforcement.** Targets outside the declared scope are refused. Do not add wildcard
  or inferred-scope expansion.
- `bandit` (severity/confidence >= medium) and `pip-audit` gate CI. Do not add `# nosec`
  without a comment justifying it.

## Pull requests

- Title in Conventional Commits form.
- Body covers: what changed, why, blast radius, and a test plan as a checklist.
- Summarise the whole commit range, not just the last commit.
