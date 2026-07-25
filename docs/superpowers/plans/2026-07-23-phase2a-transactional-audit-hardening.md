# Phase 2A Transactional Audit Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the approved fail-closed, concurrent-writer-safe, versioned Argus audit chain without changing Phase 1 execution or web boundaries.

**Architecture:** Keep `AuditLog` in `guardrail.py` as the compatibility façade. Move strict V1/V2 replay, trusted-parent file access, one-shot POSIX locking, and durable V2 append behavior into a focused `audit_storage.py`; keep strict local-anchor persistence and classification in `anchor.py`. Normal construction remains fail closed, while CLI-only diagnostics and explicitly confirmed anchor recovery use a permanently write-disabled path.

**Tech Stack:** Python 3.12+, standard-library `fcntl`, `os`, `json`, `hmac`, `hashlib`, `dataclasses`, `enum`, `pathlib`, `threading`, `time`, `contextlib`, `multiprocessing`, pytest, Ruff, Bandit, pip-audit, setuptools/build.

## Global Constraints

- Source specification: `docs/superpowers/specs/2026-07-23-phase2a-transactional-audit-hardening-design.md` at `6c7cceda6f42843f78f868904d3d61d28cf6ede4`.
- Phase 1 base: `7303089afcec5227700618b98c48f1a1c3f6c15f`.
- Controller support is POSIX macOS/Linux with `fcntl.flock`; Windows remains a scan target, not a supported audit-writer host.
- Use no new runtime dependency and do not regenerate `requirements.lock`.
- Preserve `AuditLog.write() -> str`, `AuditLog.verify() -> bool`, and `AuditLog.cross_check_anchor() -> tuple[bool, str]`.
- V2 is always chained, uses `audit_version: 2`, signs `seq`, and uses domain prefix `b"ARGUS-AUDIT-V2\0"`.
- Never rewrite, migrate, truncate, discard, or automatically repair an existing audit record.
- Never use a cached chain tip as write authority.
- Acquire the in-process lock before one lock-file descriptor and one successful outer-operation `flock`; helpers never reacquire it.
- Use a fixed, non-configurable 10.0-second monotonic lock-acquisition deadline.
- Use the approved trusted-parent-directory model; do not claim race-free intermediate-component traversal.
- All new lock, log, anchor, and temporary-anchor files use mode `0600`.
- Test crash controls remain private dependency injection, never CLI, environment, policy, web, or production configuration.
- All audit tests use temporary directories and synthetic keys.
- Do not modify web console boundaries, collectors, tool policies or values, allowlists, agents, EvidenceGraph, continuous mode, AI prompts, PoC behavior, authentication, multi-user behavior, or SIEM integration.
- If implementation inspection proves an approved design technically impossible, stop, document the exact conflict, and request review before changing the design.

---

## 1. Baseline verification and stop conditions

Run these commands before any implementation work:

```bash
git fetch origin main phase2a-transactional-audit-hardening
git status --short
git branch --show-current
git rev-parse HEAD
git merge-base HEAD main
git diff --stat main...HEAD
git merge-base HEAD origin/main
git diff --stat origin/main...HEAD
git merge-base --is-ancestor 6c7cceda6f42843f78f868904d3d61d28cf6ede4 HEAD
git merge-base --is-ancestor 7303089afcec5227700618b98c48f1a1c3f6c15f HEAD
git diff --name-status 7303089afcec5227700618b98c48f1a1c3f6c15f...HEAD
```

Expected branch:

```text
phase2a-transactional-audit-hardening
```

The current repository has a stale local `main` reference at
`7b7970bfe7cabb6b72a68616b197acbf26c226a7`; authoritative `origin/main` is
`7303089afcec5227700618b98c48f1a1c3f6c15f`. Before implementation, either
fast-forward `main` in its owning checkout or use `origin/main` for the
authoritative comparison. Do not interpret the stale local-main diff as Phase
2A scope.

Stop before editing if:

- `git status --short` contains anything other than an explicitly authorized
  implementation-plan document;
- the branch name differs;
- the approved specification commit is not an ancestor;
- `origin/main` is not the Phase 1 baseline;
- the branch contains non-documentation changes before implementation starts;
- completing the work would require weakening a Phase 1 boundary.

Record the exact pre-implementation HEAD in the implementation session report.

## 2. Current Phase 1 code and caller mapping

### 2.1 Current lifecycle

The current code performs:

```text
Guardrail.__init__
  → AuditLog.__init__
  → _last_state() reads lines and silently skips malformed JSON/missing HMAC
  → authorize/deny/record calls AuditLog.write()
  → write() signs from cached _prev, appends text without lock/fsync
  → optional write_anchor() overwrites local JSON
  → verify() later replays HMACs without strict schema/sequence validation
```

This creates the Phase 2A race: separate processes can cache the same `_prev`
and append conflicting next records.

### 2.2 Existing public and internal APIs

| File/API | Current behavior | Compatibility requirement |
|---|---|---|
| `aegis/aegis/guardrail.py:102` `AuditLog(policy)` | Loads key, creates parent directories, caches `_prev`/`_seq` from permissive replay | Keep normal constructor, but validate the complete log/anchor under one outer lock and fail closed |
| `AuditLog.write(event) -> str` | Signs V1 using cached state, text-appends, optionally writes anchor | Keep return type; write V2 only after locked replay and durability |
| `AuditLog.verify() -> bool` | Replays current policy mode and may raise parsing errors | Keep Boolean result; use locked strict replay and configured-anchor admission |
| `AuditLog.cross_check_anchor() -> tuple[bool, str]` | Reads anchor separately and leaks abbreviated tips in mismatch text | Keep tuple shape; use locked classification and redacted categories |
| `Guardrail(policy, armed)` | Constructs `AuditLog` before budget/authorization | Preserve fail-closed ordering |
| `aegis/aegis/anchor.py` `read_anchor`/`write_anchor` | Unlocked, permissive, non-durable path operations | Replace with internal lock-held strict APIs; no external caller depends on these as public package APIs |
| `Policy.audit_path` | Absolute or repo-relative `Path` | Preserve configuration value; require its parent to be pre-provisioned and trusted |
| `Policy.audit_chained` | Selects chained or unchained V1 behavior | Derive V1 semantics from stored `prev`; refuse every new V2 write when false |
| `Policy.audit_anchor_path` | Optional path | Preserve optional behavior; classify every configured state |
| `cmd_audit(args) -> int` | Constructs full `Guardrail`, then calls verify/cross-check | Switch to read-only diagnostic construction and exit codes 0/1/2 |
| `cli.main(argv) -> int` | Catches `GuardrailError` and returns 2 | Preserve operational-failure mapping |

Private `_prev`, `_seq`, `_path`, and `_anchor_path` are not compatibility
contracts. Tests must stop treating cached `_prev`/`_seq` as authoritative.

### 2.3 Production callers affected

All existing calls continue using the façade:

- `Guardrail.authorize()` writes `authorize`;
- `Guardrail.authorize_host()` writes `authorize_host`;
- `Guardrail._deny()` writes `deny` before raising;
- `Guardrail.record()` writes `exec_done`;
- `Orchestrator.run()` writes `scan_complete`;
- `host/runner.py` writes `host_scan_complete`;
- `host/winrm_collector.py` writes `win_host_scan_complete`;
- `host/ad.py` writes `ad_scan_complete`;
- `web.py` reads `guard.audit.verify()` for response/report state;
- `cli.py` currently verifies through a full `Guardrail` and must be separated.

No caller receives or supplies a sequence, `prev`, timestamp, HMAC, format
version, lock, or anchor object. Reserved audit fields remain storage-owned.

### 2.4 Existing tests affected

| Test file | Current audit coverage/change |
|---|---|
| `tests/test_guardrail.py` | Temp log; update tamper test for strict V2 and public API assertions |
| `tests/test_p1_hardening.py` | Key strength and three anchor tests; preserve intent but stop reading private `_prev` and permissive `anchor.read_anchor` |
| `tests/test_integration_agentic.py` | Temp log and `verify()` regression; retain |
| `tests/test_host.py`, `tests/test_winad.py` | Already use temp audit paths; retain |
| `tests/test_agent.py` | Constructs `Guardrail` against ignored default `aegis/output`; redirect every helper-created guard to a pre-provisioned `tmp_path` |
| `tests/test_webrecon.py` | Same default-path issue; redirect guard helpers to `tmp_path` |
| `tests/test_web_security.py` | Phase 1 boundary regression; do not change web behavior |
| all remaining tests | Full-suite regression only |

No tracked V1 `.ndjson` or `.jsonl` fixture exists. Compatibility tests must
construct independently signed synthetic V1 records from the Phase 1 byte
contract.

## 3. Planned `audit_storage.py` module and API

Create `aegis/aegis/audit_storage.py`. It is internal and has no package-level
re-export.

### 3.1 Constants and value types

Planned declarations:

```python
AUDIT_VERSION = 2
GENESIS = "genesis"
V2_DOMAIN_SEPARATOR = b"ARGUS-AUDIT-V2\0"
LOCK_TIMEOUT_SECONDS = 10.0
FILE_MODE = 0o600
RESERVED_FIELDS = frozenset({"audit_version", "seq", "ts", "prev", "hmac"})

type JsonScalar = None | bool | int | float | str
type JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
```

Enums:

```python
class AuditFailureCode(StrEnum)
class LogState(StrEnum)
class AnchorState(StrEnum)
class AuditCheckpoint(StrEnum)
```

`AuditFailureCode` contains stable, non-sensitive categories:

```text
malformed-json
duplicate-key
invalid-utf8
non-object-json
invalid-schema
invalid-version
invalid-sequence
invalid-prev
invalid-hmac
invalid-timestamp
unterminated-record
write-disabled
unsupported-platform
unsafe-parent
unsafe-owner
unsafe-mode
non-regular-file
symlink
lock-timeout
io-failure
anchor-missing
anchor-stale
anchor-ahead
anchor-divergent
anchor-malformed
```

`LogState` values match the approved diagnostic vocabulary:

```text
empty
valid-v1
valid-v2
valid-v1-v2
malformed
invalid-schema
invalid-sequence
invalid-prev
invalid-hmac
```

`AnchorState` values are:

```text
disabled
uninitialized
match
missing
stale
ahead
divergent
malformed
not-comparable
```

`AuditCheckpoint` is private test-seam vocabulary for deterministic boundaries:

```text
after-log-fsync
after-anchor-file-fsync
after-anchor-replace
after-anchor-directory-fsync
```

### 3.2 Errors and immutable models

Planned signatures:

```python
class AuditStorageError(Exception):
    code: AuditFailureCode
    record_number: int | None

@dataclass(frozen=True, slots=True)
class V1Record:
    seq: int
    ts: int | float
    prev: str | None
    event: str
    hmac: str
    chained: bool

@dataclass(frozen=True, slots=True)
class V2Record:
    audit_version: Literal[2]
    seq: int
    ts: int | float
    prev: str
    event: str
    hmac: str

type VerifiedRecord = V1Record | V2Record

@dataclass(frozen=True, slots=True)
class ReplayResult:
    state: LogState
    records: tuple[VerifiedRecord, ...]
    count: int
    tip: str
    final_ts: int | float | None

@dataclass(frozen=True, slots=True)
class AppendResult:
    seq: int
    hmac: str
    ts: int | float

@dataclass(frozen=True, slots=True)
class DiagnosticReport:
    log_state: LogState
    anchor_state: AnchorState
    record_count: int
    error_code: AuditFailureCode | None
    error_record: int | None
```

`AuditStorageError.__str__()` renders only the stable category and optional
record number. It never stores raw bytes, decoded record dictionaries, keys,
event values, HMAC values, or paths in exception text.

### 3.3 Strict decode and record functions

Planned internal signatures:

```python
def strict_json_object(raw: bytes, *, record_number: int | None) -> dict[str, JsonValue]
def decode_v1_record(data: dict[str, JsonValue], *, seq: int) -> V1Record
def decode_v2_record(data: dict[str, JsonValue], *, expected_seq: int) -> V2Record
def canonical_v1_body(data_without_hmac: dict[str, JsonValue]) -> bytes
def canonical_v2_body(data_without_hmac: dict[str, JsonValue]) -> bytes
def verify_v1_hmac(record_data: dict[str, JsonValue], *, key: bytes, expected_prev: str) -> V1Record
def verify_v2_hmac(record_data: dict[str, JsonValue], *, key: bytes, expected_seq: int, expected_prev: str) -> V2Record
def encode_v2_record(
    event: Mapping[str, JsonValue],
    *,
    key: bytes,
    seq: int,
    prev: str,
    ts: int | float,
) -> tuple[bytes, AppendResult]
```

Strict decoding uses `object_pairs_hook` to reject duplicate keys,
`parse_constant` to reject non-finite constants, UTF-8 strict decoding, exactly
one object, and explicit Boolean exclusion for numeric fields. V1 accepts
neither `audit_version` nor `seq`; V2 requires both and rejects partial version
fields.

`canonical_v1_body()` uses sorted keys, separators `(",", ":")`,
`ensure_ascii=True`, and `allow_nan=False`. `canonical_v2_body()` uses sorted
keys, the same separators, `ensure_ascii=False`, and `allow_nan=False`.
`encode_v2_record()` signs
`V2_DOMAIN_SEPARATOR + canonical_v2_body(body)`; the terminating newline is
persisted but not signed.

### 3.4 Trusted parent and held lock

Planned types:

```python
class _AuditIO(Protocol)
class _PosixAuditIO

@dataclass(slots=True)
class TrustedParent:
    path: Path
    fd: int
    owner_uid: int

    @classmethod
    def open(cls, parent: Path, *, io: _AuditIO) -> Self

    def open_regular(
        self,
        name: str,
        flags: int,
        *,
        create_mode: int = FILE_MODE,
    ) -> int

    def replace(self, source_name: str, destination_name: str) -> None
    def unlink_regular(self, name: str) -> None
    def fsync(self) -> None
    def close(self) -> None

@dataclass(slots=True)
class HeldAuditLock:
    audit_parent: TrustedParent
    lock_fd: int
    audit_name: str
    lock_name: str
    _token: object

    def assert_held(self) -> None
```

`_AuditIO` is the only private injection seam. It covers filesystem calls,
`flock`, monotonic time, bounded wait, and
`checkpoint(point: AuditCheckpoint) -> None`. Production checkpoints are
no-ops; tests can terminate at deterministic boundaries. `_PosixAuditIO` is
always selected by production construction. Nothing selects an adapter through
environment, policy, CLI, or web input.

`TrustedParent.open()` resolves the parent once, opens the directory, and
checks directory type, effective-user ownership, and absence of group/world
write bits. It does not create missing parents. Final files are opened relative
to `fd`, with `O_CLOEXEC`, `O_NOFOLLOW` where supported, then `fstat` type,
owner, and mode checks.

### 3.5 Storage object and lock-held operations

Planned signatures:

```python
class AuditStorage:
    def __init__(
        self,
        audit_path: Path,
        *,
        key: bytes,
        chained: bool,
        anchor_path: Path | None,
        _io: _AuditIO | None = None,
    ) -> None

    @contextmanager
    def locked_operation(self) -> Iterator[HeldAuditLock]

    def replay_locked(self, held: HeldAuditLock) -> ReplayResult

    def append_v2_locked(
        self,
        held: HeldAuditLock,
        replay: ReplayResult,
        event: Mapping[str, JsonValue],
        *,
        ts: int | float,
    ) -> AppendResult

    def open_anchor_parent_locked(self, held: HeldAuditLock) -> TrustedParent | None
```

`locked_operation()` takes the path-keyed in-process `RLock`, opens one lock
file descriptor, polls `LOCK_EX | LOCK_NB` on that descriptor until the fixed
deadline, yields one `HeldAuditLock`, then closes/releases exactly once. Every
other storage/anchor helper requires `held.assert_held()` and never opens or
acquires a lock.

`replay_locked()` reads bytes only while held, requires every record to end in
one newline, validates every record, enforces one uniform V1 mode, permits one
V1→V2 transition, and returns metadata only. It never silently skips a line.

`append_v2_locked()` refuses `chained=False`, reserved caller fields, invalid
event values, or a replay not proven valid. It constructs one encoded record,
opens with append/create/no-follow/close-on-exec, completes short writes, calls
log `fsync`, and returns only after that boundary. Anchor work remains in the
same outer operation but is orchestrated by the façade.

## 4. Planned anchor and façade APIs

### 4.1 `anchor.py`

Planned immutable model and functions:

```python
@dataclass(frozen=True, slots=True)
class AnchorRecord:
    seq: int
    tip: str
    ts: int | float

@dataclass(frozen=True, slots=True)
class AnchorReadResult:
    state: AnchorState
    record: AnchorRecord | None

def read_anchor_locked(
    held: HeldAuditLock,
    parent: TrustedParent,
    name: str,
) -> AnchorReadResult

def classify_anchor(
    replay: ReplayResult,
    read_result: AnchorReadResult,
    *,
    configured: bool,
) -> AnchorState

def write_anchor_locked(
    held: HeldAuditLock,
    parent: TrustedParent,
    name: str,
    record: AnchorRecord,
) -> None

def cleanup_anchor_temps_locked(
    held: HeldAuditLock,
    parent: TrustedParent,
    anchor_name: str,
) -> None
```

`classify_anchor()` compares `seq`, `tip`, and the corresponding signed record
`ts`. A well-formed anchor is `not-comparable` when replay is invalid. Temp
files use a private exact prefix based on the anchor basename, exclusive mode
`0600` creation, file `fsync`, descriptor-relative replace, then parent
directory `fsync`. Cleanup removes only safe, owner-matching, regular temp
files under the already-held audit lock.

### 4.2 `guardrail.py`

Planned façade signatures:

```python
class AuditLog:
    def __init__(self, policy: Policy) -> None

    @classmethod
    def _for_diagnostics(cls, policy: Policy) -> _DiagnosticAuditLog

    def write(self, event: dict[str, JsonValue]) -> str
    def verify(self) -> bool
    def cross_check_anchor(self) -> tuple[bool, str]

class _DiagnosticAuditLog:
    def inspect(self) -> DiagnosticReport
    def bootstrap_anchor(self, *, confirmed: bool) -> DiagnosticReport
    def reconcile_anchor(self, *, confirmed: bool) -> DiagnosticReport
    def write(self, event: dict[str, JsonValue]) -> NoReturn
```

Normal construction loads and validates the key, constructs `AuditStorage`,
then performs one locked replay and configured-anchor admission. Only empty +
uninitialized or valid + matching/disabled states return.

`write()` performs within one outer lock:

```text
replay → anchor classify → V2 encode → append/write loop → log fsync
→ anchor temp write/fsync/replace/directory fsync → return HMAC
```

The façade never uses `_prev` or `_seq` as authority. It may expose no mutable
tip cache. Storage errors are translated to redacted `GuardrailError`.

The diagnostic façade never creates `Guardrail`, never exposes a writable
storage method, and never returns to production call sites. Bootstrap and
reconcile retain one outer lock from classification through the permitted
anchor-only mutation.

### 4.3 `cli.py`

Add mutually exclusive audit options:

```text
argus audit
argus audit --bootstrap-anchor --confirm
argus audit --reconcile-anchor --confirm
```

Planned logic:

```python
def cmd_audit(args: argparse.Namespace) -> int
def _print_audit_report(report: DiagnosticReport) -> None
```

Exit mapping:

- `0`: healthy diagnosis or durable requested recovery;
- `1`: integrity/consistency failure or unmet recovery precondition;
- `2`: usage, configuration, key, platform, trusted-parent, permission,
  timeout, or I/O prevented reliable completion.

Output includes stable states and sequence counts only. It never prints HMAC
tips or event contents.

## 5. File-by-file change inventory

| File | Responsibility and exact change | Connected tests | Rollback implication |
|---|---|---|---|
| `aegis/aegis/audit_storage.py` | New internal strict models, decoder, replay, trusted-parent handle, held-lock context, timeout, V2 encoder, durable append, redacted errors, private I/O seam | `test_audit_storage.py`, `test_audit_filesystem.py`, `test_audit_concurrency.py` | Phase 1 cannot verify V2; never reuse a V2 log after code rollback |
| `aegis/aegis/guardrail.py` | Replace permissive `AuditLog` internals with storage façade; add write-disabled diagnostics; preserve public methods | existing guardrail/integration tests plus storage/CLI tests | Restore code only with matched V1 backup or rotate to a new empty Phase 1 log |
| `aegis/aegis/anchor.py` | Replace permissive path functions with strict lock-held anchor read/classify/atomic replace/temp cleanup | `test_audit_anchor.py` | Local anchor remains a consistency file, not WORM |
| `aegis/aegis/cli.py` | Use diagnostics for `audit`; add explicit bootstrap/reconcile confirmation and exit mapping | `test_audit_cli.py` | Old CLI must never inspect/append V2 operationally |
| `aegis/aegis/config.py` | Correct comments to state local-anchor/trusted-parent semantics; no field/value change | config/full regression | No configuration migration |
| `aegis/tests/audit_support.py` | Synthetic policy/V1 builders, strict record reader, top-level spawn workers, private test adapters | all new audit test modules | Test-only |
| `aegis/tests/test_audit_storage.py` | Strict formats, replay, V1/V2 transition, corruption, public semantics | required cases 1–12, 21–22 and strict additions | Test-only |
| `aegis/tests/test_audit_filesystem.py` | Parent/file protections, modes, lock acquisition/deadline, short writes | filesystem/lock additions | Test-only |
| `aegis/tests/test_audit_anchor.py` | Anchor state matrix, atomic write, bootstrap/reconcile primitives | required cases 16–20 and recovery additions | Test-only |
| `aegis/tests/test_audit_cli.py` | Read-only diagnostics, exit codes, recovery confirmation, redaction/help | diagnostic additions | Test-only |
| `aegis/tests/test_audit_concurrency.py` | Separate-process contention/stress/crash boundaries | required cases 13–15 plus durability crashes | Test-only |
| `aegis/tests/test_guardrail.py` | Adapt tamper test to strict V2 and assert Boolean/public behavior | public compatibility | Test-only |
| `aegis/tests/test_p1_hardening.py` | Preserve key/anchor regression without private tip/cache assertions | Phase 1 regressions | Test-only |
| `aegis/tests/test_agent.py` | Redirect helper-created `Guardrail` instances to pre-provisioned `tmp_path` | full regression | Test isolation only |
| `aegis/tests/test_webrecon.py` | Redirect helper-created `Guardrail` instances to pre-provisioned `tmp_path` | full regression | Test isolation only |
| `aegis/SECURITY.md` | State transactional guarantee, local-anchor limit, diagnostic/recovery rules | documentation review | Restore with code only |
| `aegis/docs/PHASE2A_AUDIT_OPERATIONS.md` | New deployment, bootstrap, reconciliation, failure, recovery, and rollback runbook | command/document review | Preserves V2 logs read-only |
| `aegis/docs/NEXT_STEPS.md` | Correct the claim that a local JSON path is already WORM-ready | documentation review | None |
| `targets/scope-policy.yaml` | Comment-only correction of local anchor claims; no policy value, scope, tool, or allowlist change | full regression | None |

Changes to `test_agent.py`, `test_webrecon.py`, and the comment in
`targets/scope-policy.yaml` are outside the narrow implementation modules but
are explicitly justified: the tests must not touch the ignored default audit
path, and operator-facing configuration comments must not describe ordinary
local JSON as WORM. No runtime policy value changes.

Do not change `.github/workflows/ci.yml`, `pyproject.toml`, requirements files,
web code, collectors, agents, evidence, continuous runner, prompts, PoC code,
scope values, or tool lists.

## 6. Task and commit sequence

Every numbered implementation task uses a RED checkpoint followed by a GREEN
checkpoint. A RED commit is coherent when its new tests execute and fail only
for the intended missing behavior, with no syntax, setup, or unrelated
failures.

### Task 1: Strict models, decoding, and V1/V2 replay

**Files:**

- Create: `aegis/aegis/audit_storage.py`
- Create: `aegis/tests/audit_support.py`
- Create: `aegis/tests/test_audit_storage.py`

**Interfaces:**

- Produces: constants, enums, `AuditStorageError`, record models,
  `ReplayResult`, strict decode/canonical/signature functions.
- Consumes: approved V1/V2 byte contracts and synthetic key/path fixtures.

- [ ] Add executable tests for strict JSON, V1 chained/unchained verification,
  V2 verification, transitions, sequence/type confusion, HMAC changes, and
  malformed tails.
- [ ] Run:

  ```bash
  PENTEST_AUDIT_HMAC_KEY=$(openssl rand -hex 32) \
    python -m pytest -q tests/test_audit_storage.py
  ```

  Expected: RED only because `aegis.audit_storage` and its declared behavior do
  not yet exist.

- [ ] Commit RED:

  ```bash
  git add aegis/tests/audit_support.py aegis/tests/test_audit_storage.py
  git commit -m "test(audit): define strict V1 and V2 replay contract"
  ```

- [ ] Implement the declarations in Sections 3.1–3.3, byte-for-byte
  canonicalization, strict parser, replay state machine, and redacted errors.
- [ ] Re-run the focused file; expected GREEN.
- [ ] Commit GREEN:

  ```bash
  git add aegis/aegis/audit_storage.py
  git commit -m "feat(audit): add strict versioned replay"
  ```

### Task 2: Trusted-parent access and one-acquisition locking

**Files:**

- Modify: `aegis/aegis/audit_storage.py`
- Create: `aegis/tests/test_audit_filesystem.py`

**Interfaces:**

- Produces: `_AuditIO`, `_PosixAuditIO`, `TrustedParent`, `HeldAuditLock`,
  `AuditStorage.locked_operation()`.
- Consumes: `AuditFailureCode`, fixed `LOCK_TIMEOUT_SECONDS`, mode constants.

- [ ] Add tests for trusted parents, final symlinks, non-regular files, unsafe
  owner/mode, one descriptor/acquisition, missing held context, virtual timeout,
  and process-exit lock release.
- [ ] Run focused filesystem tests; expected RED for absent types/behavior.
- [ ] Commit RED:

  ```bash
  git add aegis/tests/test_audit_filesystem.py
  git commit -m "test(audit): define filesystem and lock invariants"
  ```

- [ ] Implement descriptor-relative file access and the outer lock context.
  Use the same descriptor for nonblocking polls; helpers require the held token.
- [ ] Run `test_audit_storage.py` and `test_audit_filesystem.py`; expected GREEN.
- [ ] Commit GREEN:

  ```bash
  git add aegis/aegis/audit_storage.py
  git commit -m "feat(audit): add trusted-parent locking"
  ```

### Task 3: Durable V2 append and corruption refusal

**Files:**

- Modify: `aegis/aegis/audit_storage.py`
- Modify: `aegis/tests/test_audit_storage.py`
- Modify: `aegis/tests/test_audit_filesystem.py`

**Interfaces:**

- Produces: `AuditStorage.replay_locked()` and
  `AuditStorage.append_v2_locked()`.
- Consumes: strict replay, held lock, trusted parent, I/O adapter.

- [ ] Add tests for complete pre-encoding, reserved-field refusal, short-write
  completion, append `fsync`, mode `0600`, corrupted-history refusal, and
  `audit_chained: false` refusal.
- [ ] Run focused files; expected RED for append behavior.
- [ ] Commit RED:

  ```bash
  git add aegis/tests/test_audit_storage.py aegis/tests/test_audit_filesystem.py
  git commit -m "test(audit): define durable append boundary"
  ```

- [ ] Implement V2 append exactly as the locked replay→encode→append→`fsync`
  sequence. Do not add an anchor call here.
- [ ] Run focused files; expected GREEN.
- [ ] Commit GREEN:

  ```bash
  git add aegis/aegis/audit_storage.py
  git commit -m "feat(audit): add durable V2 append"
  ```

### Task 4: Atomic anchor storage and classification

**Files:**

- Modify: `aegis/aegis/anchor.py`
- Create: `aegis/tests/test_audit_anchor.py`

**Interfaces:**

- Produces: `AnchorRecord`, `AnchorReadResult`, strict read, state
  classification, atomic write, temp cleanup.
- Consumes: `HeldAuditLock`, `TrustedParent`, `ReplayResult`, `AnchorState`.

- [ ] Add anchor tests for every state, timestamp semantics, unsafe files,
  write/replace/directory-`fsync` ordering, temp cleanup, and write failure.
- [ ] Run focused anchor tests; expected RED.
- [ ] Commit RED:

  ```bash
  git add aegis/tests/test_audit_anchor.py
  git commit -m "test(audit): define anchor consistency states"
  ```

- [ ] Replace permissive `read_text`/`write_text` functions with the lock-held
  APIs in Section 4.1 and correct the module's WORM claims.
- [ ] Run storage/filesystem/anchor tests; expected GREEN.
- [ ] Commit GREEN:

  ```bash
  git add aegis/aegis/anchor.py
  git commit -m "feat(audit): add durable anchor classification"
  ```

### Task 5: `AuditLog` façade integration

**Files:**

- Modify: `aegis/aegis/guardrail.py`
- Modify: `aegis/tests/test_guardrail.py`
- Modify: `aegis/tests/test_p1_hardening.py`
- Modify: `aegis/tests/test_integration_agentic.py`
- Modify: `aegis/tests/test_agent.py`
- Modify: `aegis/tests/test_webrecon.py`

**Interfaces:**

- Produces: fail-closed normal `AuditLog`, public `write`/`verify`/cross-check.
- Consumes: `AuditStorage` and lock-held anchor functions.

- [ ] Update/add tests for normal startup rejection, public return shapes,
  configured/disabled anchor admission, V1→V2 write, and temp-path isolation.
- [ ] Run all listed test files; expected RED only for façade integration.
- [ ] Commit RED:

  ```bash
  git add aegis/tests/test_guardrail.py aegis/tests/test_p1_hardening.py \
    aegis/tests/test_integration_agentic.py aegis/tests/test_agent.py \
    aegis/tests/test_webrecon.py
  git commit -m "test(audit): define fail-closed facade compatibility"
  ```

- [ ] Replace `AuditLog` internals while leaving non-audit guardrail logic
  untouched. Translate storage codes to redacted `GuardrailError`.
- [ ] Run focused audit and affected integration tests; expected GREEN.
- [ ] Commit GREEN:

  ```bash
  git add aegis/aegis/guardrail.py
  git commit -m "feat(audit): integrate transactional AuditLog facade"
  ```

### Task 6: Read-only diagnostics and CLI exit codes

**Files:**

- Modify: `aegis/aegis/guardrail.py`
- Modify: `aegis/aegis/cli.py`
- Create: `aegis/tests/test_audit_cli.py`

**Interfaces:**

- Produces: `_DiagnosticAuditLog`, `DiagnosticReport`, audit option parsing,
  stable output and exit mapping.
- Consumes: strict replay/anchor classification without write capability.

- [ ] Add CLI tests for healthy, each invalid state, operational failures,
  disabled writes, redacted output, help, and exit codes 0/1/2.
- [ ] Run CLI tests; expected RED.
- [ ] Commit RED:

  ```bash
  git add aegis/tests/test_audit_cli.py
  git commit -m "test(audit): define diagnostic CLI behavior"
  ```

- [ ] Implement `_for_diagnostics`, report formatting, mutually exclusive
  audit flags, and exit mapping. `cmd_audit` must not call `_guard`.
- [ ] Run CLI, storage, anchor, and guardrail tests; expected GREEN.
- [ ] Commit GREEN:

  ```bash
  git add aegis/aegis/guardrail.py aegis/aegis/cli.py
  git commit -m "feat(audit): add read-only diagnostics"
  ```

### Task 7: Anchor bootstrap and reconciliation

**Files:**

- Modify: `aegis/aegis/guardrail.py`
- Modify: `aegis/aegis/cli.py`
- Modify: `aegis/tests/test_audit_anchor.py`
- Modify: `aegis/tests/test_audit_cli.py`

**Interfaces:**

- Produces: explicit confirmed bootstrap/reconciliation methods.
- Consumes: diagnostic session, one retained outer lock, atomic anchor writer.

- [ ] Add success/refusal tests proving no audit-log byte changes and exact
  allowed state transitions.
- [ ] Run anchor/CLI tests; expected RED.
- [ ] Commit RED:

  ```bash
  git add aegis/tests/test_audit_anchor.py aegis/tests/test_audit_cli.py
  git commit -m "test(audit): define explicit anchor recovery"
  ```

- [ ] Implement bootstrap for absent anchor + valid populated log and
  reconciliation for proven stale anchor only. Retain the same lock through
  classification and replacement.
- [ ] Run all audit-focused tests; expected GREEN.
- [ ] Commit GREEN:

  ```bash
  git add aegis/aegis/guardrail.py aegis/aegis/cli.py
  git commit -m "feat(audit): add explicit anchor recovery"
  ```

### Task 8: Multiprocessing and crash-boundary verification

**Files:**

- Modify: `aegis/tests/audit_support.py`
- Create: `aegis/tests/test_audit_concurrency.py`
- Modify: `aegis/aegis/audit_storage.py`
- Modify: `aegis/aegis/anchor.py`

**Interfaces:**

- Produces: separately started worker and crash tests.
- Consumes: private injected `_AuditIO`, top-level spawn-safe helpers, façade.

- [ ] Add two-writer, repeated stress, partial-write termination, post-log-fsync
  crash, post-anchor-fsync crash, and lock-release tests.
- [ ] Run concurrency tests; expected RED for any incomplete private seam.
- [ ] Commit RED:

  ```bash
  git add aegis/tests/audit_support.py aegis/tests/test_audit_concurrency.py
  git commit -m "test(audit): add process and crash-boundary coverage"
  ```

- [ ] Invoke the already-declared private checkpoints after log `fsync`,
  anchor-file `fsync`, anchor replace, and anchor-directory `fsync`. Do not add
  operational controls.
- [ ] Run concurrency tests repeatedly and all audit-focused tests; expected
  GREEN.
- [ ] Commit GREEN:

  ```bash
  git add aegis/aegis/audit_storage.py aegis/aegis/anchor.py
  git commit -m "feat(audit): wire private crash boundary seam"
  ```

### Task 9: Documentation, configuration comments, and final verification

**Files:**

- Modify: `aegis/aegis/config.py`
- Modify: `aegis/SECURITY.md`
- Create: `aegis/docs/PHASE2A_AUDIT_OPERATIONS.md`
- Modify: `aegis/docs/NEXT_STEPS.md`
- Modify comments only: `targets/scope-policy.yaml`

**Interfaces:**

- Produces: deployment/bootstrap/reconciliation/rollback operator contract.
- Consumes: verified CLI syntax and final failure matrix.

- [ ] Document trusted-parent provisioning, permissions, local-anchor limits,
  exit codes, uncertain commits, bootstrap, reconciliation, Phase 1 rollback
  prohibition, residual risks, and exact verification commands.
- [ ] Run documentation claim searches and all quality gates in Section 11.
- [ ] Commit:

  ```bash
  git add aegis/aegis/config.py aegis/SECURITY.md \
    aegis/docs/PHASE2A_AUDIT_OPERATIONS.md aegis/docs/NEXT_STEPS.md \
    targets/scope-policy.yaml
  git commit -m "docs: add Phase 2A audit operations runbook"
  ```

Planned sequence: 17 commits—eight RED/GREEN pairs plus one documentation and
verification commit. No giant combined security commit.

## 7. Complete test mapping

Planned inventory: **72 named tests**, with parameterization producing at least
**90 collected cases**, plus the existing full suite. Exact collected count is
recorded after implementation because pytest expands parameterized cases.

### 7.1 Original 22 required cases

| # | File and test | Fixture/helper | Behavior | Expected |
|---|---|---|---|---|
| 1 | `test_audit_storage.py::test_empty_log_initializes_and_replays` | `audit_policy` | Empty absent/zero-byte log | valid, count 0, genesis |
| 2 | `test_audit_storage.py::test_multiple_v2_records_append_and_verify` | `audit_log` | Multi-entry V2 | contiguous and valid |
| 3 | `test_audit_storage.py::test_malformed_json_in_middle_rejected` | `write_raw_log` | Broken middle line | startup `GuardrailError` |
| 4 | `test_audit_storage.py::test_malformed_json_final_record_rejected` | `write_raw_log` | Broken final JSON | startup refusal |
| 5 | `test_audit_storage.py::test_missing_hmac_rejected` | `signed_v2_records` | Required field absent | invalid schema |
| 6 | `test_audit_storage.py::test_altered_event_rejected` | `signed_v2_records` | Signed content changed | invalid HMAC |
| 7 | `test_audit_storage.py::test_altered_prev_rejected` | `signed_v2_records` | Chain pointer changed | invalid prev/HMAC |
| 8 | `test_audit_storage.py::test_duplicate_sequence_rejected` | `signed_v2_records` | Duplicate signed seq | invalid sequence |
| 9 | `test_audit_storage.py::test_skipped_sequence_rejected` | `signed_v2_records` | Sequence gap | invalid sequence |
| 10 | `test_audit_storage.py::test_reordered_records_rejected` | `signed_v2_records` | Physical reorder | invalid seq/prev |
| 11 | `test_audit_storage.py::test_truncated_final_record_rejected` | `write_raw_log` | Partial final bytes | malformed/unterminated |
| 12 | `test_audit_storage.py::test_append_refuses_corrupted_history` | `audit_log` | Write after tamper | `GuardrailError`, unchanged bytes |
| 13 | `test_audit_concurrency.py::test_two_processes_append_without_fork` | `spawn_append_worker` | Two OS processes | two unique contiguous records |
| 14 | `test_audit_concurrency.py::test_repeated_process_stress_is_exactly_once` | `spawn_stress_workers` | Repeated process fan-out | all IDs once, valid tip/anchor |
| 15 | `test_audit_concurrency.py::test_process_termination_during_append_is_detected` | `PartialWriteExitIO` | Child exits mid-record | nonzero child exit, startup refusal |
| 16 | `test_audit_anchor.py::test_populated_log_with_missing_anchor_is_refused` | `anchored_log` | Anchor deleted | missing/fail closed |
| 17 | `test_audit_anchor.py::test_stale_anchor_is_classified` | `anchor_at_seq` | Anchor behind matching prefix | stale |
| 18 | `test_audit_anchor.py::test_ahead_anchor_is_classified` | `anchor_at_seq` | Anchor seq beyond log | ahead |
| 19 | `test_audit_anchor.py::test_malformed_anchor_is_classified` | `write_raw_anchor` | Invalid JSON/schema | malformed |
| 20 | `test_audit_anchor.py::test_anchor_write_failure_leaves_recoverable_stale_state` | `FailAnchorReplaceIO` | Log fsynced, anchor fails | write raises; stale; reconcile allowed |
| 21 | `test_audit_storage.py::test_synthetic_phase1_chained_fixture_verifies` | `encode_v1_fixture` | Independent Phase 1 bytes | valid V1 |
| 22 | `test_audit_storage.py::test_sensitive_values_never_appear_in_errors` | `sensitive_corruption` | Secret-bearing invalid record | category only, secret absent |

### 7.2 Additional specification cases

| File and test | Fixture/helper | Behavior | Expected |
|---|---|---|---|
| `test_audit_storage.py::test_synthetic_phase1_unchained_fixture_verifies` | `encode_v1_fixture(chained=False)` | V1 `prev:null` prefix | valid independently of current policy |
| `test_audit_storage.py::test_v1_to_v2_transition_uses_count_and_final_tip` | `v1_prefix` | First V2 transition | V1 count+1 and final V1 HMAC |
| `test_audit_storage.py::test_v1_after_v2_is_rejected` | `write_raw_log` | Reverse transition | invalid schema |
| `test_audit_storage.py::test_v2_only_log_verifies` | `signed_v2_records` | V2-only chain | seq 1/genesis and valid |
| `test_audit_storage.py::test_v2_write_refused_when_chained_policy_false` | `audit_policy(chained=False)` | Weaker V2 attempt | `GuardrailError`, no bytes |
| `test_audit_storage.py::test_duplicate_json_keys_are_rejected` | `write_raw_log` | Duplicate key | duplicate-key category |
| `test_audit_storage.py::test_nonfinite_json_constants_are_rejected` | `nonfinite_token` parameter | NaN/+Inf/-Inf | malformed JSON |
| `test_audit_storage.py::test_non_object_json_values_are_rejected` | `json_value` parameter | list/string/number/null | non-object category |
| `test_audit_storage.py::test_boolean_numeric_fields_are_rejected` | `numeric_field` parameter | Boolean version/seq/ts | invalid field type |
| `test_audit_storage.py::test_partial_version_fields_are_rejected` | `partial_version_record` | Only version or only seq | invalid schema |
| `test_audit_storage.py::test_invalid_hmac_encodings_are_rejected` | `bad_hmac` parameter | Length/case/non-hex/type variants | invalid HMAC |
| `test_audit_storage.py::test_nonfinite_timestamp_is_rejected` | `synthetic_record` | Runtime non-finite ts | invalid timestamp |
| `test_audit_storage.py::test_complete_record_without_newline_is_rejected` | `write_raw_log` | Valid JSON without terminator | unterminated-record |
| `test_audit_storage.py::test_v2_signed_bytes_are_independently_reproducible` | `independent_v2_mac` | Exact UTF-8/domain/canonical contract | expected HMAC equals stored HMAC |
| `test_audit_storage.py::test_write_returns_committed_hmac` | `audit_log` | Public `write()` | 64-character committed HMAC |
| `test_audit_storage.py::test_verify_returns_boolean` | `audit_log` | Public `verify()` | `True`/`False`, no parse exception |
| `test_audit_storage.py::test_cross_check_anchor_retains_tuple_shape` | `anchored_log` | Public cross-check | `(bool, redacted str)` |
| `test_audit_filesystem.py::test_short_write_loop_completes_one_record` | `ShortWriteIO` | Repeated short writes | one complete valid line |
| `test_audit_filesystem.py::test_new_files_use_mode_0600` | `audit_log_with_anchor` | Create log/lock/anchor/temp | all owner-only |
| `test_audit_filesystem.py::test_final_symlink_is_rejected` | `final_symlink` | No-follow final entry | symlink category |
| `test_audit_filesystem.py::test_non_regular_file_is_rejected` | `non_regular_entry` | Directory/device-style object | non-regular category |
| `test_audit_filesystem.py::test_unsafe_owner_is_rejected` | `ForeignOwnerStatIO` | Foreign UID metadata | unsafe-owner category |
| `test_audit_filesystem.py::test_unsafe_mode_is_rejected` | `chmod_existing_file` | Group/other permission bits | unsafe-mode category |
| `test_audit_filesystem.py::test_untrusted_parent_is_rejected` | `unsafe_parent` | Foreign/writable parent | unsafe-parent category |
| `test_audit_filesystem.py::test_outer_operation_uses_one_lock_descriptor_and_acquisition` | `CountingLockIO` | Instrument outer operation | one descriptor/one successful acquisition |
| `test_audit_filesystem.py::test_helper_without_held_context_is_rejected` | `invalid_held_context` | Direct helper invocation | fail before disk access |
| `test_audit_filesystem.py::test_lock_timeout_uses_virtual_monotonic_deadline` | `VirtualClockContendedIO` | Contended lock | lock-timeout at virtual 10.0 seconds |
| `test_audit_filesystem.py::test_lock_releases_when_process_terminates` | `lock_holder_worker` | Kernel releases child lock | next process acquires |
| `test_audit_filesystem.py::test_unsupported_platform_fails_closed` | `UnsupportedLockIO` | No `flock` support | unsupported-platform category |
| `test_audit_anchor.py::test_matching_anchor_includes_record_timestamp` | `anchored_log` | Compare seq/tip/ts | match |
| `test_audit_anchor.py::test_timestamp_mismatch_is_divergent` | `write_anchor_record` | Same seq/tip, changed ts | divergent |
| `test_audit_anchor.py::test_atomic_anchor_write_orders_file_and_directory_fsync` | `RecordingAnchorIO` | Atomic persistence calls | write→file fsync→replace→dir fsync |
| `test_audit_anchor.py::test_safe_abandoned_temp_is_cleaned` | `safe_anchor_temp` | Exact safe temp | removed under lock |
| `test_audit_anchor.py::test_unsafe_abandoned_temp_fails_closed` | `unsafe_anchor_temp` | Symlink/foreign/unsafe temp | refusal without removal |
| `test_audit_anchor.py::test_bootstrap_writes_anchor_without_log_mutation` | `unanchored_valid_log` | Explicit confirmed bootstrap | match; identical log bytes |
| `test_audit_anchor.py::test_bootstrap_refuses_invalid_states` | `bootstrap_state` parameter | Empty/existing/invalid history | refusal; no mutation |
| `test_audit_anchor.py::test_reconciliation_advances_only_stale_anchor` | `stale_anchored_log` | Explicit confirmed reconcile | final match; identical log bytes |
| `test_audit_anchor.py::test_reconciliation_refuses_other_states` | `anchor_state` parameter | Missing/malformed/ahead/divergent/match | refusal; no mutation |
| `test_audit_cli.py::test_healthy_diagnostic_returns_zero` | `cli_policy_file` | Valid log/admissible anchor | exit 0 |
| `test_audit_cli.py::test_integrity_diagnostics_return_one` | `integrity_state` parameter | Log/anchor integrity failures | exit 1 and stable category |
| `test_audit_cli.py::test_operational_diagnostics_return_two` | `OperationalFailureIO` | Key/platform/parent/timeout/I/O | exit 2 |
| `test_audit_cli.py::test_diagnostic_facade_cannot_write` | `diagnostic_log` | Call diagnostic `write()` | write-disabled refusal |
| `test_audit_cli.py::test_recovery_requires_confirmation` | `recovery_cli_args` | Missing `--confirm` | exit 1, no mutation |
| `test_audit_cli.py::test_bootstrap_and_reconcile_success_return_zero` | `recoverable_cli_state` | Durable explicit recovery | exit 0 |
| `test_audit_cli.py::test_audit_help_lists_recovery_options` | `cli_runner` | `argus audit --help` | both recovery flags shown |
| `test_audit_cli.py::test_cli_output_redacts_sensitive_values_and_hmac_tips` | `sensitive_corruption` | Diagnostic rendering | category/count only |
| `test_audit_concurrency.py::test_crash_after_log_fsync_leaves_stale_anchor` | `CheckpointExitIO(AFTER_LOG_FSYNC)` | Crash at committed log boundary | stale; reconcile allowed |
| `test_audit_concurrency.py::test_crash_after_anchor_directory_fsync_is_committed` | `CheckpointExitIO(AFTER_ANCHOR_DIRECTORY_FSYNC)` | Crash after full local boundary | replay and anchor match |
| `test_audit_concurrency.py::test_stress_anchor_matches_final_tip` | `spawn_stress_workers` | Final stress state | seq/tip/ts equal replay |
| `test_audit_cli.py::test_no_operational_crash_control_exists` | `parser_and_policy_surfaces` | Inspect CLI/config/public constructor | no crash control present |

### 7.3 Non-flaky process and crash strategy

- Use `multiprocessing.get_context("spawn")` so workers are separately started
  and do not inherit a held lock or monkeypatch state.
- Put worker functions at module top level in `tests/audit_support.py`.
- Use `multiprocessing.Barrier` or one-way pipes for readiness/start; never use
  sleep as a correctness condition.
- Give parent joins a bounded deadlock guard, but assert correctness from
  process exit codes and records, not elapsed time.
- Test the 10-second timeout with injected monotonic/sleep functions that
  advance a virtual clock; the test completes immediately.
- Inject crash points through private `_AuditIO` implementations instantiated
  directly by tests. The child calls `os._exit()` only after a deterministic
  byte count or recorded `fsync` boundary.
- Run stress as three deterministic rounds of six processes × twenty uniquely
  identified events. Assert exactly 120 records per round, contiguous
  sequences, exact `prev`, successful verify, and matching anchor.
- For kernel lock release, a child signals through a pipe only after the
  instrumented lock acquisition; the parent terminates and joins it before a
  second process attempts acquisition.

## 8. Compatibility strategy

| Input/state | Implementation behavior |
|---|---|
| Empty log | Missing log or zero-byte log under a trusted existing parent replays as count 0/genesis; first V2 is seq 1/prev genesis |
| Chained V1 | Strictly verify required fields, finite ts, lower-hex HMAC, uniform string `prev`, Phase 1 canonical bytes and chain |
| Unchained V1 | Strictly verify uniform `prev:null` and Phase 1 body-only HMAC; current policy does not reinterpret it |
| V1→V2 | New write requires `audit_chained:true`; seq is V1 count+1 and prev is final V1 HMAC; V1 bytes remain unchanged |
| V2 only | Strict V2/domain/sequence/prev verification |
| V1 after V2 | Fail closed |
| Malformed history | Normal construction and append raise redacted `GuardrailError`; diagnostics classify; no repair |
| Phase 1 rollback | Phase 1 cannot verify V2; never open a V2 log with Phase 1. Restore matched V1 backup or rotate Phase 1 to a new empty path |
| Anchoring disabled | Log `fsync` is the return boundary; diagnostics report `disabled` |
| Empty + configured missing anchor | `uninitialized`, admissible until first write creates anchor |
| Populated + configured matching anchor | Admissible |
| Missing/stale/ahead/divergent/malformed anchor | Normal construction fails; diagnostics classify; only explicit permitted recovery changes anchor |
| `write()` | Returns HMAC after log and configured anchor durability; raises redacted `GuardrailError` otherwise |
| `verify()` | Returns Boolean under one lock; never exposes parse exceptions |
| `cross_check_anchor()` | Returns `(bool, redacted_reason)` under one lock |

No startup migration, format guessing from partial fields, silent rewrite, or
automatic tail repair.

## 9. Failure-state matrix

| Failure point | Durable log state | Anchor state | Caller result | Subsequent startup | Permitted recovery |
|---|---|---|---|---|---|
| Before append open/write | Previous valid tip | Previous match/disabled | Redacted failure | Normal previous state | Retry operation after cause fixed |
| Partial append | Invalid partial tail may exist | Previous anchor | No success | Fails on malformed tail | No bootstrap/reconcile; restore matched backup/manual forensic procedure |
| Complete write before log `fsync` | Not guaranteed: absent, partial, or complete | Previous anchor | No success | Replay decides; complete anchored log may be stale | Reconcile only if complete verified log + proven stale anchor |
| After log `fsync`, before anchor temp write | New record committed | Stale previous anchor | Redacted failure/no confirmation | Fails closed as stale | Explicit reconcile |
| During temporary-anchor write | New record committed | Final anchor remains stale; safe temp may remain | Redacted failure | Cleanup then stale classification | Explicit reconcile |
| After temporary-anchor `fsync`, before replace | New record committed | Final anchor stale; durable temp may remain | Redacted failure | Cleanup then stale | Explicit reconcile |
| After anchor replacement, before directory `fsync` | New record committed | Restart may observe match, stale, or missing | No confirmed success | Classify observed state | None if match; reconcile if stale; bootstrap if absent + verified |
| After anchor-directory `fsync` | New record committed | Match committed to local boundary | Success may return | Normal | None |
| Crash after commitment before return | New record committed | Match | Caller uncertain | Normal replay shows event | Do not blind retry; inspect event |
| Lock timeout | Unchanged | Unchanged | `GuardrailError`; CLI 2 | Previous state | Retry outer operation after contention ends |
| Unsafe parent/file/symlink/non-regular object | No authorized mutation | Unchanged/unknown | `GuardrailError`; CLI 2 | Fails closed | Operator inspects and explicitly corrects object; no log repair |
| Malformed log | Invalid | Not comparable or independently missing/malformed | Normal failure; CLI 1 | Fails closed | Restore matched backup; no automatic recovery |
| Malformed anchor with valid log | Valid | Malformed | Normal failure; CLI 1 | Fails closed | Restore valid anchor from operational evidence; bootstrap/reconcile refused |
| Anchor write I/O failure | New record committed if after log `fsync` | Usually stale or missing | Redacted failure; CLI 2 for recovery I/O | Fails closed | Reconcile stale; bootstrap missing; only after full verification |

Filesystem durability is limited to the defined POSIX `fsync` boundaries and
does not promise survival of hostile/lying storage or administrator action.

## 10. Security invariants

Implementation and review must prove:

- no record write occurs before a complete locked replay;
- no cached chain tip is authoritative;
- one outer operation owns one lock descriptor and one successful `flock`;
- no replay, append, anchor, verification, or diagnostic helper reacquires
  `flock`;
- lock order is always in-process lock then interprocess lock;
- no V2 unchained mode exists;
- V2 sequence, timestamp, `prev`, event, and version are signed;
- no malformed or ambiguous record is skipped;
- no corruption is automatically repaired, discarded, truncated, or rewritten;
- diagnostics never mutate the audit log;
- bootstrap/reconciliation mutate only the anchor under explicit confirmation;
- errors and CLI output contain no records, HMAC tips, key values, approval
  tokens, credentials, full command output, PHI, or discovered secrets;
- crash controls are private injection only and absent from operational
  surfaces;
- trusted-parent limits and local-anchor non-WORM status are documented;
- Phase 1 web peer authorization, request-size enforcement, execution
  disablement, DOM safety, redirect refusal, guardrail scope, tool boundaries,
  and approval gates are unchanged.

## 11. Quality gates and delivery

Run from `aegis/` with repository-supported Python:

### 11.1 Installation and focused tests

```bash
python -m pip install --require-hashes -r requirements.lock
PENTEST_AUDIT_HMAC_KEY=$(openssl rand -hex 32) \
  python -m pytest -q \
    tests/test_audit_storage.py \
    tests/test_audit_filesystem.py \
    tests/test_audit_anchor.py \
    tests/test_audit_cli.py \
    tests/test_audit_concurrency.py
```

### 11.2 Full regression and static/security gates

```bash
PENTEST_AUDIT_HMAC_KEY=$(openssl rand -hex 32) python -m pytest -q
ruff check .
bandit -c pyproject.toml -r aegis --severity-level medium --confidence-level medium
pip-audit -r requirements.lock --strict --desc
```

Record exact pass/fail counts and tool versions. `pip-audit` is authoritative
only when this exact command completes successfully against the locked file;
do not substitute a partial local environment result.

### 11.3 Clean-wheel smoke

Build from a temporary export of the committed `aegis/` tree so setuptools
artifacts cannot dirty the implementation worktree:

```bash
implementation_aegis_dir=$(pwd)
package_root=$(mktemp -d)
smoke_dir=$(mktemp -d)
git -C .. archive HEAD aegis | tar -x -C "$package_root"
cd "$package_root/aegis"
python -m build
python3.12 -m venv "$smoke_dir/venv"
"$smoke_dir/venv/bin/python" -m pip install --upgrade pip
"$smoke_dir/venv/bin/python" -m pip install dist/argus_security-*.whl
"$smoke_dir/venv/bin/argus" --help
"$smoke_dir/venv/bin/argus" audit --help
cd "$implementation_aegis_dir"
```

Return to the implementation worktree's `aegis/` directory before repository
checks. The temporary directories contain only the exported source, built
artifacts, and smoke environment. Record their paths in the verification log;
removal is optional and must target only those explicit `mktemp` paths.

### 11.4 Final repository checks

```bash
git status --short
git diff --check origin/main...HEAD
git diff --name-status origin/main...HEAD
git log --oneline --decorate origin/main..HEAD
git rev-parse HEAD
```

Confirm no dependency lock, web, collector, agent, evidence, continuous,
prompt, PoC, policy value, scope value, or allowlist change.

### 11.5 Draft PR process

After all commits and gates pass:

```bash
git push -u origin phase2a-transactional-audit-hardening
gh pr create \
  --base main \
  --head phase2a-transactional-audit-hardening \
  --draft \
  --title "fix: harden transactional audit chain" \
  --body "Implements the approved Phase 2A transactional audit-hardening specification at docs/superpowers/specs/2026-07-23-phase2a-transactional-audit-hardening-design.md. Includes strict V1/V2 replay, POSIX interprocess locking, durable append/anchor boundaries, diagnostics, explicit recovery, multiprocessing tests, deployment and rollback guidance. No Phase 2B or V2 feature work."
gh pr view phase2a-transactional-audit-hardening
```

The PR report must include:

- implementation and threat-model summary;
- exact changed-file inventory and justification for test/config-comment files;
- mapping/count of new tests and full regression count;
- exact quality-gate command results;
- final branch SHA;
- residual risks from Section 12;
- deployment/bootstrap/reconciliation steps;
- rollback procedure and Phase 1/V2 incompatibility warning.

Do not mark ready for review or merge until CI passes and the user separately
authorizes that action.

## 12. Deployment and rollback procedure

Deployment:

1. Stop every Phase 1 Argus writer.
2. Preserve matched log/anchor backups read-only.
3. Verify the complete V1 log with Phase 1 before upgrade.
4. Provision trusted audit and anchor parent directories owned by the Argus
   user and not group/world writable.
5. Inspect existing final objects; explicitly set safe ownership and `0600`
   only after operator review.
6. Deploy the Phase 2A wheel.
7. Run read-only `argus audit`.
8. If enabling anchoring on a populated verified log, run
   `argus audit --bootstrap-anchor --confirm`.
9. Begin writers only after diagnosis returns 0.

Rollback:

1. Stop all Phase 2A writers.
2. Determine whether any V2 record exists.
3. If no V2 exists, restore the matched pre-deployment V1 pair before Phase 1.
4. If V2 exists, never let Phase 1 open that log. Preserve it and its anchor
   read-only.
5. Either restore the matched V1 backup or configure Phase 1 to a new empty
   audit path under a separately recorded operational rotation.
6. Never downgrade, truncate, or rewrite V2 records.

## 13. Residual implementation risks

- `flock` is advisory; a non-cooperating writer can bypass it.
- Trusted-parent resolution does not prevent hostile intermediate-component or
  mount replacement by privileged actors.
- A same-filesystem JSON anchor is not WORM and shares the controller trust
  domain.
- A valid whole-record tail deletion needs an independent matching anchor for
  detection.
- A crash after durable commitment but before response leaves caller
  uncertainty; event-level idempotency remains deferred.
- Network/remote filesystem `fsync`, device caches, and administrator behavior
  may not honor local durability assumptions.
- Unsafe-owner testing requires private metadata injection when the test user
  cannot create a foreign-owned file.
- Multiprocessing behavior must remain compatible with both macOS and Linux
  `spawn`; no test may depend on `fork`.
- Phase 1 cannot verify V2 domain-separated signatures and must never open a
  V2-containing log.

## 14. Implementation authorization gate

This plan commit contains documentation only. Do not create any RED test
commit, production change, CLI change, configuration change, dependency
change, or draft implementation PR until the user separately approves
implementation from this committed plan.
