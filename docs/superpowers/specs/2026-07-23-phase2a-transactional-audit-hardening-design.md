# Phase 2A Transactional Audit-Chain and Concurrent-Writer Hardening

**Status:** Approved design specification

**Repository:** `gesh75/argus`

**Baseline:** `7303089afcec5227700618b98c48f1a1c3f6c15f`

**Scope:** Phase 2A only

## 1. Objective and scope

Phase 2A makes the existing HMAC audit trail fail closed and verifiable when
multiple Argus processes write concurrently and when writes, processes, or
anchor updates fail partway through.

The implementation preserves the existing guardrail call flow:

`Guardrail construction → strict existing-chain replay → authorize/deny/record → durable append → anchor update → verify`

This phase does not change web request boundaries, reconnaissance collectors,
scope rules, tool allowlists, agents, EvidenceGraph, continuous mode, AI
prompts, PoC behavior, authentication, multi-user behavior, SIEM integration,
or UI behavior.

## 2. Threat model and integrity boundary

Phase 2A addresses:

- two or more Argus processes racing to append from the same chain tip;
- malformed, reordered, duplicated, skipped, or partially written records;
- process termination before, during, or after a log append;
- a durable log append followed by an anchor-write failure;
- missing, stale, ahead, divergent, or malformed anchors;
- unsafe audit-file types, symlink substitution, and permissive file modes;
- sensitive values leaking through validation or recovery errors.

The design assumes:

- the HMAC key remains secret and has the existing minimum strength;
- Argus runs as one trusted controller operating-system user;
- the operating system and Python runtime correctly implement the specified
  POSIX file operations;
- all cooperating Argus writers use this implementation and the same
  canonical audit path.

The design does not protect against root, filesystem administrators, a
compromised Argus controller user, an attacker who can replace both the log and
anchor while possessing the HMAC key, hostile storage firmware, compromised
backups, or physical attacks. A local JSON anchor on the same writable
filesystem is a consistency checkpoint, not WORM storage and not an
independent trust domain.

## 3. Supported platforms

Audit writing and recovery are supported on POSIX controller hosts on which
Python provides `fcntl.flock`, including the supported macOS and Linux
environments. Argus may continue to assess Windows targets, but the Phase 2A
audit writer is not a Windows-hosted controller implementation.

If `fcntl.flock` or required POSIX open flags are unavailable, startup fails
closed with a redacted `GuardrailError`. The implementation does not fall back
to `threading.Lock` or an advisory lock that is only process-local.

## 4. Component boundaries

### 4.1 `aegis/aegis/guardrail.py`

`AuditLog` remains the public façade used by existing callers. It owns key
loading, translates internal integrity failures into redacted
`GuardrailError`s, and preserves these public behaviors:

- `write(event)` returns the committed record HMAC;
- `verify()` returns a Boolean;
- startup corruption raises `GuardrailError`;
- append and anchor failures raise `GuardrailError` without record contents;
- `cross_check_anchor()` returns `(bool, str)`.

`AuditLog` does not keep an authoritative in-memory chain tip. Every append
derives its next state from a locked, strict replay of disk state.

### 4.2 `aegis/aegis/audit_storage.py`

A new, narrowly scoped internal module owns:

- canonical path validation;
- in-process and interprocess lock acquisition;
- strict JSON decoding and record-schema validation;
- V1 and V2 signature verification;
- current-tip derivation;
- complete-record byte construction;
- durable append operations;
- internal integrity categories that contain no record values.

The module exposes no CLI flags, environment switches, or public API for crash
simulation.

### 4.3 `aegis/aegis/anchor.py`

The anchor module owns strict anchor decoding and validation, atomic local
anchor replacement, directory durability, anchor-state classification,
bootstrap, and reconciliation primitives. All disk access occurs while the
audit storage lock is held.

### 4.4 `aegis/aegis/cli.py`

The existing `argus audit` verification behavior remains available. Explicit
operator-only modes are added for anchor bootstrap and reconciliation. The
operations require a confirmation option and never modify audit records.

## 5. Locking protocol

### 5.1 Lock identity

The audit-log path is canonicalized before any file is opened. The lock path is
derived solely from that canonical path by appending `.lock` to the log
filename. For example:

`/var/lib/argus/audit.ndjson` → `/var/lib/argus/audit.ndjson.lock`

Aliases that resolve to the same accepted audit path therefore use the same
lock. Existing symlink components are rejected rather than followed.

### 5.2 Lock order

Every disk-state operation uses one order:

`in-process lock → open lock file → interprocess flock`

No code may acquire these locks in the reverse order. The in-process lock is a
path-keyed re-entrant lock and protects separate `AuditLog` instances and
threads in one process. The interprocess lock is an exclusive
`fcntl.flock(LOCK_EX)` on the canonical lock file.

An exclusive lock is used for startup replay, verification, append, anchor
validation, anchor bootstrap, anchor reconciliation, and chain-tip inspection.
Verification cannot read while another process appends.

The lock file is opened with close-on-exec and no-follow protections described
below. Its presence after a process terminates is expected and harmless:
`flock` ownership belongs to the open file description, and the kernel releases
the lock when the descriptor or process exits.

### 5.3 Append critical section

The exclusive lock covers:

1. strict replay of every existing non-empty record;
2. configured-anchor validation;
3. next-sequence and previous-HMAC derivation;
4. complete V2 record construction and HMAC calculation;
5. log append and log `fsync`;
6. anchor replacement and anchor-directory `fsync`, when configured.

The lock is released only after the operation has either crossed its defined
durability boundary or failed closed.

## 6. Strict JSON decoding

Every audit and anchor line is decoded with a strict decoder that:

- detects and rejects duplicate object keys through an object-pairs hook;
- rejects `NaN`, positive infinity, and negative infinity through an explicit
  constant parser;
- rejects any top-level value that is not a JSON object;
- rejects trailing non-whitespace data after one JSON value;
- rejects invalid UTF-8;
- rejects Boolean values wherever an integer or numeric timestamp is required;
- rejects non-finite timestamps after decoding.

Blank lines are not records and are rejected inside a non-empty audit file.
An empty, zero-byte file is a valid empty log. Every record, including the
final record, must end with exactly one newline byte. A missing final newline,
truncated record, or malformed final record is an invalid tail and is never
discarded or repaired. Requiring the terminator prevents a later append from
being concatenated directly onto an unterminated JSON object.

Errors identify only the one-based record number and a stable category such as
`malformed JSON`, `duplicate key`, `invalid schema`, `sequence discontinuity`,
`previous-HMAC discontinuity`, or `HMAC mismatch`. They never include the
record, HMAC value, signing key, approval token, command output, credential,
PHI, or discovered secret.

## 7. V1 compatibility contract

Phase 1 records form a V1 prefix. No repository audit fixture is tracked, but
the reader supports existing production-format records without rewriting
them.

A V1 record:

- is a strict JSON object;
- contains required fields `ts`, `prev`, `event`, and `hmac`;
- contains neither `audit_version` nor `seq`;
- has a finite numeric `ts` that is not Boolean;
- has a non-empty string `event`;
- has an `hmac` containing exactly 64 lowercase hexadecimal characters;
- may contain additional event-specific fields with string keys.

The stored `prev` field defines the V1 signing mode and prevents a policy
change from reinterpreting an existing record:

- a chained V1 prefix uses `"genesis"` for the first `prev`, then the exact
  preceding record HMAC; its HMAC input is the UTF-8 encoding of
  `previous_hmac + canonical_v1_body`;
- an unchained V1 prefix uses JSON `null` for every `prev`; its HMAC input is
  the UTF-8 encoding of `canonical_v1_body`.

`canonical_v1_body` is the V1 object with `hmac` removed, serialized using the
Phase 1 contract:

```python
json.dumps(
    body,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
    allow_nan=False,
)
```

The entire V1 prefix must use one mode. A change from string `prev` to `null`
or from `null` to string `prev` is invalid. Verification derives V1 semantics
from the stored, validated prefix rather than from the current
`audit_chained` policy value.

V1 sequence position is its one-based physical record position. Because V1
does not contain a signed sequence field, the reader does not claim that V1
sequence numbers were cryptographically bound. V1 continuity is established
by its verified HMAC and `prev` contract.

## 8. Exact V1-to-V2 transition

The reader accepts either:

- an empty log;
- a complete, strictly validated V1 prefix;
- V2 records only; or
- a complete, strictly validated V1 prefix followed by V2 records.

The first V2 record:

- contains `audit_version: 2`;
- has `seq = number_of_valid_v1_records + 1`;
- references the final validated V1 HMAC through `prev`; or
- for an empty log, has `seq = 1` and `prev = "genesis"`.

Once the first V2 record exists, every later record must be V2. A V1 record
after V2 begins is invalid. A record containing only one of `audit_version` or
`seq` is ambiguous and invalid. V1 records are never silently rewritten,
converted, renumbered, or repaired.

New V2 writes require `audit_chained: true`. If the policy is false,
verification of a valid legacy unchained V1 log remains possible, but
`write()` fails closed before creating a V2 record. V2 has no unchained mode.

## 9. V2 record and signed-byte contract

### 9.1 Required and reserved fields

Every V2 record contains:

| Field | Type and constraint |
|---|---|
| `audit_version` | JSON integer exactly `2`; Boolean is invalid |
| `seq` | JSON integer `>= 1`; Boolean is invalid |
| `ts` | finite JSON integer or float; Boolean is invalid |
| `prev` | `"genesis"` for sequence 1, otherwise the preceding 64-character lowercase hexadecimal HMAC |
| `event` | non-empty JSON string |
| `hmac` | exactly 64 lowercase hexadecimal characters |

Event-specific fields are allowed. Caller events may not supply or overwrite
`audit_version`, `seq`, `ts`, `prev`, or `hmac`. Every JSON object key must be
a string, as required by JSON.

### 9.2 Sequence and chain validation

For every V2 record:

- `seq` must equal the preceding physical record position plus one;
- sequence 1 must use `prev = "genesis"`;
- every later `prev` must equal the immediately preceding stored HMAC;
- duplicate, skipped, reordered, reset, negative, floating-point, string, or
  Boolean sequence values are invalid;
- `audit_version` must be the integer 2, not `2.0`, `"2"`, or `true`.

Sequence, timestamp, event fields, and `prev` are all inside the signed
payload.

### 9.3 Canonical payload

Let `body` be the complete V2 record with only the `hmac` field removed.
Canonical JSON bytes are:

```python
canonical_payload = json.dumps(
    body,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
    allow_nan=False,
).encode("utf-8")
```

The signed byte string is exactly:

```python
b"ARGUS-AUDIT-V2\0" + canonical_payload
```

The terminating NDJSON newline is not signed. `prev` participates exactly
once as a required member of `body`; no implicit current-policy value is
prepended. The MAC is:

```python
hmac.new(key_bytes, signed_bytes, hashlib.sha256).hexdigest()
```

The stored HMAC is the resulting 64-character lowercase hexadecimal string.
This contract is deterministic and independently reproducible from the stored
record and key.

The persisted line is the complete record including `hmac`, serialized with
the same canonical JSON settings, followed by one byte `b"\n"`.

## 10. Durable append protocol

The writer constructs and encodes the entire V2 record before opening the log
for append. Under the audit lock it opens the log with:

- `O_WRONLY | O_CREAT | O_APPEND`;
- `O_CLOEXEC`;
- `O_NOFOLLOW` where the platform provides it;
- creation mode `0600`.

After opening, `fstat` must confirm a regular file with safe ownership and
permissions and the expected canonical identity. The implementation writes
the encoded record through a short-write-safe loop, then calls `fsync` on the
log descriptor before updating the anchor or returning.

No temporary audit-log copy is created. If the process dies after writing only
part of the encoded line, the next startup detects the malformed tail and
refuses all appends. No automatic truncation occurs.

A successful unanchored return means the record bytes reached the operating
system and filesystem's `fsync` durability boundary. It does not guarantee
survival of lying device caches, hostile or broken remote filesystems,
controller compromise, or storage-administrator action.

## 11. Filesystem protections

### 11.1 Canonical paths and file types

Audit, lock, and anchor paths are converted to absolute normalized paths after
validating existing path components with `lstat`. Symlink path components and
symlink final files are rejected. Missing controlled directories are created
without following symlinks.

Every opened lock, log, temporary-anchor, and anchor object must be a regular
file. Devices, sockets, FIFOs, directories, and other non-regular types are
rejected.

### 11.2 Open flags and modes

New lock, log, temporary-anchor, and anchor files are created with mode
`0600`, subject to platform behavior, and verified after opening. File
descriptors use `O_CLOEXEC`. Final-path opens use `O_NOFOLLOW` where supported,
with `lstat`/`fstat` identity checks retained as defense in depth.

Existing files must:

- be owned by the effective Argus user;
- be regular files;
- not be symlinks;
- have no group or other permission bits.

Unsafe existing ownership or permissions fail closed. Operators must inspect
the file and explicitly correct ownership or use `chmod 0600`; Argus does not
silently take ownership or relax/tighten an existing file's permissions.

Mode `0600` limits access by ordinary local users only. It does not protect
against root, filesystem administrators, the owning account after compromise,
backup readers, or hostile storage.

### 11.3 Anchor temporary files

Atomic anchor writes use a uniquely named mode-`0600` temporary regular file
created with exclusive creation in the anchor's own directory. The writer
fully writes and `fsync`s the temporary file, atomically replaces the final
anchor with `os.replace`, and `fsync`s the anchor directory.

Temporary anchor files never leave the controlled anchor directory. Under the
audit lock, abandoned files matching Argus's exact private temporary-name
pattern may be removed only after `lstat` confirms they are regular,
non-symlink files owned by the effective user. Unexpected types, owners, or
unsafe modes fail closed. Cleanup errors fail the anchor operation rather than
being ignored.

## 12. Anchor schema and state classification

The local anchor remains the strict JSON object:

```json
{"seq": 2, "tip": "<64 lowercase hex characters>", "ts": 1720000000.123}
```

It has exactly:

- integer `seq >= 1`, excluding Boolean;
- 64-character lowercase hexadecimal string `tip`;
- finite numeric `ts`, excluding Boolean.

Duplicate keys, extra keys, missing keys, non-object values, invalid UTF-8,
non-finite numbers, and trailing data are malformed.

While holding the audit lock, a configured anchor is classified as:

- **uninitialized:** log is empty and anchor is absent;
- **match:** `seq` equals the log sequence and `tip` equals the final log HMAC;
- **missing:** log is populated and anchor is absent;
- **stale:** anchor `seq` is less than log sequence and `tip` equals the HMAC
  at that exact sequence in the verified log;
- **ahead:** anchor `seq` is greater than log sequence;
- **divergent:** anchor sequence exists in the log but its tip does not match
  the HMAC at that sequence;
- **malformed:** strict anchor decoding or schema validation fails.

Normal startup and append accept only `uninitialized` for an empty log or
`match` for a populated log. Every other configured-anchor state fails closed.

## 13. Anchor bootstrap

Bootstrap is an explicit operator action used when anchoring is first enabled
for an already populated log:

```text
argus audit --bootstrap-anchor --confirm
```

The command:

1. requires the explicit confirmation option;
2. acquires the normal in-process lock and interprocess flock;
3. requires a configured anchor path;
4. requires the anchor to be absent;
5. strictly replays and cryptographically verifies the complete audit log;
6. writes the current verified sequence, tip, and timestamp to the anchor
   using the durable atomic protocol;
7. never changes the audit log;
8. prints a redacted console acknowledgement containing the operation and
   sequence, but not the tip or any event data.

Bootstrap is refused for an empty log, an existing anchor, malformed history,
an invalid HMAC, a sequence or `prev` discontinuity, an unsafe file, or a
failed durability operation.

The CLI enters a narrowly scoped recovery construction path that bypasses only
the normal requirement that a populated log already have a matching anchor.
It does not bypass log replay, cryptographic verification, filesystem checks,
locking, or explicit confirmation.

## 14. Anchor reconciliation

Reconciliation is an explicit operator action for the narrow case in which a
log record was durably appended but the previous anchor update failed:

```text
argus audit --reconcile-anchor --confirm
```

The command:

1. requires explicit confirmation;
2. acquires the normal audit locks;
3. strictly replays and cryptographically verifies the entire log;
4. strictly validates and classifies the existing anchor;
5. proceeds only when the anchor is **stale**, meaning its stored tip matches
   the verified log HMAC at its stored sequence;
6. advances only the anchor to the current verified log tip using the durable
   atomic protocol;
7. never removes, rewrites, truncates, or repairs an audit record;
8. prints a redacted console acknowledgement with the old and new sequence
   numbers, but no tips or event data.

Reconciliation is refused for missing, malformed, ahead, divergent, or already
matching anchors; malformed or truncated logs; invalid HMACs; unexplained
sequence gaps; and `prev` discontinuities. A missing anchor for a populated
verified log uses bootstrap, not reconciliation.

The console acknowledgement is the separate operational evidence required for
this recovery. Phase 2A does not add a second operational log.

As with bootstrap, the recovery construction path bypasses only the normal
anchor-match admission check needed to classify and advance a proven stale
anchor. It cannot bypass any audit-log or filesystem validation.

## 15. Commit states and failure behavior

The local durability states are:

- **Before log `fsync`:** the event is not guaranteed committed. A crash may
  leave no bytes, a complete line, or an invalid partial tail.
- **After log `fsync`, before anchor durability:** the event is committed to
  the audit log, but configured-anchor consistency is incomplete. Failure is
  reported and normal use remains fail closed until explicit reconciliation.
- **After anchor replacement and anchor-directory `fsync`:** the log and local
  anchor have crossed the defined local durability boundary.
- **Crash after commitment but before returning:** the caller receives no
  confirmation, but replay may show the event as committed.

`write()` returns the HMAC only after log durability and, when configured,
anchor durability. It never reports success after an incomplete configured
anchor update.

Callers must not blindly retry an event after an uncertain outcome. Phase 2A
does not add an event identifier or event-level idempotency protocol because
that would change existing audit semantics. Event-level idempotency is
explicitly deferred. An operator or higher-level caller must verify whether
the intended event is present before deciding to retry.

## 16. Startup, verification, and redacted errors

`AuditLog` construction acquires the audit locks, validates filesystem
protections, strictly replays the complete log, and validates any configured
anchor. Corruption raises `GuardrailError` before `Guardrail` can authorize,
deny, execute, or record an action.

`verify()` acquires the same locks and returns `False` for any integrity,
schema, filesystem, or configured-anchor failure observed after construction.
It does not raise detailed parsing exceptions to callers.

`cross_check_anchor()` retains `(bool, str)`. Its reason uses stable categories
such as `anchor missing`, `anchor stale`, `anchor ahead`, `anchor divergent`,
or `anchor malformed`; it does not expose HMAC tips or record values.

All internal exceptions are translated at the façade. Messages may contain a
record number, path role such as `audit log` or `anchor`, and a stable error
category. They do not contain raw paths supplied through secrets, JSON
fragments, event data, environment values, keys, approval tokens, passwords,
API keys, command output, PHI, or discovered secrets.

## 17. Private crash-test seam

The storage implementation accepts a private dependency-injected I/O adapter
used only by tests. Production construction supplies the real adapter
internally. Tests may inject an adapter that terminates after a controlled
partial write or after a durability boundary.

The seam is private, is not exported from the package API, and is inaccessible
through CLI arguments, environment variables, policy files, web/API inputs, or
production configuration. No production `simulate-crash` switch is added.

## 18. Required tests

All audit tests use temporary directories and synthetic keys. No test reads or
modifies the repository's ignored `aegis/output` directory or a real audit
path.

The Phase 2A suite covers:

1. valid empty-log initialization;
2. valid multi-entry V2 append and verification;
3. malformed JSON in the middle;
4. malformed JSON at the final line;
5. missing HMAC;
6. altered event content;
7. altered `prev`;
8. duplicate sequence;
9. skipped sequence;
10. reordered records;
11. truncated final record;
12. append refusal after corrupted history;
13. two separate processes appending;
14. repeated multi-process append stress;
15. process termination during append through the private injected seam;
16. configured anchor missing for a populated log;
17. stale anchor;
18. anchor ahead of the log;
19. malformed anchor;
20. anchor-write failure after durable log append;
21. verified compatibility with synthetic Phase 1-format records because no
    tracked production fixture exists;
22. sensitive-value redaction in startup, verification, append, and recovery
    errors.

Additional focused tests cover:

- V1-to-V2 transition sequence and `prev`;
- refusal of V1 after V2;
- strict duplicate-key and non-finite-number rejection;
- Boolean/integer type confusion;
- `audit_chained: false` V2-write refusal;
- symlink, non-regular-file, unsafe-owner, and unsafe-mode rejection;
- anchor bootstrap success and refusal states;
- anchor reconciliation success and refusal states;
- crash after log durability and crash after anchor durability;
- short writes completed by the production write loop;
- lock release after process termination.

The concurrency tests use `multiprocessing` with separately started processes,
not threads. Each event has a synthetic test identifier. After every stress
run, tests assert that:

- every expected identifier exists exactly once;
- sequences are contiguous;
- every `prev` points to the immediately preceding HMAC;
- the complete chain verifies;
- the configured anchor matches the final committed tip.

## 19. Quality gates

From `aegis/`, using the repository-supported Python version:

```bash
python -m pip install --require-hashes -r requirements.lock
PENTEST_AUDIT_HMAC_KEY=$(openssl rand -hex 32) python -m pytest -q
ruff check .
bandit -c pyproject.toml -r aegis --severity-level medium --confidence-level medium
pip-audit -r requirements.lock --strict --desc
python -m build
```

The built wheel is installed into a clean temporary virtual environment, then:

```bash
argus --help
argus audit --help
```

Dependencies and lockfiles remain unchanged unless implementation proves a
new dependency is genuinely necessary. The selected POSIX design requires no
new dependency.

## 20. Planned change boundary

The implementation is expected to:

- add `aegis/aegis/audit_storage.py`;
- modify `aegis/aegis/guardrail.py`;
- modify `aegis/aegis/anchor.py`;
- minimally modify `aegis/aegis/cli.py` for explicit anchor operations;
- add audit-focused tests under `aegis/tests/`;
- update audit security and migration/rollback documentation.

No implementation code, test, dependency, policy, web, collector, agent,
EvidenceGraph, continuous-runner, prompt, or allowlist change belongs in the
specification commit.

## 21. Deployment, compatibility, and rollback

Before deployment:

1. stop all Phase 1 Argus writers;
2. preserve the existing audit log and anchor as a matched, read-only backup;
3. inspect ownership, file type, and permissions;
4. correct accepted files explicitly to owner-only mode `0600`;
5. deploy Phase 2A;
6. run verification;
7. if enabling anchoring on a populated verified log, run explicit bootstrap.

Phase 2A writes V2 records that the Phase 1 reader can parse and HMAC-check,
but a rolled-back Phase 1 writer would append a V1 record after V2. Phase 2A
correctly rejects that mixed order. Therefore rollback must never point a
Phase 1 writer at a log that already contains V2 records.

Safe rollback options are:

- restore the matched pre-deployment V1 log and anchor pair before starting
  Phase 1; or
- preserve the Phase 2A log and anchor read-only, configure Phase 1 to use a
  new empty audit path, and record that operational rotation outside the audit
  log.

Never truncate, rewrite, renumber, or automatically downgrade a V2 log.
Reconciliation advances only a proven stale anchor and is not a general log
repair mechanism.

## 22. Residual risks and deferred work

- A valid whole-record tail deletion is detectable only when an independent
  matching anchor is available. A partial tail is always detected.
- Advisory locking cannot stop non-cooperating processes from writing directly
  to the file. OS ownership and permissions reduce but do not eliminate that
  risk.
- The local anchor shares the controller's trust domain and is not WORM.
- A crash after commitment but before response creates an uncertain caller
  outcome.
- Event-level identifiers and idempotent retry are deferred.
- Windows-hosted Argus audit writing and a cross-platform locking abstraction
  are deferred.
- Real WORM/object-lock anchoring, external signing, multi-user authorization,
  and SIEM export remain outside Phase 2A.
