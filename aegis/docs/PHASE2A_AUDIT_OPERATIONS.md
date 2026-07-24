# Phase 2A Audit Operations

Phase 2A makes the local audit log strict, durable, and safe for cooperating
concurrent writers on supported POSIX macOS/Linux controllers. It does not turn
a local JSON anchor into WORM storage.

## Provisioning

Stop all writers. Create the audit and optional anchor parent directories
before starting Argus. Each parent must be a directory owned by the effective
Argus uid and must not be group/world writable. Review existing final objects:
the lock, log, anchor, and anchor temp files must be regular, owner-matching
files with mode `0600`. Argus does not create missing parent directories.

The pathname model resolves and trusts each configured parent once, opens that
directory, and uses descriptor-relative no-follow opens for final names. It
does not claim race-free protection against privileged replacement of an
intermediate pathname component or mount.

Lock acquisition has a fixed 10.0-second monotonic deadline. One outer
operation acquires one path-keyed in-process lock and one kernel `flock` through
one lock-file descriptor. Replay, append, anchor, verification, and recovery
helpers do not reacquire it.

## Diagnosis and exit codes

```text
argus audit
```

Output contains only `log_state`, `anchor_state`, record count, and an optional
stable error category/record number. It never contains event data, keys, or
HMAC tips.

- `0`: healthy diagnosis or completed durable recovery.
- `1`: integrity/consistency failure or unmet recovery precondition.
- `2`: usage, configuration, key, platform, trust, permission, timeout, or I/O
  prevented reliable completion.

Normal `AuditLog` construction remains fail closed. The diagnostic path is
permanently unable to append audit events.

Anchor `ts` is the exact signed timestamp of the record identified by `seq`;
it is not anchor write time.

## Bootstrap and reconciliation

Bootstrap is allowed only when the log is valid and populated and the
configured anchor is absent:

```text
argus audit --bootstrap-anchor --confirm
```

Reconciliation is allowed only when the existing anchor exactly matches an
earlier signed record and is therefore provably stale:

```text
argus audit --reconcile-anchor --confirm
```

Neither operation changes audit-log bytes. Missing confirmation is a usage
error. Ahead, divergent, malformed, uninitialized, or non-comparable anchors
are never repaired automatically. Preserve evidence and investigate.

## Durability and uncertain commits

A V2 append is completely encoded before opening the log, written with a
short-write loop, and `fsync`ed. When configured, the anchor is written to an
exclusive `0600` temp file, file-`fsync`ed, descriptor-relatively replaced,
then the parent directory is `fsync`ed.

A crash after durable log commitment but before the caller receives success
leaves an uncertain commit. Diagnose before retrying; Phase 2A has no
event-level idempotency key. A crash between log and anchor commitment leaves a
stale anchor and requires explicit reconciliation after investigation.

## Deployment

1. Stop every Phase 1 writer.
2. Preserve a matched V1 log/anchor backup read-only.
3. Verify the complete V1 log using Phase 1.
4. Provision and inspect trusted parents and final-file ownership/modes.
5. Deploy the Phase 2A wheel.
6. Run `argus audit`.
7. If enabling anchoring on a populated log, run the confirmed bootstrap.
8. Start writers only after diagnosis exits `0`.

## Recovery and rollback

Never truncate, rewrite, migrate, skip, or automatically repair an audit
record. Preserve malformed or divergent material for investigation.

To roll back, stop all Phase 2A writers and determine whether any V2 record
exists. Phase 1 can JSON-parse V2 but cannot verify its domain-separated
signature. A Phase 1 writer must never open a V2-containing log. If V2 exists,
preserve the Phase 2A log and anchor read-only, then either restore the matched
pre-upgrade V1 pair or configure Phase 1 with a separately recorded new empty
path. Never downgrade or remove V2 records.

## Residual risk

- `flock` is advisory; non-cooperating writers can bypass it.
- Privileged intermediate-path or mount replacement is outside the
  trusted-parent guarantee.
- A same-host anchor shares the controller trust domain and is not WORM.
- Whole-record tail deletion requires an independent matching anchor to detect.
- Remote filesystem and device-cache durability may differ from local `fsync`.
- A leaked HMAC key permits chain recomputation.
