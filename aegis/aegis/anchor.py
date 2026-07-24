"""Strict local consistency anchor operations under the audit lock.

The local anchor detects ordinary loss, truncation, and divergence. It is not
an external WORM control and does not protect against an attacker who can
replace both the audit log and this file.
"""

from __future__ import annotations

import json
import math
import os
import re
import secrets
from dataclasses import dataclass

from .audit_storage import (
    FILE_MODE,
    AnchorState,
    AuditCheckpoint,
    AuditFailureCode,
    AuditStorageError,
    HeldAuditLock,
    LogState,
    ReplayResult,
    TrustedParent,
    strict_json_object,
)

_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class AnchorRecord:
    seq: int
    tip: str
    ts: int | float


@dataclass(frozen=True, slots=True)
class AnchorReadResult:
    state: AnchorState
    record: AnchorRecord | None


def _read_all(parent: TrustedParent, name: str) -> bytes | None:
    fd = -1
    try:
        try:
            fd = parent.open_regular(name, os.O_RDONLY)
        except AuditStorageError as exc:
            if isinstance(exc.__cause__, FileNotFoundError):
                return None
            raise
        chunks: list[bytes] = []
        while True:
            chunk = parent._io.read(fd, 4096)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    finally:
        if fd >= 0:
            parent._io.close(fd)


def read_anchor_locked(
    held: HeldAuditLock,
    parent: TrustedParent,
    name: str,
) -> AnchorReadResult:
    held.assert_held()
    raw = _read_all(parent, name)
    if raw is None:
        return AnchorReadResult(AnchorState.MISSING, None)
    try:
        if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
            return AnchorReadResult(AnchorState.MALFORMED, None)
        data = strict_json_object(raw[:-1], record_number=None)
        if set(data) != {"seq", "tip", "ts"}:
            return AnchorReadResult(AnchorState.MALFORMED, None)
        seq = data["seq"]
        tip = data["tip"]
        timestamp = data["ts"]
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            return AnchorReadResult(AnchorState.MALFORMED, None)
        if not isinstance(tip, str) or _HEX_DIGEST.fullmatch(tip) is None:
            return AnchorReadResult(AnchorState.MALFORMED, None)
        if (
            not isinstance(timestamp, (int, float))
            or isinstance(timestamp, bool)
            or not math.isfinite(timestamp)
        ):
            return AnchorReadResult(AnchorState.MALFORMED, None)
        return AnchorReadResult(
            AnchorState.MATCH, AnchorRecord(seq, tip, timestamp)
        )
    except AuditStorageError:
        return AnchorReadResult(AnchorState.MALFORMED, None)


def classify_anchor(
    replay: ReplayResult,
    read_result: AnchorReadResult,
    *,
    configured: bool,
) -> AnchorState:
    if not configured:
        return AnchorState.DISABLED
    if replay.state not in {
        LogState.EMPTY,
        LogState.VALID_V1,
        LogState.VALID_V2,
        LogState.VALID_V1_V2,
    }:
        return AnchorState.NOT_COMPARABLE
    if read_result.state is AnchorState.MALFORMED:
        return AnchorState.MALFORMED
    if read_result.record is None:
        return (
            AnchorState.UNINITIALIZED
            if replay.state is LogState.EMPTY
            else AnchorState.MISSING
        )
    anchor = read_result.record
    if replay.state is LogState.EMPTY:
        return AnchorState.AHEAD
    if anchor.seq > replay.count:
        return AnchorState.AHEAD
    corresponding = replay.records[anchor.seq - 1]
    if anchor.tip != corresponding.hmac or anchor.ts != corresponding.ts:
        return AnchorState.DIVERGENT
    if anchor.seq < replay.count:
        return AnchorState.STALE
    return AnchorState.MATCH


def _write_all(parent: TrustedParent, fd: int, encoded: bytes) -> None:
    offset = 0
    while offset < len(encoded):
        written = parent._io.write(fd, encoded[offset:])
        if written <= 0:
            raise OSError("zero-byte anchor write")
        offset += written


def write_anchor_locked(
    held: HeldAuditLock,
    parent: TrustedParent,
    name: str,
    record: AnchorRecord,
) -> None:
    held.assert_held()
    if (
        not isinstance(record.seq, int)
        or isinstance(record.seq, bool)
        or record.seq < 1
        or _HEX_DIGEST.fullmatch(record.tip) is None
        or not isinstance(record.ts, (int, float))
        or isinstance(record.ts, bool)
        or not math.isfinite(record.ts)
    ):
        raise ValueError("invalid anchor metadata")

    # Validate an existing destination before replacing it. A final symlink,
    # non-regular node, wrong owner, or broad mode remains fail closed.
    read_anchor_locked(held, parent, name)
    temp_name = f".{name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    temp_fd = -1
    replaced = False
    primary_error: AuditStorageError | None = None
    try:
        temp_fd = parent.open_regular(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            create_mode=FILE_MODE,
        )
        encoded = (
            json.dumps(
                {"seq": record.seq, "tip": record.tip, "ts": record.ts},
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
        _write_all(parent, temp_fd, encoded)
        parent._io.fsync(temp_fd)
        parent._io.checkpoint(AuditCheckpoint.AFTER_ANCHOR_FILE_FSYNC)
        parent.replace(temp_name, name)
        replaced = True
        parent._io.checkpoint(AuditCheckpoint.AFTER_ANCHOR_REPLACE)
        parent.fsync()
        parent._io.checkpoint(
            AuditCheckpoint.AFTER_ANCHOR_DIRECTORY_FSYNC
        )
    except AuditStorageError as exc:
        primary_error = exc
    except OSError as exc:
        primary_error = AuditStorageError(AuditFailureCode.IO_FAILURE)
        primary_error.__cause__ = exc
    finally:
        if temp_fd >= 0:
            try:
                parent._io.close(temp_fd)
            except OSError as exc:
                if primary_error is None:
                    primary_error = AuditStorageError(
                        AuditFailureCode.IO_FAILURE
                    )
                    primary_error.__cause__ = exc
    cleanup_error: AuditStorageError | None = None
    if not replaced:
        try:
            parent.unlink_regular(temp_name)
        except AuditStorageError as exc:
            if not isinstance(exc.__cause__, FileNotFoundError):
                cleanup_error = exc
        except OSError as exc:
            cleanup_error = AuditStorageError(AuditFailureCode.IO_FAILURE)
            cleanup_error.__cause__ = exc
    if primary_error is not None:
        if cleanup_error is not None:
            primary_error.cleanup_code = cleanup_error.code
            primary_error.args = (str(primary_error),)
            raise primary_error from cleanup_error
        raise primary_error
    if cleanup_error is not None:
        raise cleanup_error


def _anchor_temp_pattern(anchor_name: str) -> re.Pattern[str]:
    return re.compile(
        rf"^\.{re.escape(anchor_name)}\.tmp\.[1-9][0-9]*\.[0-9a-f]{{16}}$"
    )


def cleanup_anchor_temps_locked(
    held: HeldAuditLock,
    parent: TrustedParent,
    anchor_name: str,
) -> None:
    held.assert_held()
    pattern = _anchor_temp_pattern(anchor_name)
    try:
        candidates = parent._io.listdir(parent.fd)
    except OSError as exc:
        raise AuditStorageError(AuditFailureCode.IO_FAILURE) from exc
    for candidate in candidates:
        if pattern.fullmatch(candidate) is None:
            continue
        try:
            parent.unlink_regular(candidate)
        except AuditStorageError:
            raise
        except OSError as exc:
            raise AuditStorageError(AuditFailureCode.IO_FAILURE) from exc
