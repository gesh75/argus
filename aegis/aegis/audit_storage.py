"""Strict, versioned audit-record encoding and replay primitives."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, TypeAlias

AUDIT_VERSION = 2
GENESIS = "genesis"
V2_DOMAIN_SEPARATOR = b"ARGUS-AUDIT-V2\0"
LOCK_TIMEOUT_SECONDS = 10.0
FILE_MODE = 0o600
RESERVED_FIELDS = frozenset({"audit_version", "seq", "ts", "prev", "hmac"})

JsonScalar: TypeAlias = None | bool | int | float | str
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]

_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class AuditFailureCode(StrEnum):
    MALFORMED_JSON = "malformed-json"
    DUPLICATE_KEY = "duplicate-key"
    INVALID_UTF8 = "invalid-utf8"
    NON_OBJECT_JSON = "non-object-json"
    INVALID_SCHEMA = "invalid-schema"
    INVALID_VERSION = "invalid-version"
    INVALID_SEQUENCE = "invalid-sequence"
    INVALID_PREV = "invalid-prev"
    INVALID_HMAC = "invalid-hmac"
    INVALID_TIMESTAMP = "invalid-timestamp"
    UNTERMINATED_RECORD = "unterminated-record"
    WRITE_DISABLED = "write-disabled"
    UNSUPPORTED_PLATFORM = "unsupported-platform"
    UNSAFE_PARENT = "unsafe-parent"
    UNSAFE_OWNER = "unsafe-owner"
    UNSAFE_MODE = "unsafe-mode"
    NON_REGULAR_FILE = "non-regular-file"
    SYMLINK = "symlink"
    LOCK_TIMEOUT = "lock-timeout"
    IO_FAILURE = "io-failure"
    ANCHOR_MISSING = "anchor-missing"
    ANCHOR_STALE = "anchor-stale"
    ANCHOR_AHEAD = "anchor-ahead"
    ANCHOR_DIVERGENT = "anchor-divergent"
    ANCHOR_MALFORMED = "anchor-malformed"


class LogState(StrEnum):
    EMPTY = "empty"
    VALID_V1 = "valid-v1"
    VALID_V2 = "valid-v2"
    VALID_V1_V2 = "valid-v1-v2"
    MALFORMED = "malformed"
    INVALID_SCHEMA = "invalid-schema"
    INVALID_SEQUENCE = "invalid-sequence"
    INVALID_PREV = "invalid-prev"
    INVALID_HMAC = "invalid-hmac"


class AnchorState(StrEnum):
    DISABLED = "disabled"
    UNINITIALIZED = "uninitialized"
    MATCH = "match"
    MISSING = "missing"
    STALE = "stale"
    AHEAD = "ahead"
    DIVERGENT = "divergent"
    MALFORMED = "malformed"
    NOT_COMPARABLE = "not-comparable"


class AuditCheckpoint(StrEnum):
    AFTER_LOG_FSYNC = "after-log-fsync"
    AFTER_ANCHOR_FILE_FSYNC = "after-anchor-file-fsync"
    AFTER_ANCHOR_REPLACE = "after-anchor-replace"
    AFTER_ANCHOR_DIRECTORY_FSYNC = "after-anchor-directory-fsync"


class AuditStorageError(Exception):
    """A redacted storage failure safe to expose to operators."""

    def __init__(
        self, code: AuditFailureCode, *, record_number: int | None = None
    ) -> None:
        self.code = code
        self.record_number = record_number
        super().__init__(str(self))

    def __str__(self) -> str:
        suffix = (
            f" at record {self.record_number}"
            if self.record_number is not None
            else ""
        )
        return f"{self.code.value}{suffix}"


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


VerifiedRecord: TypeAlias = V1Record | V2Record


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


class _DuplicateKey(ValueError):
    pass


def _pairs_to_object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError


def strict_json_object(
    raw: bytes, *, record_number: int | None
) -> dict[str, JsonValue]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AuditStorageError(
            AuditFailureCode.INVALID_UTF8, record_number=record_number
        ) from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_to_object,
            parse_constant=_reject_constant,
        )
    except _DuplicateKey as exc:
        raise AuditStorageError(
            AuditFailureCode.DUPLICATE_KEY, record_number=record_number
        ) from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise AuditStorageError(
            AuditFailureCode.MALFORMED_JSON, record_number=record_number
        ) from exc
    if not isinstance(value, dict):
        raise AuditStorageError(
            AuditFailureCode.NON_OBJECT_JSON, record_number=record_number
        )
    return value


def _valid_timestamp(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and _HEX_DIGEST.fullmatch(value) is not None


def _canonical(data: Mapping[str, JsonValue], *, ensure_ascii: bool) -> bytes:
    try:
        return json.dumps(
            dict(data),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=ensure_ascii,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AuditStorageError(AuditFailureCode.INVALID_SCHEMA) from exc


def canonical_v1_body(data_without_hmac: dict[str, JsonValue]) -> bytes:
    return _canonical(data_without_hmac, ensure_ascii=True)


def canonical_v2_body(data_without_hmac: dict[str, JsonValue]) -> bytes:
    return _canonical(data_without_hmac, ensure_ascii=False)


def decode_v1_record(data: dict[str, JsonValue], *, seq: int) -> V1Record:
    if "audit_version" in data or "seq" in data:
        raise AuditStorageError(AuditFailureCode.INVALID_VERSION)
    if not {"ts", "prev", "event", "hmac"}.issubset(data):
        raise AuditStorageError(AuditFailureCode.INVALID_SCHEMA)
    if not _valid_timestamp(data["ts"]):
        raise AuditStorageError(AuditFailureCode.INVALID_TIMESTAMP)
    if not isinstance(data["event"], str) or not data["event"]:
        raise AuditStorageError(AuditFailureCode.INVALID_SCHEMA)
    if data["prev"] is not None and not _valid_digest(data["prev"]) and data["prev"] != GENESIS:
        raise AuditStorageError(AuditFailureCode.INVALID_PREV)
    if not _valid_digest(data["hmac"]):
        raise AuditStorageError(AuditFailureCode.INVALID_HMAC)
    return V1Record(
        seq=seq,
        ts=data["ts"],
        prev=data["prev"],
        event=data["event"],
        hmac=data["hmac"],
        chained=data["prev"] is not None,
    )


def decode_v2_record(
    data: dict[str, JsonValue], *, expected_seq: int
) -> V2Record:
    if "audit_version" not in data or "seq" not in data:
        raise AuditStorageError(AuditFailureCode.INVALID_SCHEMA)
    version = data["audit_version"]
    if not isinstance(version, int) or isinstance(version, bool) or version != 2:
        raise AuditStorageError(AuditFailureCode.INVALID_VERSION)
    sequence = data["seq"]
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence != expected_seq
    ):
        raise AuditStorageError(AuditFailureCode.INVALID_SEQUENCE)
    if not {"ts", "prev", "event", "hmac"}.issubset(data):
        raise AuditStorageError(AuditFailureCode.INVALID_SCHEMA)
    if not _valid_timestamp(data["ts"]):
        raise AuditStorageError(AuditFailureCode.INVALID_TIMESTAMP)
    if not isinstance(data["prev"], str):
        raise AuditStorageError(AuditFailureCode.INVALID_PREV)
    if not isinstance(data["event"], str) or not data["event"]:
        raise AuditStorageError(AuditFailureCode.INVALID_SCHEMA)
    if not _valid_digest(data["hmac"]):
        raise AuditStorageError(AuditFailureCode.INVALID_HMAC)
    return V2Record(
        audit_version=2,
        seq=sequence,
        ts=data["ts"],
        prev=data["prev"],
        event=data["event"],
        hmac=data["hmac"],
    )


def verify_v1_hmac(
    record_data: dict[str, JsonValue], *, key: bytes, expected_prev: str
) -> V1Record:
    record = decode_v1_record(record_data, seq=0)
    if record.chained and record.prev != expected_prev:
        raise AuditStorageError(AuditFailureCode.INVALID_PREV)
    body_data = dict(record_data)
    stored = body_data.pop("hmac")
    body = canonical_v1_body(body_data)
    signed = expected_prev.encode() + body if record.chained else body
    expected = hmac.new(key, signed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(stored, expected):
        raise AuditStorageError(AuditFailureCode.INVALID_HMAC)
    return record


def verify_v2_hmac(
    record_data: dict[str, JsonValue],
    *,
    key: bytes,
    expected_seq: int,
    expected_prev: str,
) -> V2Record:
    record = decode_v2_record(record_data, expected_seq=expected_seq)
    if record.prev != expected_prev:
        raise AuditStorageError(AuditFailureCode.INVALID_PREV)
    body_data = dict(record_data)
    stored = body_data.pop("hmac")
    body = canonical_v2_body(body_data)
    expected = hmac.new(
        key, V2_DOMAIN_SEPARATOR + body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(stored, expected):
        raise AuditStorageError(AuditFailureCode.INVALID_HMAC)
    return record


def _raise_at_record(error: AuditStorageError, number: int) -> None:
    raise AuditStorageError(error.code, record_number=number) from error


def replay_bytes(raw: bytes, *, key: bytes) -> ReplayResult:
    if not raw:
        return ReplayResult(LogState.EMPTY, (), 0, GENESIS, None)
    if not raw.endswith(b"\n"):
        raise AuditStorageError(AuditFailureCode.UNTERMINATED_RECORD)

    verified: list[VerifiedRecord] = []
    tip = GENESIS
    v1_mode: bool | None = None
    saw_v1 = False
    saw_v2 = False
    for sequence, line in enumerate(raw.splitlines(), start=1):
        if not line:
            raise AuditStorageError(
                AuditFailureCode.INVALID_SCHEMA, record_number=sequence
            )
        data = strict_json_object(line, record_number=sequence)
        is_v2 = "audit_version" in data or "seq" in data
        try:
            if is_v2:
                record = verify_v2_hmac(
                    data,
                    key=key,
                    expected_seq=sequence,
                    expected_prev=tip,
                )
                saw_v2 = True
            else:
                if saw_v2:
                    raise AuditStorageError(AuditFailureCode.INVALID_VERSION)
                record = verify_v1_hmac(data, key=key, expected_prev=tip)
                if v1_mode is None:
                    v1_mode = record.chained
                elif v1_mode is not record.chained:
                    raise AuditStorageError(AuditFailureCode.INVALID_SCHEMA)
                record = V1Record(
                    seq=sequence,
                    ts=record.ts,
                    prev=record.prev,
                    event=record.event,
                    hmac=record.hmac,
                    chained=record.chained,
                )
                saw_v1 = True
        except AuditStorageError as exc:
            _raise_at_record(exc, sequence)
        verified.append(record)
        tip = record.hmac

    if saw_v1 and saw_v2:
        state = LogState.VALID_V1_V2
    elif saw_v2:
        state = LogState.VALID_V2
    else:
        state = LogState.VALID_V1
    return ReplayResult(
        state=state,
        records=tuple(verified),
        count=len(verified),
        tip=tip,
        final_ts=verified[-1].ts,
    )


def encode_v2_record(
    event: Mapping[str, JsonValue],
    *,
    key: bytes,
    seq: int,
    prev: str,
    ts: int | float,
) -> tuple[bytes, AppendResult]:
    if RESERVED_FIELDS.intersection(event):
        raise AuditStorageError(AuditFailureCode.INVALID_SCHEMA)
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        raise AuditStorageError(AuditFailureCode.INVALID_SEQUENCE)
    if prev != GENESIS and not _valid_digest(prev):
        raise AuditStorageError(AuditFailureCode.INVALID_PREV)
    if not _valid_timestamp(ts):
        raise AuditStorageError(AuditFailureCode.INVALID_TIMESTAMP)
    if not isinstance(event.get("event"), str) or not event["event"]:
        raise AuditStorageError(AuditFailureCode.INVALID_SCHEMA)
    body: dict[str, JsonValue] = {
        "audit_version": AUDIT_VERSION,
        "seq": seq,
        "ts": ts,
        "prev": prev,
        **dict(event),
    }
    canonical = canonical_v2_body(body)
    digest = hmac.new(
        key, V2_DOMAIN_SEPARATOR + canonical, hashlib.sha256
    ).hexdigest()
    encoded = _canonical({**body, "hmac": digest}, ensure_ascii=False) + b"\n"
    return encoded, AppendResult(seq=seq, hmac=digest, ts=ts)
