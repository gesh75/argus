"""Strict, versioned audit-record encoding and replay primitives."""

from __future__ import annotations

import errno
import hashlib
import hmac
import json
import math
import os
import re
import stat
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol, Self

try:
    import fcntl
except ImportError:  # pragma: no cover - supported writers are POSIX only
    fcntl = None  # type: ignore[assignment]

AUDIT_VERSION = 2
GENESIS = "genesis"
V2_DOMAIN_SEPARATOR = b"ARGUS-AUDIT-V2\0"
LOCK_TIMEOUT_SECONDS = 10.0
FILE_MODE = 0o600
RESERVED_FIELDS = frozenset({"audit_version", "seq", "ts", "prev", "hmac"})

type JsonScalar = None | bool | int | float | str
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]

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
        self,
        code: AuditFailureCode,
        *,
        record_number: int | None = None,
        cleanup_code: AuditFailureCode | None = None,
    ) -> None:
        self.code = code
        self.record_number = record_number
        self.cleanup_code = cleanup_code
        super().__init__(str(self))

    def __str__(self) -> str:
        suffix = (
            f" at record {self.record_number}"
            if self.record_number is not None
            else ""
        )
        cleanup = (
            f"; cleanup={self.cleanup_code.value}"
            if self.cleanup_code is not None
            else ""
        )
        return f"{self.code.value}{suffix}{cleanup}"


INTEGRITY_FAILURE_CODES = frozenset(
    {
        AuditFailureCode.MALFORMED_JSON,
        AuditFailureCode.DUPLICATE_KEY,
        AuditFailureCode.INVALID_UTF8,
        AuditFailureCode.NON_OBJECT_JSON,
        AuditFailureCode.INVALID_SCHEMA,
        AuditFailureCode.INVALID_VERSION,
        AuditFailureCode.INVALID_SEQUENCE,
        AuditFailureCode.INVALID_PREV,
        AuditFailureCode.INVALID_HMAC,
        AuditFailureCode.INVALID_TIMESTAMP,
        AuditFailureCode.UNTERMINATED_RECORD,
        AuditFailureCode.ANCHOR_MISSING,
        AuditFailureCode.ANCHOR_STALE,
        AuditFailureCode.ANCHOR_AHEAD,
        AuditFailureCode.ANCHOR_DIVERGENT,
        AuditFailureCode.ANCHOR_MALFORMED,
    }
)


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


class _AuditIO(Protocol):
    def open(
        self,
        path: str,
        flags: int,
        mode: int = FILE_MODE,
        *,
        dir_fd: int | None = None,
    ) -> int: ...

    def close(self, fd: int) -> None: ...

    def fstat(self, fd: int) -> os.stat_result: ...

    def flock(self, fd: int, operation: int) -> None: ...

    def monotonic(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...

    def fsync(self, fd: int) -> None: ...

    def write(self, fd: int, data: bytes) -> int: ...

    def read(self, fd: int, size: int) -> bytes: ...

    def replace(
        self,
        source: str,
        destination: str,
        *,
        source_dir_fd: int,
        destination_dir_fd: int,
    ) -> None: ...

    def unlink(self, name: str, *, dir_fd: int) -> None: ...

    def listdir(self, fd: int) -> list[str]: ...

    def checkpoint(self, point: AuditCheckpoint) -> None: ...


class _PosixAuditIO:
    def open(
        self,
        path: str,
        flags: int,
        mode: int = FILE_MODE,
        *,
        dir_fd: int | None = None,
    ) -> int:
        return os.open(path, flags, mode, dir_fd=dir_fd)

    def close(self, fd: int) -> None:
        os.close(fd)

    def fstat(self, fd: int) -> os.stat_result:
        return os.fstat(fd)

    def flock(self, fd: int, operation: int) -> None:
        if fcntl is None:
            raise AuditStorageError(AuditFailureCode.UNSUPPORTED_PLATFORM)
        fcntl.flock(fd, operation)

    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def fsync(self, fd: int) -> None:
        os.fsync(fd)

    def write(self, fd: int, data: bytes) -> int:
        return os.write(fd, data)

    def read(self, fd: int, size: int) -> bytes:
        return os.read(fd, size)

    def replace(
        self,
        source: str,
        destination: str,
        *,
        source_dir_fd: int,
        destination_dir_fd: int,
    ) -> None:
        os.replace(
            source,
            destination,
            src_dir_fd=source_dir_fd,
            dst_dir_fd=destination_dir_fd,
        )

    def unlink(self, name: str, *, dir_fd: int) -> None:
        os.unlink(name, dir_fd=dir_fd)

    def listdir(self, fd: int) -> list[str]:
        return os.listdir(fd)

    def checkpoint(self, point: AuditCheckpoint) -> None:
        del point


@dataclass(slots=True)
class TrustedParent:
    path: Path
    fd: int
    owner_uid: int
    _io: _AuditIO

    @classmethod
    def open(cls, parent: Path, *, io: _AuditIO) -> Self:
        try:
            resolved = parent.resolve(strict=True)
            fd = io.open(
                str(resolved),
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
        except (FileNotFoundError, NotADirectoryError, OSError) as exc:
            raise AuditStorageError(AuditFailureCode.UNSAFE_PARENT) from exc
        try:
            metadata = io.fstat(fd)
            if not stat.S_ISDIR(metadata.st_mode):
                raise AuditStorageError(AuditFailureCode.UNSAFE_PARENT)
            if metadata.st_uid != os.geteuid():
                raise AuditStorageError(AuditFailureCode.UNSAFE_OWNER)
            if stat.S_IMODE(metadata.st_mode) & 0o022:
                raise AuditStorageError(AuditFailureCode.UNSAFE_MODE)
            return cls(resolved, fd, metadata.st_uid, io)
        except BaseException:
            io.close(fd)
            raise

    def open_regular(
        self,
        name: str,
        flags: int,
        *,
        create_mode: int = FILE_MODE,
    ) -> int:
        if not name or Path(name).name != name:
            raise AuditStorageError(AuditFailureCode.INVALID_SCHEMA)
        try:
            fd = self._io.open(
                name,
                flags
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                create_mode,
                dir_fd=self.fd,
            )
        except OSError as exc:
            code = (
                AuditFailureCode.SYMLINK
                if exc.errno in {errno.ELOOP, errno.EMLINK}
                else AuditFailureCode.NON_REGULAR_FILE
                if exc.errno in {errno.EISDIR, errno.ENXIO}
                else AuditFailureCode.IO_FAILURE
            )
            raise AuditStorageError(code) from exc
        try:
            metadata = self._io.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise AuditStorageError(AuditFailureCode.NON_REGULAR_FILE)
            if metadata.st_uid != self.owner_uid:
                raise AuditStorageError(AuditFailureCode.UNSAFE_OWNER)
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise AuditStorageError(AuditFailureCode.UNSAFE_MODE)
            return fd
        except BaseException:
            self._io.close(fd)
            raise

    def replace(self, source_name: str, destination_name: str) -> None:
        self._io.replace(
            source_name,
            destination_name,
            source_dir_fd=self.fd,
            destination_dir_fd=self.fd,
        )

    def unlink_regular(self, name: str) -> None:
        fd = self.open_regular(name, os.O_RDONLY)
        self._io.close(fd)
        self._io.unlink(name, dir_fd=self.fd)

    def fsync(self) -> None:
        self._io.fsync(self.fd)

    def close(self) -> None:
        self._io.close(self.fd)


@dataclass(slots=True)
class HeldAuditLock:
    audit_parent: TrustedParent
    lock_fd: int
    audit_name: str
    lock_name: str
    _token: object
    _active: bool = True

    def assert_held(self) -> None:
        if not self._active:
            raise AuditStorageError(AuditFailureCode.WRITE_DISABLED)


_PROCESS_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[str, threading.RLock] = {}
_ACTIVE_LOCKS = threading.local()


def _process_lock(identity: str) -> threading.RLock:
    with _PROCESS_LOCKS_GUARD:
        return _PROCESS_LOCKS.setdefault(identity, threading.RLock())


def _thread_active_locks() -> dict[str, HeldAuditLock]:
    active = getattr(_ACTIVE_LOCKS, "held", None)
    if active is None:
        active = {}
        _ACTIVE_LOCKS.held = active
    return active


class AuditStorage:
    def __init__(
        self,
        audit_path: Path,
        *,
        key: bytes,
        chained: bool,
        anchor_path: Path | None,
        _io: _AuditIO | None = None,
    ) -> None:
        self.audit_path = Path(audit_path)
        self.key = key
        self.chained = chained
        self.anchor_path = Path(anchor_path) if anchor_path is not None else None
        self._io = _io or _PosixAuditIO()

    @contextmanager
    def locked_operation(self) -> Iterator[HeldAuditLock]:
        if fcntl is None:
            raise AuditStorageError(AuditFailureCode.UNSUPPORTED_PLATFORM)
        try:
            identity = str(self.audit_path.parent.resolve(strict=True) / self.audit_path.name)
        except OSError as exc:
            raise AuditStorageError(AuditFailureCode.UNSAFE_PARENT) from exc
        process_lock = _process_lock(identity)
        deadline = self._io.monotonic() + LOCK_TIMEOUT_SECONDS
        while not process_lock.acquire(blocking=False):
            if self._io.monotonic() >= deadline:
                raise AuditStorageError(AuditFailureCode.LOCK_TIMEOUT)
            self._io.sleep(0.01)
        active_locks = _thread_active_locks()
        reentrant = active_locks.get(identity)
        if reentrant is not None:
            try:
                reentrant.assert_held()
                yield reentrant
            finally:
                process_lock.release()
            return
        if self._io.monotonic() >= deadline:
            process_lock.release()
            raise AuditStorageError(AuditFailureCode.LOCK_TIMEOUT)
        parent: TrustedParent | None = None
        lock_fd = -1
        held: HeldAuditLock | None = None
        try:
            parent = TrustedParent.open(self.audit_path.parent, io=self._io)
            lock_name = f".{self.audit_path.name}.lock"
            lock_fd = parent.open_regular(
                lock_name, os.O_RDWR | os.O_CREAT, create_mode=FILE_MODE
            )
            while True:
                if self._io.monotonic() >= deadline:
                    raise AuditStorageError(
                        AuditFailureCode.LOCK_TIMEOUT
                    )
                try:
                    self._io.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as exc:
                    retryable = isinstance(exc, BlockingIOError) or (
                        exc.errno == errno.EINTR
                    )
                    if not retryable:
                        raise
                    if self._io.monotonic() >= deadline:
                        raise AuditStorageError(
                            AuditFailureCode.LOCK_TIMEOUT
                        ) from exc
                    self._io.sleep(0.01)
            held = HeldAuditLock(
                audit_parent=parent,
                lock_fd=lock_fd,
                audit_name=self.audit_path.name,
                lock_name=lock_name,
                _token=object(),
            )
            active_locks[identity] = held
            yield held
        except AuditStorageError:
            raise
        except OSError as exc:
            raise AuditStorageError(AuditFailureCode.IO_FAILURE) from exc
        finally:
            try:
                active_locks.pop(identity, None)
                if held is not None:
                    held._active = False
                    try:
                        self._io.flock(lock_fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
                if lock_fd >= 0:
                    self._io.close(lock_fd)
                if parent is not None:
                    parent.close()
            finally:
                process_lock.release()

    def open_anchor_parent_locked(
        self, held: HeldAuditLock
    ) -> TrustedParent | None:
        held.assert_held()
        if self.anchor_path is None:
            return None
        return TrustedParent.open(self.anchor_path.parent, io=self._io)

    def replay_locked(self, held: HeldAuditLock) -> ReplayResult:
        held.assert_held()
        fd = -1
        try:
            try:
                fd = held.audit_parent.open_regular(
                    held.audit_name, os.O_RDONLY
                )
            except AuditStorageError as exc:
                if isinstance(exc.__cause__, FileNotFoundError):
                    return replay_bytes(b"", key=self.key)
                raise
            chunks: list[bytes] = []
            while True:
                chunk = self._io.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            return replay_bytes(b"".join(chunks), key=self.key)
        except AuditStorageError:
            raise
        except OSError as exc:
            raise AuditStorageError(AuditFailureCode.IO_FAILURE) from exc
        finally:
            if fd >= 0:
                self._io.close(fd)

    def append_v2_locked(
        self,
        held: HeldAuditLock,
        replay: ReplayResult,
        event: Mapping[str, JsonValue],
        *,
        ts: int | float,
    ) -> AppendResult:
        held.assert_held()
        if not self.chained:
            raise AuditStorageError(AuditFailureCode.WRITE_DISABLED)
        if replay.state not in {
            LogState.EMPTY,
            LogState.VALID_V1,
            LogState.VALID_V2,
            LogState.VALID_V1_V2,
        }:
            raise AuditStorageError(AuditFailureCode.INVALID_SCHEMA)
        encoded, result = encode_v2_record(
            event,
            key=self.key,
            seq=replay.count + 1,
            prev=replay.tip,
            ts=ts,
        )
        fd = -1
        try:
            fd = held.audit_parent.open_regular(
                held.audit_name,
                os.O_WRONLY | os.O_APPEND | os.O_CREAT,
                create_mode=FILE_MODE,
            )
            offset = 0
            while offset < len(encoded):
                written = self._io.write(fd, encoded[offset:])
                if written <= 0:
                    raise AuditStorageError(AuditFailureCode.IO_FAILURE)
                offset += written
            self._io.fsync(fd)
            self._io.checkpoint(AuditCheckpoint.AFTER_LOG_FSYNC)
            return result
        except AuditStorageError:
            raise
        except OSError as exc:
            raise AuditStorageError(AuditFailureCode.IO_FAILURE) from exc
        finally:
            if fd >= 0:
                self._io.close(fd)


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
    if any(not isinstance(field, str) for field in event):
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
