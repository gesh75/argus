from __future__ import annotations

import fcntl
import os
import stat
from pathlib import Path

import pytest

from aegis.audit_storage import (
    FILE_MODE,
    AuditFailureCode,
    AuditStorage,
    AuditStorageError,
    _PosixAuditIO,
)
from tests.audit_support import TEST_KEY


class CountingIO(_PosixAuditIO):
    def __init__(self) -> None:
        self.exclusive_attempts = 0

    def flock(self, fd: int, operation: int) -> None:
        if operation & fcntl.LOCK_EX:
            self.exclusive_attempts += 1
        super().flock(fd, operation)


class ShortWriteIO(_PosixAuditIO):
    def __init__(self) -> None:
        self.write_calls = 0
        self.fsync_calls = 0

    def write(self, fd: int, data: bytes) -> int:
        self.write_calls += 1
        return super().write(fd, data[:7])

    def fsync(self, fd: int) -> None:
        self.fsync_calls += 1
        super().fsync(fd)


class ImmediateTimeoutIO(_PosixAuditIO):
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        self.now += 11.0
        return self.now

    def sleep(self, seconds: float) -> None:
        del seconds

    def flock(self, fd: int, operation: int) -> None:
        if operation & fcntl.LOCK_EX:
            raise BlockingIOError
        super().flock(fd, operation)


def storage(path: Path, *, io: _PosixAuditIO | None = None) -> AuditStorage:
    return AuditStorage(
        path,
        key=TEST_KEY,
        chained=True,
        anchor_path=None,
        _io=io,
    )


def test_outer_operation_acquires_kernel_lock_once(tmp_path: Path) -> None:
    io = CountingIO()
    audit = storage(tmp_path / "audit.ndjson", io=io)
    with audit.locked_operation() as held:
        held.assert_held()
        held.assert_held()
    assert io.exclusive_attempts == 1
    assert stat.S_IMODE((tmp_path / ".audit.ndjson.lock").stat().st_mode) == FILE_MODE


def test_held_token_cannot_be_used_after_context(tmp_path: Path) -> None:
    audit = storage(tmp_path / "audit.ndjson")
    with audit.locked_operation() as held:
        held.assert_held()
    with pytest.raises(AuditStorageError) as error:
        held.assert_held()
    assert error.value.code is AuditFailureCode.WRITE_DISABLED


def test_missing_parent_is_not_created(tmp_path: Path) -> None:
    audit = storage(tmp_path / "missing" / "audit.ndjson")
    with pytest.raises(AuditStorageError) as error:
        with audit.locked_operation():
            pass
    assert error.value.code is AuditFailureCode.UNSAFE_PARENT
    assert not (tmp_path / "missing").exists()


def test_group_writable_parent_is_rejected(tmp_path: Path) -> None:
    tmp_path.chmod(0o770)
    audit = storage(tmp_path / "audit.ndjson")
    with pytest.raises(AuditStorageError) as error:
        with audit.locked_operation():
            pass
    assert error.value.code is AuditFailureCode.UNSAFE_MODE


def test_final_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"")
    (tmp_path / "audit.ndjson").symlink_to(target)
    audit = storage(tmp_path / "audit.ndjson")
    with audit.locked_operation() as held:
        with pytest.raises(AuditStorageError) as error:
            held.audit_parent.open_regular(held.audit_name, os.O_RDONLY)
    assert error.value.code is AuditFailureCode.SYMLINK


def test_non_regular_final_file_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "audit.ndjson").mkdir()
    audit = storage(tmp_path / "audit.ndjson")
    with audit.locked_operation() as held:
        with pytest.raises(AuditStorageError) as error:
            held.audit_parent.open_regular(held.audit_name, os.O_RDONLY)
    assert error.value.code is AuditFailureCode.NON_REGULAR_FILE


def test_existing_file_with_broad_mode_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "audit.ndjson"
    path.write_bytes(b"")
    path.chmod(0o640)
    audit = storage(path)
    with audit.locked_operation() as held:
        with pytest.raises(AuditStorageError) as error:
            held.audit_parent.open_regular(held.audit_name, os.O_RDONLY)
    assert error.value.code is AuditFailureCode.UNSAFE_MODE


def test_lock_timeout_uses_fixed_monotonic_deadline(tmp_path: Path) -> None:
    audit = storage(tmp_path / "audit.ndjson", io=ImmediateTimeoutIO())
    with pytest.raises(AuditStorageError) as error:
        with audit.locked_operation():
            pass
    assert error.value.code is AuditFailureCode.LOCK_TIMEOUT


def test_append_completes_short_writes_and_fsyncs(tmp_path: Path) -> None:
    io = ShortWriteIO()
    path = tmp_path / "audit.ndjson"
    audit = storage(path, io=io)
    with audit.locked_operation() as held:
        replay = audit.replay_locked(held)
        audit.append_v2_locked(
            held, replay, {"event": "short-write"}, ts=1
        )
    assert io.write_calls > 1
    assert io.fsync_calls == 1
    assert stat.S_IMODE(path.stat().st_mode) == FILE_MODE
