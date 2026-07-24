from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from aegis.anchor import (
    AnchorReadResult,
    AnchorRecord,
    classify_anchor,
    cleanup_anchor_temps_locked,
    read_anchor_locked,
    write_anchor_locked,
)
from aegis.audit_storage import (
    FILE_MODE,
    AnchorState,
    AuditFailureCode,
    AuditStorage,
    AuditStorageError,
    _PosixAuditIO,
    replay_bytes,
)
from aegis.config import DEFAULT_POLICY, Policy
from aegis.guardrail import AuditLog
from tests.audit_support import TEST_KEY, signed_v1


def replay_with_two_records():
    first, tip = signed_v1({"event": "one"}, seq=1)
    second, _ = signed_v1({"event": "two"}, seq=2, previous=tip)
    return replay_bytes(first + second, key=TEST_KEY)


def test_anchor_classification_matrix() -> None:
    replay = replay_with_two_records()
    first = replay.records[0]
    assert classify_anchor(
        replay,
        AnchorReadResult(AnchorState.MISSING, None),
        configured=False,
    ) is AnchorState.DISABLED
    assert classify_anchor(
        replay_bytes(b"", key=TEST_KEY),
        AnchorReadResult(AnchorState.MISSING, None),
        configured=True,
    ) is AnchorState.UNINITIALIZED
    assert classify_anchor(
        replay,
        AnchorReadResult(AnchorState.MISSING, None),
        configured=True,
    ) is AnchorState.MISSING
    assert classify_anchor(
        replay,
        AnchorReadResult(
            AnchorState.MATCH,
            AnchorRecord(replay.count, replay.tip, replay.final_ts),
        ),
        configured=True,
    ) is AnchorState.MATCH
    assert classify_anchor(
        replay,
        AnchorReadResult(
            AnchorState.MATCH, AnchorRecord(1, first.hmac, first.ts)
        ),
        configured=True,
    ) is AnchorState.STALE
    assert classify_anchor(
        replay,
        AnchorReadResult(
            AnchorState.MATCH, AnchorRecord(3, "0" * 64, 3)
        ),
        configured=True,
    ) is AnchorState.AHEAD
    assert classify_anchor(
        replay,
        AnchorReadResult(
            AnchorState.MATCH, AnchorRecord(2, "0" * 64, replay.final_ts)
        ),
        configured=True,
    ) is AnchorState.DIVERGENT
    assert classify_anchor(
        replay,
        AnchorReadResult(AnchorState.MALFORMED, None),
        configured=True,
    ) is AnchorState.MALFORMED


def test_anchor_timestamp_is_signed_record_timestamp() -> None:
    replay = replay_with_two_records()
    assert classify_anchor(
        replay,
        AnchorReadResult(
            AnchorState.MATCH,
            AnchorRecord(replay.count, replay.tip, replay.final_ts + 1),
        ),
        configured=True,
    ) is AnchorState.DIVERGENT


def test_atomic_anchor_round_trip_and_mode(tmp_path: Path) -> None:
    storage = AuditStorage(
        tmp_path / "audit.ndjson",
        key=TEST_KEY,
        chained=True,
        anchor_path=tmp_path / "anchor.json",
    )
    record = AnchorRecord(1, "a" * 64, 1.5)
    with storage.locked_operation() as held:
        parent = storage.open_anchor_parent_locked(held)
        assert parent is not None
        try:
            write_anchor_locked(held, parent, "anchor.json", record)
            assert read_anchor_locked(held, parent, "anchor.json").record == record
        finally:
            parent.close()
    assert stat.S_IMODE((tmp_path / "anchor.json").stat().st_mode) == FILE_MODE


def test_strict_anchor_read_classifies_malformed(tmp_path: Path) -> None:
    anchor = tmp_path / "anchor.json"
    anchor.write_text('{"seq":true,"tip":"x","ts":1}\n')
    anchor.chmod(0o600)
    storage = AuditStorage(
        tmp_path / "audit.ndjson",
        key=TEST_KEY,
        chained=True,
        anchor_path=anchor,
    )
    with storage.locked_operation() as held:
        parent = storage.open_anchor_parent_locked(held)
        assert parent is not None
        try:
            assert read_anchor_locked(
                held, parent, anchor.name
            ).state is AnchorState.MALFORMED
        finally:
            parent.close()


def test_cleanup_removes_only_exact_owned_regular_anchor_temps(
    tmp_path: Path,
) -> None:
    removable = tmp_path / f".anchor.json.tmp.{os.getpid()}.{'a' * 16}"
    removable.write_bytes(b"x")
    removable.chmod(0o600)
    invalid_prefix = tmp_path / ".anchor.json.tmp.safe"
    invalid_prefix.write_bytes(b"x")
    invalid_prefix.chmod(0o600)
    unrelated = tmp_path / ".other.tmp.safe"
    unrelated.write_bytes(b"x")
    unrelated.chmod(0o600)
    storage = AuditStorage(
        tmp_path / "audit.ndjson",
        key=TEST_KEY,
        chained=True,
        anchor_path=tmp_path / "anchor.json",
    )
    with storage.locked_operation() as held:
        parent = storage.open_anchor_parent_locked(held)
        assert parent is not None
        try:
            cleanup_anchor_temps_locked(held, parent, "anchor.json")
        finally:
            parent.close()
    assert not removable.exists()
    assert invalid_prefix.exists()
    assert unrelated.exists()


@pytest.mark.parametrize("unsafe_kind", ["directory", "symlink", "mode"])
def test_matching_unsafe_abandoned_temp_fails_closed(
    tmp_path: Path, unsafe_kind: str
) -> None:
    candidate = tmp_path / f".anchor.json.tmp.{os.getpid()}.{'b' * 16}"
    if unsafe_kind == "directory":
        candidate.mkdir()
    elif unsafe_kind == "symlink":
        target = tmp_path / "target"
        target.write_bytes(b"x")
        target.chmod(0o600)
        candidate.symlink_to(target)
    else:
        candidate.write_bytes(b"x")
        candidate.chmod(0o640)
    storage = AuditStorage(
        tmp_path / "audit.ndjson",
        key=TEST_KEY,
        chained=True,
        anchor_path=tmp_path / "anchor.json",
    )
    with storage.locked_operation() as held:
        parent = storage.open_anchor_parent_locked(held)
        assert parent is not None
        try:
            with pytest.raises(AuditStorageError):
                cleanup_anchor_temps_locked(held, parent, "anchor.json")
        finally:
            parent.close()
    assert candidate.exists() or candidate.is_symlink()


class _FailTempUnlinkIO(_PosixAuditIO):
    def unlink(self, name: str, *, dir_fd: int) -> None:
        if name.startswith(".anchor.json.tmp."):
            raise PermissionError("injected unlink failure")
        super().unlink(name, dir_fd=dir_fd)


class _FailAnchorWriteAndUnlinkIO(_FailTempUnlinkIO):
    def write(self, fd: int, data: bytes) -> int:
        del fd, data
        raise OSError("injected write failure")


class _FailAnchorReplaceIO(_PosixAuditIO):
    def replace(
        self,
        source: str,
        destination: str,
        *,
        source_dir_fd: int,
        destination_dir_fd: int,
    ) -> None:
        del source, destination, source_dir_fd, destination_dir_fd
        raise OSError("injected anchor replace failure")


class _RecordingAnchorIO(_PosixAuditIO):
    def __init__(self) -> None:
        self.temp_fds: set[int] = set()
        self.events: list[str] = []

    def open(
        self,
        path: str,
        flags: int,
        mode: int = FILE_MODE,
        *,
        dir_fd: int | None = None,
    ) -> int:
        fd = super().open(path, flags, mode, dir_fd=dir_fd)
        if ".tmp." in path:
            self.temp_fds.add(fd)
        return fd

    def write(self, fd: int, data: bytes) -> int:
        if fd in self.temp_fds and "write" not in self.events:
            self.events.append("write")
        return super().write(fd, data)

    def fsync(self, fd: int) -> None:
        self.events.append(
            "file-fsync" if fd in self.temp_fds else "directory-fsync"
        )
        super().fsync(fd)

    def replace(
        self,
        source: str,
        destination: str,
        *,
        source_dir_fd: int,
        destination_dir_fd: int,
    ) -> None:
        self.events.append("replace")
        super().replace(
            source,
            destination,
            source_dir_fd=source_dir_fd,
            destination_dir_fd=destination_dir_fd,
        )

    def close(self, fd: int) -> None:
        self.temp_fds.discard(fd)
        super().close(fd)


class _ForeignTempOwnerIO(_PosixAuditIO):
    def __init__(self) -> None:
        self._foreign_fds: set[int] = set()

    def open(
        self,
        path: str,
        flags: int,
        mode: int = FILE_MODE,
        *,
        dir_fd: int | None = None,
    ) -> int:
        fd = super().open(path, flags, mode, dir_fd=dir_fd)
        if path.startswith(".anchor.json.tmp."):
            self._foreign_fds.add(fd)
        return fd

    def fstat(self, fd: int) -> os.stat_result:
        metadata = super().fstat(fd)
        if fd not in self._foreign_fds:
            return metadata
        values = list(metadata)
        values[4] = metadata.st_uid + 1
        return os.stat_result(values)

    def close(self, fd: int) -> None:
        self._foreign_fds.discard(fd)
        super().close(fd)


def test_matching_wrong_owner_abandoned_temp_fails_closed(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / f".anchor.json.tmp.{os.getpid()}.{'e' * 16}"
    candidate.write_bytes(b"x")
    candidate.chmod(0o600)
    storage = AuditStorage(
        tmp_path / "audit.ndjson",
        key=TEST_KEY,
        chained=True,
        anchor_path=tmp_path / "anchor.json",
        _io=_ForeignTempOwnerIO(),
    )
    with storage.locked_operation() as held:
        parent = storage.open_anchor_parent_locked(held)
        assert parent is not None
        try:
            with pytest.raises(AuditStorageError) as error:
                cleanup_anchor_temps_locked(held, parent, "anchor.json")
        finally:
            parent.close()
    assert error.value.code is AuditFailureCode.UNSAFE_OWNER
    assert candidate.exists()


def test_matching_temp_unlink_failure_is_propagated(tmp_path: Path) -> None:
    candidate = tmp_path / f".anchor.json.tmp.{os.getpid()}.{'c' * 16}"
    candidate.write_bytes(b"x")
    candidate.chmod(0o600)
    storage = AuditStorage(
        tmp_path / "audit.ndjson",
        key=TEST_KEY,
        chained=True,
        anchor_path=tmp_path / "anchor.json",
        _io=_FailTempUnlinkIO(),
    )
    with storage.locked_operation() as held:
        parent = storage.open_anchor_parent_locked(held)
        assert parent is not None
        try:
            with pytest.raises(AuditStorageError) as error:
                cleanup_anchor_temps_locked(held, parent, "anchor.json")
        finally:
            parent.close()
    assert error.value.code is AuditFailureCode.IO_FAILURE
    assert candidate.exists()


def test_anchor_write_preserves_primary_and_reports_cleanup_failure(
    tmp_path: Path,
) -> None:
    storage = AuditStorage(
        tmp_path / "audit.ndjson",
        key=TEST_KEY,
        chained=True,
        anchor_path=tmp_path / "anchor.json",
        _io=_FailAnchorWriteAndUnlinkIO(),
    )
    with storage.locked_operation() as held:
        parent = storage.open_anchor_parent_locked(held)
        assert parent is not None
        try:
            with pytest.raises(AuditStorageError) as error:
                write_anchor_locked(
                    held,
                    parent,
                    "anchor.json",
                    AnchorRecord(1, "a" * 64, 1),
                )
        finally:
            parent.close()
    assert error.value.code is AuditFailureCode.IO_FAILURE
    assert error.value.cleanup_code is AuditFailureCode.IO_FAILURE
    assert str(error.value) == "io-failure; cleanup=io-failure"


def test_atomic_anchor_write_orders_file_and_directory_fsync(
    tmp_path: Path,
) -> None:
    io = _RecordingAnchorIO()
    storage = AuditStorage(
        tmp_path / "audit.ndjson",
        key=TEST_KEY,
        chained=True,
        anchor_path=tmp_path / "anchor.json",
        _io=io,
    )
    with storage.locked_operation() as held:
        parent = storage.open_anchor_parent_locked(held)
        assert parent is not None
        try:
            write_anchor_locked(
                held,
                parent,
                "anchor.json",
                AnchorRecord(1, "a" * 64, 1),
            )
        finally:
            parent.close()
    assert io.events == [
        "write",
        "file-fsync",
        "replace",
        "directory-fsync",
    ]


def test_anchor_write_failure_leaves_recoverable_stale_state(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.ndjson"
    anchor_path = tmp_path / "anchor.json"
    normal = AuditStorage(
        path, key=TEST_KEY, chained=True, anchor_path=anchor_path
    )
    with normal.locked_operation() as held:
        replay = normal.replay_locked(held)
        first = normal.append_v2_locked(
            held, replay, {"event": "one"}, ts=1
        )
        parent = normal.open_anchor_parent_locked(held)
        assert parent is not None
        try:
            write_anchor_locked(
                held,
                parent,
                anchor_path.name,
                AnchorRecord(first.seq, first.hmac, first.ts),
            )
        finally:
            parent.close()
    failing = AuditStorage(
        path,
        key=TEST_KEY,
        chained=True,
        anchor_path=anchor_path,
        _io=_FailAnchorReplaceIO(),
    )
    with failing.locked_operation() as held:
        replay = failing.replay_locked(held)
        second = failing.append_v2_locked(
            held, replay, {"event": "two"}, ts=2
        )
        parent = failing.open_anchor_parent_locked(held)
        assert parent is not None
        try:
            with pytest.raises(AuditStorageError) as error:
                write_anchor_locked(
                    held,
                    parent,
                    anchor_path.name,
                    AnchorRecord(second.seq, second.hmac, second.ts),
                )
        finally:
            parent.close()
    assert error.value.code is AuditFailureCode.IO_FAILURE
    with normal.locked_operation() as held:
        replay = normal.replay_locked(held)
        parent = normal.open_anchor_parent_locked(held)
        assert parent is not None
        try:
            read = read_anchor_locked(held, parent, anchor_path.name)
            assert (
                classify_anchor(replay, read, configured=True)
                is AnchorState.STALE
            )
        finally:
            parent.close()


def test_abandoned_valid_temp_is_cleaned_before_normal_admission(
    tmp_path: Path, monkeypatch
) -> None:
    policy = diagnostic_policy(tmp_path, monkeypatch)
    candidate = tmp_path / f".anchor.json.tmp.{os.getpid()}.{'d' * 16}"
    candidate.write_bytes(b"x")
    candidate.chmod(0o600)
    AuditLog(policy)
    assert not candidate.exists()


def test_bootstrap_does_not_suppress_unsafe_temp_cleanup(
    tmp_path: Path, monkeypatch
) -> None:
    policy = diagnostic_policy(tmp_path, monkeypatch)
    object.__setattr__(policy, "audit_anchor_path", None)
    AuditLog(policy).write({"event": "one"})
    object.__setattr__(policy, "audit_anchor_path", tmp_path / "anchor.json")
    candidate = tmp_path / f".anchor.json.tmp.{os.getpid()}.{'f' * 16}"
    candidate.mkdir()
    with pytest.raises(AuditStorageError) as error:
        AuditLog._for_diagnostics(policy).bootstrap_anchor(confirmed=True)
    assert error.value.code is AuditFailureCode.NON_REGULAR_FILE
    assert candidate.is_dir()


def diagnostic_policy(tmp_path: Path, monkeypatch) -> Policy:
    monkeypatch.setenv("PENTEST_AUDIT_HMAC_KEY", "k" * 32)
    policy = Policy.load(DEFAULT_POLICY)
    object.__setattr__(policy, "audit_path", tmp_path / "audit.ndjson")
    object.__setattr__(policy, "audit_anchor_path", tmp_path / "anchor.json")
    return policy


def test_confirmed_bootstrap_changes_only_missing_anchor(
    tmp_path: Path, monkeypatch
) -> None:
    policy = diagnostic_policy(tmp_path, monkeypatch)
    object.__setattr__(policy, "audit_anchor_path", None)
    AuditLog(policy).write({"event": "one"})
    before = policy.audit_path.read_bytes()
    object.__setattr__(policy, "audit_anchor_path", tmp_path / "anchor.json")
    diagnostic = AuditLog._for_diagnostics(policy)
    report = diagnostic.bootstrap_anchor(confirmed=True)
    assert report.anchor_state is AnchorState.MATCH
    assert policy.audit_path.read_bytes() == before
    assert (tmp_path / "anchor.json").exists()


def test_bootstrap_refuses_empty_or_unconfirmed(
    tmp_path: Path, monkeypatch
) -> None:
    policy = diagnostic_policy(tmp_path, monkeypatch)
    diagnostic = AuditLog._for_diagnostics(policy)
    with pytest.raises(AuditStorageError) as unconfirmed:
        diagnostic.bootstrap_anchor(confirmed=False)
    assert unconfirmed.value.code is AuditFailureCode.WRITE_DISABLED
    with pytest.raises(AuditStorageError):
        diagnostic.bootstrap_anchor(confirmed=True)
    assert not policy.audit_path.exists()
    assert not (tmp_path / "anchor.json").exists()


def test_reconcile_updates_only_proven_stale_anchor(
    tmp_path: Path, monkeypatch
) -> None:
    policy = diagnostic_policy(tmp_path, monkeypatch)
    log = AuditLog(policy)
    log.write({"event": "one"})
    first = json.loads(policy.audit_path.read_text().splitlines()[0])
    log.write({"event": "two"})
    policy.audit_anchor_path.write_text(
        json.dumps(
            {"seq": 1, "tip": first["hmac"], "ts": first["ts"]},
            separators=(",", ":"),
        )
        + "\n"
    )
    policy.audit_anchor_path.chmod(0o600)
    before = policy.audit_path.read_bytes()
    report = AuditLog._for_diagnostics(policy).reconcile_anchor(
        confirmed=True
    )
    assert report.anchor_state is AnchorState.MATCH
    assert policy.audit_path.read_bytes() == before


@pytest.mark.parametrize(
    "state", ["missing", "malformed", "ahead", "divergent", "match"]
)
def test_reconciliation_refuses_other_states(
    tmp_path: Path, monkeypatch, state: str
) -> None:
    policy = diagnostic_policy(tmp_path, monkeypatch)
    log = AuditLog(policy)
    log.write({"event": "one"})
    record = json.loads(policy.audit_path.read_text())
    if state == "missing":
        policy.audit_anchor_path.unlink()
    elif state == "malformed":
        policy.audit_anchor_path.write_bytes(b"{broken\n")
    elif state == "ahead":
        policy.audit_anchor_path.write_text(
            json.dumps({"seq": 2, "tip": "a" * 64, "ts": 2}) + "\n"
        )
    elif state == "divergent":
        policy.audit_anchor_path.write_text(
            json.dumps(
                {"seq": 1, "tip": "a" * 64, "ts": record["ts"]}
            )
            + "\n"
        )
    if policy.audit_anchor_path.exists():
        policy.audit_anchor_path.chmod(0o600)
    before = policy.audit_path.read_bytes()
    with pytest.raises(AuditStorageError):
        AuditLog._for_diagnostics(policy).reconcile_anchor(confirmed=True)
    assert policy.audit_path.read_bytes() == before
