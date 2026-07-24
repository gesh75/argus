from __future__ import annotations

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
from aegis.audit_storage import AnchorState, AuditStorage, FILE_MODE, replay_bytes
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


def test_cleanup_removes_only_owned_regular_anchor_temps(tmp_path: Path) -> None:
    removable = tmp_path / ".anchor.json.tmp.safe"
    removable.write_bytes(b"x")
    removable.chmod(0o600)
    unrelated = tmp_path / ".other.tmp.safe"
    unrelated.write_bytes(b"x")
    unrelated.chmod(0o600)
    directory = tmp_path / ".anchor.json.tmp.directory"
    directory.mkdir()
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
    assert unrelated.exists()
    assert directory.is_dir()
