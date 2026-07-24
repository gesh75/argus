from __future__ import annotations

import multiprocessing
from pathlib import Path

import pytest

from aegis import anchor
from aegis.audit_storage import (
    AnchorState,
    AuditCheckpoint,
    AuditFailureCode,
    AuditStorage,
    AuditStorageError,
    replay_bytes,
)
from tests.audit_support import (
    TEST_KEY,
    anchored_append_worker,
    append_worker,
    checkpoint_worker,
    partial_write_worker,
)


def spawned(target, *args):
    process = multiprocessing.get_context("spawn").Process(
        target=target, args=args
    )
    process.start()
    process.join(15)
    if process.is_alive():
        process.terminate()
        process.join(5)
        pytest.fail("spawned audit worker timed out")
    return process


@pytest.mark.parametrize("round_number", range(3))
def test_separate_process_writers_form_one_linear_chain(
    tmp_path: Path, round_number: int
) -> None:
    path = tmp_path / f"audit-{round_number}.ndjson"
    context = multiprocessing.get_context("spawn")
    workers = [
        context.Process(target=append_worker, args=(str(path), 15, worker))
        for worker in range(3)
    ]
    for process in workers:
        process.start()
    for process in workers:
        process.join(20)
        assert process.exitcode == 0
    replay = replay_bytes(path.read_bytes(), key=TEST_KEY)
    assert replay.count == 45
    assert [record.seq for record in replay.records] == list(range(1, 46))


def test_partial_process_write_is_detected_and_lock_is_released(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.ndjson"
    process = spawned(partial_write_worker, str(path))
    assert process.exitcode == 78
    with pytest.raises(AuditStorageError) as error:
        replay_bytes(path.read_bytes(), key=TEST_KEY)
    assert error.value.code is AuditFailureCode.UNTERMINATED_RECORD
    storage = AuditStorage(
        path, key=TEST_KEY, chained=True, anchor_path=None
    )
    with storage.locked_operation() as held:
        held.assert_held()


def test_exit_after_log_fsync_leaves_complete_record_and_releases_lock(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.ndjson"
    process = spawned(
        checkpoint_worker,
        str(path),
        None,
        AuditCheckpoint.AFTER_LOG_FSYNC.value,
    )
    assert process.exitcode == 77
    assert replay_bytes(path.read_bytes(), key=TEST_KEY).count == 1
    storage = AuditStorage(
        path, key=TEST_KEY, chained=True, anchor_path=None
    )
    with storage.locked_operation() as held:
        assert storage.replay_locked(held).count == 1


def test_exit_after_anchor_file_fsync_leaves_stale_anchor(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.ndjson"
    anchor_path = tmp_path / "anchor.json"
    storage = AuditStorage(
        path, key=TEST_KEY, chained=True, anchor_path=anchor_path
    )
    with storage.locked_operation() as held:
        replay = storage.replay_locked(held)
        first = storage.append_v2_locked(
            held, replay, {"event": "seed"}, ts=1
        )
        parent = storage.open_anchor_parent_locked(held)
        assert parent is not None
        try:
            anchor.write_anchor_locked(
                held,
                parent,
                anchor_path.name,
                anchor.AnchorRecord(first.seq, first.hmac, first.ts),
            )
        finally:
            parent.close()


def test_crash_after_anchor_directory_fsync_is_committed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.ndjson"
    anchor_path = tmp_path / "anchor.json"
    process = spawned(
        checkpoint_worker,
        str(path),
        str(anchor_path),
        AuditCheckpoint.AFTER_ANCHOR_DIRECTORY_FSYNC.value,
    )
    assert process.exitcode == 77
    storage = AuditStorage(
        path, key=TEST_KEY, chained=True, anchor_path=anchor_path
    )
    with storage.locked_operation() as held:
        replay = storage.replay_locked(held)
        parent = storage.open_anchor_parent_locked(held)
        assert parent is not None
        try:
            read = anchor.read_anchor_locked(
                held, parent, anchor_path.name
            )
            assert replay.count == 1
            assert (
                anchor.classify_anchor(replay, read, configured=True)
                is AnchorState.MATCH
            )
        finally:
            parent.close()


@pytest.mark.parametrize("round_number", range(3))
def test_stress_anchor_matches_final_tip(
    tmp_path: Path, round_number: int
) -> None:
    path = tmp_path / f"audit-anchored-{round_number}.ndjson"
    anchor_path = tmp_path / f"anchor-{round_number}.json"
    context = multiprocessing.get_context("spawn")
    workers = [
        context.Process(
            target=anchored_append_worker,
            args=(str(path), str(anchor_path), 20, worker),
        )
        for worker in range(6)
    ]
    for process in workers:
        process.start()
    for process in workers:
        process.join(30)
        assert process.exitcode == 0
    storage = AuditStorage(
        path, key=TEST_KEY, chained=True, anchor_path=anchor_path
    )
    with storage.locked_operation() as held:
        replay = storage.replay_locked(held)
        parent = storage.open_anchor_parent_locked(held)
        assert parent is not None
        try:
            read = anchor.read_anchor_locked(
                held, parent, anchor_path.name
            )
            assert replay.count == 120
            assert len({record.event for record in replay.records}) == 120
            assert read.record is not None
            assert read.record.seq == replay.count
            assert read.record.tip == replay.tip
            assert read.record.ts == replay.final_ts
        finally:
            parent.close()

    process = spawned(
        checkpoint_worker,
        str(path),
        str(anchor_path),
        AuditCheckpoint.AFTER_ANCHOR_FILE_FSYNC.value,
    )
    assert process.exitcode == 77
    with storage.locked_operation() as held:
        replay = storage.replay_locked(held)
        parent = storage.open_anchor_parent_locked(held)
        assert parent is not None
        try:
            read = anchor.read_anchor_locked(
                held, parent, anchor_path.name
            )
            assert (
                anchor.classify_anchor(replay, read, configured=True)
                is AnchorState.STALE
            )
        finally:
            parent.close()
