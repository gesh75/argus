from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

TEST_KEY = b"phase-2a-test-key-material-32-bytes"


def signed_v1(
    event: Mapping[str, Any],
    *,
    seq: int,
    previous: str = "genesis",
    chained: bool = True,
) -> tuple[bytes, str]:
    entry = {
        "ts": 1_700_000_000 + seq,
        "prev": previous if chained else None,
        **event,
    }
    body = json.dumps(
        entry,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    signed = (previous + body).encode() if chained else body.encode()
    digest = hmac.new(TEST_KEY, signed, hashlib.sha256).hexdigest()
    return (
        json.dumps({**entry, "hmac": digest}, separators=(",", ":")).encode() + b"\n",
        digest,
    )


def replace_json_field(record: bytes, field: str, value: Any) -> bytes:
    decoded = json.loads(record)
    decoded[field] = value
    return json.dumps(decoded, separators=(",", ":")).encode() + b"\n"


def append_worker(path: str, count: int, worker_id: int) -> None:
    from aegis.audit_storage import AuditStorage

    storage = AuditStorage(
        Path(path), key=TEST_KEY, chained=True, anchor_path=None
    )
    for index in range(count):
        with storage.locked_operation() as held:
            replay = storage.replay_locked(held)
            storage.append_v2_locked(
                held,
                replay,
                {"event": "worker", "worker": worker_id, "index": index},
                ts=worker_id * 10_000 + index,
            )


def anchored_append_worker(
    path: str, anchor_path: str, count: int, worker_id: int
) -> None:
    from aegis import anchor
    from aegis.audit_storage import AnchorState, AuditStorage

    storage = AuditStorage(
        Path(path),
        key=TEST_KEY,
        chained=True,
        anchor_path=Path(anchor_path),
    )
    for index in range(count):
        with storage.locked_operation() as held:
            replay = storage.replay_locked(held)
            parent = storage.open_anchor_parent_locked(held)
            assert parent is not None
            try:
                anchor.cleanup_anchor_temps_locked(
                    held, parent, Path(anchor_path).name
                )
                read = anchor.read_anchor_locked(
                    held, parent, Path(anchor_path).name
                )
                state = anchor.classify_anchor(
                    replay, read, configured=True
                )
                assert state in {
                    AnchorState.UNINITIALIZED,
                    AnchorState.MATCH,
                }
                result = storage.append_v2_locked(
                    held,
                    replay,
                    {"event": f"worker-{worker_id}-{index}"},
                    ts=worker_id * 10_000 + index,
                )
                anchor.write_anchor_locked(
                    held,
                    parent,
                    Path(anchor_path).name,
                    anchor.AnchorRecord(
                        result.seq, result.hmac, result.ts
                    ),
                )
            finally:
                parent.close()


def partial_write_worker(path: str) -> None:
    from aegis.audit_storage import AuditStorage, _PosixAuditIO

    class ExitAfterFirstWrite(_PosixAuditIO):
        def write(self, fd: int, data: bytes) -> int:
            written = super().write(fd, data[:9])
            os._exit(78)
            return written

    storage = AuditStorage(
        Path(path),
        key=TEST_KEY,
        chained=True,
        anchor_path=None,
        _io=ExitAfterFirstWrite(),
    )
    with storage.locked_operation() as held:
        replay = storage.replay_locked(held)
        storage.append_v2_locked(
            held, replay, {"event": "partial"}, ts=1
        )


def checkpoint_worker(
    path: str, anchor_path: str | None, checkpoint: str
) -> None:
    from aegis import anchor
    from aegis.audit_storage import (
        AuditCheckpoint,
        AuditStorage,
        _PosixAuditIO,
    )

    class ExitAtCheckpoint(_PosixAuditIO):
        def checkpoint(self, point: AuditCheckpoint) -> None:
            if point.value == checkpoint:
                os._exit(77)

    storage = AuditStorage(
        Path(path),
        key=TEST_KEY,
        chained=True,
        anchor_path=Path(anchor_path) if anchor_path else None,
        _io=ExitAtCheckpoint(),
    )
    with storage.locked_operation() as held:
        replay = storage.replay_locked(held)
        result = storage.append_v2_locked(
            held, replay, {"event": "checkpoint"}, ts=replay.count + 1
        )
        parent = storage.open_anchor_parent_locked(held)
        if parent is not None:
            try:
                anchor.write_anchor_locked(
                    held,
                    parent,
                    Path(anchor_path).name,
                    anchor.AnchorRecord(
                        result.seq, result.hmac, result.ts
                    ),
                )
            finally:
                parent.close()
