from __future__ import annotations

import json

import pytest

from aegis.audit_storage import (
    AuditFailureCode,
    AuditStorage,
    AuditStorageError,
    GENESIS,
    LogState,
    encode_v2_record,
    replay_bytes,
    strict_json_object,
)
from tests.audit_support import TEST_KEY, replace_json_field, signed_v1


def test_strict_json_rejects_duplicate_key_and_non_object() -> None:
    with pytest.raises(AuditStorageError) as duplicate:
        strict_json_object(b'{"event":"a","event":"b"}', record_number=1)
    assert duplicate.value.code is AuditFailureCode.DUPLICATE_KEY
    with pytest.raises(AuditStorageError) as non_object:
        strict_json_object(b"[]", record_number=1)
    assert non_object.value.code is AuditFailureCode.NON_OBJECT_JSON


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b"\xff", AuditFailureCode.INVALID_UTF8),
        (b'{"event":NaN}', AuditFailureCode.MALFORMED_JSON),
        (b'{"event":', AuditFailureCode.MALFORMED_JSON),
    ],
)
def test_strict_json_rejects_invalid_input(raw: bytes, code: AuditFailureCode) -> None:
    with pytest.raises(AuditStorageError) as error:
        strict_json_object(raw, record_number=3)
    assert error.value.code is code
    assert str(error.value) == f"{code.value} at record 3"


@pytest.mark.parametrize("chained", [True, False])
def test_replay_accepts_independently_signed_v1(chained: bool) -> None:
    first, tip = signed_v1({"event": "one"}, seq=1, chained=chained)
    second, final_tip = signed_v1(
        {"event": "two"}, seq=2, previous=tip, chained=chained
    )
    result = replay_bytes(first + second, key=TEST_KEY)
    assert result.state is LogState.VALID_V1
    assert result.count == 2
    assert result.tip == final_tip
    assert result.records[-1].seq == 2


def test_replay_accepts_v1_to_v2_transition() -> None:
    first, tip = signed_v1({"event": "legacy"}, seq=1)
    second, append = encode_v2_record(
        {"event": "current"}, key=TEST_KEY, seq=2, prev=tip, ts=1_700_000_002
    )
    result = replay_bytes(first + second, key=TEST_KEY)
    assert result.state is LogState.VALID_V1_V2
    assert result.count == 2
    assert result.tip == append.hmac


def test_empty_replay_has_genesis_tip() -> None:
    result = replay_bytes(b"", key=TEST_KEY)
    assert result.state is LogState.EMPTY
    assert result.count == 0
    assert result.tip == GENESIS


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("seq", 2, AuditFailureCode.INVALID_SEQUENCE),
        ("seq", True, AuditFailureCode.INVALID_SEQUENCE),
        ("audit_version", True, AuditFailureCode.INVALID_VERSION),
        ("prev", "0" * 64, AuditFailureCode.INVALID_PREV),
        ("hmac", "0" * 64, AuditFailureCode.INVALID_HMAC),
        ("ts", True, AuditFailureCode.INVALID_TIMESTAMP),
    ],
)
def test_v2_replay_rejects_corruption(
    field: str, value: object, code: AuditFailureCode
) -> None:
    record, _ = encode_v2_record(
        {"event": "one"}, key=TEST_KEY, seq=1, prev=GENESIS, ts=1
    )
    with pytest.raises(AuditStorageError) as error:
        replay_bytes(replace_json_field(record, field, value), key=TEST_KEY)
    assert error.value.code is code


def test_v2_replay_rejects_v1_after_v2() -> None:
    first, append = encode_v2_record(
        {"event": "current"}, key=TEST_KEY, seq=1, prev=GENESIS, ts=1
    )
    second, _ = signed_v1({"event": "legacy"}, seq=2, previous=append.hmac)
    with pytest.raises(AuditStorageError) as error:
        replay_bytes(first + second, key=TEST_KEY)
    assert error.value.code is AuditFailureCode.INVALID_VERSION


@pytest.mark.parametrize(
    "raw",
    [
        b'{"audit_version":2,"event":"x"}\n',
        b'{"seq":1,"event":"x"}\n',
        b"\n",
    ],
)
def test_replay_rejects_partial_schema_and_blank_records(raw: bytes) -> None:
    with pytest.raises(AuditStorageError) as error:
        replay_bytes(raw, key=TEST_KEY)
    assert error.value.code is AuditFailureCode.INVALID_SCHEMA


def test_replay_rejects_unterminated_tail() -> None:
    record, _ = encode_v2_record(
        {"event": "one"}, key=TEST_KEY, seq=1, prev=GENESIS, ts=1
    )
    with pytest.raises(AuditStorageError) as error:
        replay_bytes(record.rstrip(b"\n"), key=TEST_KEY)
    assert error.value.code is AuditFailureCode.UNTERMINATED_RECORD


def test_v2_encoding_is_domain_separated_and_unicode_canonical() -> None:
    record, result = encode_v2_record(
        {"event": "café"}, key=TEST_KEY, seq=1, prev=GENESIS, ts=1.25
    )
    assert b"caf\xc3\xa9" in record
    decoded = json.loads(record)
    assert decoded["audit_version"] == 2
    assert decoded["hmac"] == result.hmac
    assert replay_bytes(record, key=TEST_KEY).state is LogState.VALID_V2


def test_locked_append_replays_then_writes_v2(tmp_path) -> None:
    path = tmp_path / "audit.ndjson"
    legacy, legacy_tip = signed_v1({"event": "legacy"}, seq=1)
    path.write_bytes(legacy)
    path.chmod(0o600)
    audit = AuditStorage(
        path, key=TEST_KEY, chained=True, anchor_path=None
    )
    with audit.locked_operation() as held:
        before = audit.replay_locked(held)
        appended = audit.append_v2_locked(
            held, before, {"event": "current"}, ts=2
        )
    result = replay_bytes(path.read_bytes(), key=TEST_KEY)
    assert result.state is LogState.VALID_V1_V2
    assert appended.seq == 2
    assert appended.hmac != legacy_tip
    assert result.tip == appended.hmac


def test_append_refuses_reserved_fields_and_unchained_mode(tmp_path) -> None:
    path = tmp_path / "audit.ndjson"
    audit = AuditStorage(
        path, key=TEST_KEY, chained=True, anchor_path=None
    )
    with audit.locked_operation() as held:
        replay = audit.replay_locked(held)
        with pytest.raises(AuditStorageError) as reserved:
            audit.append_v2_locked(
                held, replay, {"event": "x", "seq": 99}, ts=1
            )
    assert reserved.value.code is AuditFailureCode.INVALID_SCHEMA

    unchained = AuditStorage(
        path, key=TEST_KEY, chained=False, anchor_path=None
    )
    with unchained.locked_operation() as held:
        replay = unchained.replay_locked(held)
        with pytest.raises(AuditStorageError) as disabled:
            unchained.append_v2_locked(
                held, replay, {"event": "x"}, ts=1
            )
    assert disabled.value.code is AuditFailureCode.WRITE_DISABLED


def test_locked_replay_refuses_corrupted_history_before_append(tmp_path) -> None:
    path = tmp_path / "audit.ndjson"
    record, _ = encode_v2_record(
        {"event": "one"}, key=TEST_KEY, seq=1, prev=GENESIS, ts=1
    )
    path.write_bytes(replace_json_field(record, "hmac", "0" * 64))
    path.chmod(0o600)
    audit = AuditStorage(
        path, key=TEST_KEY, chained=True, anchor_path=None
    )
    with audit.locked_operation() as held:
        with pytest.raises(AuditStorageError) as error:
            audit.replay_locked(held)
    assert error.value.code is AuditFailureCode.INVALID_HMAC
    assert path.read_bytes().count(b"\n") == 1
