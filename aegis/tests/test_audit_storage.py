from __future__ import annotations

import hashlib
import hmac
import json
import math
from pathlib import Path

import pytest

from aegis.audit_storage import (
    GENESIS,
    V2_DOMAIN_SEPARATOR,
    AuditFailureCode,
    AuditStorage,
    AuditStorageError,
    LogState,
    canonical_v2_body,
    decode_v2_record,
    encode_v2_record,
    replay_bytes,
    strict_json_object,
)
from aegis.config import DEFAULT_POLICY, Policy
from aegis.guardrail import AuditLog
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


@pytest.mark.parametrize("raw", [b"[]", b'"text"', b"1", b"null"])
def test_non_object_json_values_are_rejected(raw: bytes) -> None:
    with pytest.raises(AuditStorageError) as error:
        strict_json_object(raw, record_number=1)
    assert error.value.code is AuditFailureCode.NON_OBJECT_JSON


@pytest.mark.parametrize("token", [b"NaN", b"Infinity", b"-Infinity"])
def test_nonfinite_json_constants_are_rejected(token: bytes) -> None:
    with pytest.raises(AuditStorageError) as error:
        strict_json_object(
            b'{"event":' + token + b"}", record_number=1
        )
    assert error.value.code is AuditFailureCode.MALFORMED_JSON


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


def test_malformed_json_in_middle_rejected() -> None:
    first, append = encode_v2_record(
        {"event": "one"}, key=TEST_KEY, seq=1, prev=GENESIS, ts=1
    )
    third, _ = encode_v2_record(
        {"event": "three"}, key=TEST_KEY, seq=3, prev=append.hmac, ts=3
    )
    with pytest.raises(AuditStorageError) as error:
        replay_bytes(first + b"{broken\n" + third, key=TEST_KEY)
    assert error.value.code is AuditFailureCode.MALFORMED_JSON
    assert error.value.record_number == 2


def test_malformed_json_final_record_rejected() -> None:
    first, _ = encode_v2_record(
        {"event": "one"}, key=TEST_KEY, seq=1, prev=GENESIS, ts=1
    )
    with pytest.raises(AuditStorageError) as error:
        replay_bytes(first + b"{broken\n", key=TEST_KEY)
    assert error.value.code is AuditFailureCode.MALFORMED_JSON
    assert error.value.record_number == 2


def test_missing_hmac_rejected() -> None:
    record, _ = encode_v2_record(
        {"event": "one"}, key=TEST_KEY, seq=1, prev=GENESIS, ts=1
    )
    data = json.loads(record)
    del data["hmac"]
    with pytest.raises(AuditStorageError) as error:
        replay_bytes(json.dumps(data).encode() + b"\n", key=TEST_KEY)
    assert error.value.code is AuditFailureCode.INVALID_SCHEMA


def test_altered_event_rejected() -> None:
    record, _ = encode_v2_record(
        {"event": "one"}, key=TEST_KEY, seq=1, prev=GENESIS, ts=1
    )
    with pytest.raises(AuditStorageError) as error:
        replay_bytes(
            replace_json_field(record, "event", "altered"), key=TEST_KEY
        )
    assert error.value.code is AuditFailureCode.INVALID_HMAC


def test_reordered_records_rejected() -> None:
    first, append = encode_v2_record(
        {"event": "one"}, key=TEST_KEY, seq=1, prev=GENESIS, ts=1
    )
    second, _ = encode_v2_record(
        {"event": "two"}, key=TEST_KEY, seq=2, prev=append.hmac, ts=2
    )
    with pytest.raises(AuditStorageError) as error:
        replay_bytes(second + first, key=TEST_KEY)
    assert error.value.code is AuditFailureCode.INVALID_SEQUENCE


@pytest.mark.parametrize(
    ("sequences", "expected"),
    [
        ((1, 1), AuditFailureCode.INVALID_SEQUENCE),
        ((1, 3), AuditFailureCode.INVALID_SEQUENCE),
        ((2, 1), AuditFailureCode.INVALID_SEQUENCE),
    ],
)
def test_sequence_corruption_is_rejected(
    sequences: tuple[int, int], expected: AuditFailureCode
) -> None:
    first, append = encode_v2_record(
        {"event": "one"},
        key=TEST_KEY,
        seq=sequences[0],
        prev=GENESIS,
        ts=1,
    )
    second, _ = encode_v2_record(
        {"event": "two"},
        key=TEST_KEY,
        seq=sequences[1],
        prev=append.hmac,
        ts=2,
    )
    with pytest.raises(AuditStorageError) as error:
        replay_bytes(first + second, key=TEST_KEY)
    assert error.value.code is expected


@pytest.mark.parametrize("bad_hmac", ["a" * 63, "A" * 64, "z" * 64, 7])
def test_invalid_hmac_encodings_are_rejected(bad_hmac: object) -> None:
    record, _ = encode_v2_record(
        {"event": "one"}, key=TEST_KEY, seq=1, prev=GENESIS, ts=1
    )
    with pytest.raises(AuditStorageError) as error:
        replay_bytes(
            replace_json_field(record, "hmac", bad_hmac), key=TEST_KEY
        )
    assert error.value.code is AuditFailureCode.INVALID_HMAC


def test_nonfinite_timestamp_is_rejected() -> None:
    data = {
        "audit_version": 2,
        "seq": 1,
        "ts": math.inf,
        "prev": GENESIS,
        "event": "one",
        "hmac": "a" * 64,
    }
    with pytest.raises(AuditStorageError) as error:
        decode_v2_record(data, expected_seq=1)
    assert error.value.code is AuditFailureCode.INVALID_TIMESTAMP


def test_v2_signed_bytes_are_independently_reproducible() -> None:
    encoded, result = encode_v2_record(
        {"event": "café"}, key=TEST_KEY, seq=1, prev=GENESIS, ts=1.25
    )
    data = json.loads(encoded)
    stored = data.pop("hmac")
    independent = hmac.new(
        TEST_KEY,
        V2_DOMAIN_SEPARATOR + canonical_v2_body(data),
        hashlib.sha256,
    ).hexdigest()
    assert stored == result.hmac == independent


def test_sensitive_values_never_appear_in_errors() -> None:
    sensitive_value = "operator-token-should-never-leak"
    raw = json.dumps({"event": sensitive_value}).encode() + b"\n"
    with pytest.raises(AuditStorageError) as error:
        replay_bytes(raw, key=TEST_KEY)
    assert str(error.value) == "invalid-schema at record 1"
    assert sensitive_value not in str(error.value)


def _audit_policy(tmp_path: Path, monkeypatch) -> Policy:
    monkeypatch.setenv("PENTEST_AUDIT_HMAC_KEY", "k" * 32)
    policy = Policy.load(DEFAULT_POLICY)
    object.__setattr__(policy, "audit_path", tmp_path / "audit.ndjson")
    object.__setattr__(policy, "audit_anchor_path", tmp_path / "anchor.json")
    return policy


def test_write_returns_committed_hmac(tmp_path: Path, monkeypatch) -> None:
    result = AuditLog(_audit_policy(tmp_path, monkeypatch)).write(
        {"event": "one"}
    )
    assert len(result) == 64
    assert all(character in "0123456789abcdef" for character in result)


def test_verify_returns_boolean(tmp_path: Path, monkeypatch) -> None:
    log = AuditLog(_audit_policy(tmp_path, monkeypatch))
    log.write({"event": "one"})
    assert log.verify() is True
    log._path.write_bytes(b"{broken\n")
    assert log.verify() is False


def test_cross_check_anchor_retains_tuple_shape(
    tmp_path: Path, monkeypatch
) -> None:
    log = AuditLog(_audit_policy(tmp_path, monkeypatch))
    log.write({"event": "one"})
    result = log.cross_check_anchor()
    assert isinstance(result, tuple)
    assert len(result) == 2
    assert result[0] is True
    assert isinstance(result[1], str)
