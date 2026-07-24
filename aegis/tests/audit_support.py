from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
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
