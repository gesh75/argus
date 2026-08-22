"""Out-of-band HMAC signer (issue #4)."""
from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from aegis.audit_storage import encode_v2_record, replay_bytes
from aegis.signer import (
    MAX_MATERIAL,
    InProcessSigner,
    SignerError,
    UnixSocketSigner,
    serve_forever,
)

KEY = b"k" * 32
MATERIAL = b"ARGUS-AUDIT-V2\0test-body"


def test_in_process_signer_is_stable() -> None:
    a = InProcessSigner(KEY)
    b = InProcessSigner(KEY)
    assert a.hmac_sha256(MATERIAL) == b.hmac_sha256(MATERIAL)
    assert len(a.hmac_sha256(MATERIAL)) == 64


def test_in_process_signer_rejects_short_key() -> None:
    with pytest.raises(SignerError, match="too short"):
        InProcessSigner(b"short")


def test_in_process_signer_rejects_oversized_material() -> None:
    s = InProcessSigner(KEY)
    with pytest.raises(SignerError, match="protocol"):
        s.hmac_sha256(b"x" * (MAX_MATERIAL + 1))


def test_unix_socket_signer_never_requires_key_in_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sock = str(tmp_path / "signer.sock")
    monkeypatch.delenv("PENTEST_AUDIT_HMAC_KEY", raising=False)
    thread = threading.Thread(target=serve_forever, args=(sock, KEY), daemon=True)
    thread.start()
    for _ in range(50):
        if Path(sock).exists():
            break
        thread.join(0.02)
    client = UnixSocketSigner(sock)
    client.ping()
    digest = client.hmac_sha256(MATERIAL)
    assert digest == InProcessSigner(KEY).hmac_sha256(MATERIAL)
    assert os.environ.get("PENTEST_AUDIT_HMAC_KEY") is None


def test_encode_and_replay_via_socket_signer(tmp_path: Path) -> None:
    sock = str(tmp_path / "signer.sock")
    thread = threading.Thread(target=serve_forever, args=(sock, KEY), daemon=True)
    thread.start()
    for _ in range(50):
        if Path(sock).exists():
            break
        thread.join(0.02)
    signer = UnixSocketSigner(sock)
    raw, result = encode_v2_record(
        {"event": "authorize", "tool": "nmap"},
        signer=signer,
        seq=1,
        prev="genesis",
        ts=1.0,
    )
    replay = replay_bytes(raw, signer=signer)
    assert replay.count == 1
    assert replay.tip == result.hmac


def test_socket_signer_fail_closed_when_missing(tmp_path: Path) -> None:
    client = UnixSocketSigner(str(tmp_path / "no-such.sock"))
    with pytest.raises(SignerError, match="unavailable"):
        client.ping()


def test_client_rejects_oversized_hmac_request(tmp_path: Path) -> None:
    sock = str(tmp_path / "signer.sock")
    thread = threading.Thread(target=serve_forever, args=(sock, KEY), daemon=True)
    thread.start()
    for _ in range(50):
        if Path(sock).exists():
            break
        thread.join(0.02)
    client = UnixSocketSigner(sock)
    with pytest.raises(SignerError, match="protocol"):
        client.hmac_sha256(b"x" * (MAX_MATERIAL + 1))
