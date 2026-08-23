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


def test_default_socket_path_prefers_explicit_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aegis.signer import default_socket_path

    explicit = str(tmp_path / "explicit.sock")
    monkeypatch.setenv("ARGUS_SIGNER_SOCKET", explicit)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    assert default_socket_path() == explicit


def test_default_socket_path_uses_xdg_runtime_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aegis.signer import SIGNER_SOCKET_NAME, default_socket_path

    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    monkeypatch.delenv("ARGUS_SIGNER_SOCKET", raising=False)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    assert default_socket_path() == str(runtime / SIGNER_SOCKET_NAME)


def test_default_socket_path_rejects_shared_xdg_runtime_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aegis.signer import default_socket_path

    shared = tmp_path / "shared"
    shared.mkdir(mode=0o1777)
    shared.chmod(0o1777)
    monkeypatch.delenv("ARGUS_SIGNER_SOCKET", raising=False)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(shared))
    assert default_socket_path() is None


def test_default_socket_path_is_unset_without_private_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegis.signer import default_socket_path

    monkeypatch.delenv("ARGUS_SIGNER_SOCKET", raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    assert default_socket_path() is None


def test_signer_cli_refuses_missing_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from aegis.cli import main

    monkeypatch.delenv("ARGUS_SIGNER_SOCKET", raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    assert main(["--policy", str(tmp_path / "unused-policy.yml"), "signer"]) == 2
    assert "signer socket unset" in capsys.readouterr().err


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
