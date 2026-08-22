"""Out-of-band HMAC signer (GitHub issue #4).

When ARGUS_SIGNER_SOCKET is set, the orchestrator never loads the audit key.
The signer process is the only process that reads PENTEST_AUDIT_HMAC_KEY.
Signer unavailability is fail-closed — audit-dependent actions are refused.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import stat
from pathlib import Path
from typing import Protocol

MIN_AUDIT_KEY_LEN = 32
_HEX = set("0123456789abcdef")


class SignerError(Exception):
    """Redacted signer failure. Never includes key material."""


class Signer(Protocol):
    def hmac_sha256(self, material: bytes) -> str: ...


class InProcessSigner:
    """Compatibility signer for tests and unsupervised local labs.

    This still holds the key in-process. Production-shaped deployments should
    use UnixSocketSigner so the orchestrator never sees the key.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) < MIN_AUDIT_KEY_LEN:
            raise SignerError("audit key too short")
        self._key = key

    def hmac_sha256(self, material: bytes) -> str:
        return hmac.new(self._key, material, hashlib.sha256).hexdigest()


class UnixSocketSigner:
    """Client that asks a separately started signer process for HMACs."""

    def __init__(self, path: str, *, timeout: float = 2.0) -> None:
        if not path:
            raise SignerError("signer socket path empty")
        self._path = path
        self._timeout = timeout

    def ping(self) -> None:
        self._roundtrip({"op": "ping"})

    def hmac_sha256(self, material: bytes) -> str:
        data = self._roundtrip({"op": "hmac", "material_hex": material.hex()})
        digest = data.get("hmac")
        if not isinstance(digest, str) or len(digest) != 64 or set(digest) - _HEX:
            raise SignerError("signer protocol error")
        return digest

    def _roundtrip(self, payload: dict[str, str]) -> dict[str, object]:
        raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)
        try:
            sock.connect(self._path)
            sock.sendall(raw)
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except OSError as exc:
            raise SignerError("signer unavailable") from exc
        finally:
            sock.close()
        try:
            data = json.loads(buf.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SignerError("signer protocol error") from exc
        if not isinstance(data, dict) or data.get("ok") is not True:
            raise SignerError("signer refused")
        return data


def serve_forever(socket_path: str, key: bytes) -> None:
    """Run the signer daemon. Caller must already hold `key`; never log it."""
    if len(key) < MIN_AUDIT_KEY_LEN:
        raise SignerError("audit key too short")
    path = Path(socket_path)
    if path.exists():
        path.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    os.chmod(str(path), stat.S_IRUSR | stat.S_IWUSR)
    server.listen(8)
    signer = InProcessSigner(key)
    while True:
        conn, _ = server.accept()
        try:
            _handle_conn(conn, signer)
        finally:
            conn.close()


def _handle_conn(conn: socket.socket, signer: InProcessSigner) -> None:
    conn.settimeout(2.0)
    try:
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
        line = buf.split(b"\n", 1)[0]
        req = json.loads(line.decode("utf-8"))
        if not isinstance(req, dict):
            raise ValueError
        op = req.get("op")
        if op == "ping":
            conn.sendall(b'{"ok":true}\n')
            return
        if op == "hmac":
            material_hex = req.get("material_hex")
            if not isinstance(material_hex, str):
                raise ValueError
            material = bytes.fromhex(material_hex)
            digest = signer.hmac_sha256(material)
            body = json.dumps({"ok": True, "hmac": digest}, separators=(",", ":"))
            conn.sendall(body.encode("utf-8") + b"\n")
            return
        raise ValueError
    except Exception:  # noqa: BLE001 — protocol errors are redacted
        try:
            conn.sendall(b'{"ok":false,"error":"unavailable"}\n')
        except OSError:
            return
