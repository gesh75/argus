"""Out-of-band HMAC signer (GitHub issue #4).

When ARGUS_SIGNER_SOCKET is set, the orchestrator never loads the audit key.
The signer process is the only process that reads PENTEST_AUDIT_HMAC_KEY.
Signer unavailability is fail-closed — audit-dependent actions are refused.

Hardening on top of the socket split:
- Linux SO_PEERCRED: refuse connections from a different uid.
- Bounded JSON-line messages and HMAC material.
- Socket mode 0600. Protocol errors are redacted.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import stat
import struct
from pathlib import Path
from typing import Protocol

MIN_AUDIT_KEY_LEN = 32
MAX_MSG = 65_536
MAX_MATERIAL = 32_768
SIGNER_SOCKET_ENV = "ARGUS_SIGNER_SOCKET"
SIGNER_SOCKET_NAME = "argus-signer.sock"
_HEX = set("0123456789abcdef")
_SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)


def default_socket_path() -> str | None:
    """Resolve a user-private signer socket path.

    World-writable shared temp directories are never an implicit default
    (CWE-377). Operators may still pass an explicit ``--socket`` path.
    Preference: ``ARGUS_SIGNER_SOCKET``, then a user-owned, unshared
    ``$XDG_RUNTIME_DIR`` / ``argus-signer.sock``.
    """
    explicit = os.environ.get(SIGNER_SOCKET_ENV, "").strip()
    if explicit:
        return explicit
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR", "").strip()
    if runtime_dir and _is_private_runtime_dir(Path(runtime_dir)):
        return str(Path(runtime_dir) / SIGNER_SOCKET_NAME)
    return None


def _is_private_runtime_dir(path: Path) -> bool:
    """XDG runtime dirs must be user-owned and inaccessible to group/other."""
    try:
        st = path.stat()
    except OSError:
        return False
    if not stat.S_ISDIR(st.st_mode):
        return False
    if st.st_uid != os.getuid():
        return False
    return (st.st_mode & 0o077) == 0


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
        if len(material) > MAX_MATERIAL:
            raise SignerError("signer protocol error")
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
        if len(material) > MAX_MATERIAL:
            raise SignerError("signer protocol error")
        data = self._roundtrip({"op": "hmac", "material_hex": material.hex()})
        digest = data.get("hmac")
        if not isinstance(digest, str) or len(digest) != 64 or set(digest) - _HEX:
            raise SignerError("signer protocol error")
        return digest

    def _roundtrip(self, payload: dict[str, str]) -> dict[str, object]:
        raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        if len(raw) > MAX_MSG:
            raise SignerError("signer protocol error")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)
        try:
            sock.connect(self._path)
            sock.sendall(raw)
            line = _recv_line(sock)
        except OSError as exc:
            raise SignerError("signer unavailable") from exc
        finally:
            sock.close()
        try:
            data = json.loads(line.decode("utf-8"))
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
            if not _same_uid(conn):
                _send_refuse(conn)
                continue
            _handle_conn(conn, signer)
        finally:
            conn.close()


def _same_uid(conn: socket.socket) -> bool:
    """Linux SO_PEERCRED. If the platform cannot attest, socket mode is the control."""
    uid = _peer_uid(conn)
    if uid is None:
        return True
    return uid == os.getuid()


def _peer_uid(conn: socket.socket) -> int | None:
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", raw)
        return int(uid)
    except (OSError, struct.error, OverflowError, TypeError):
        return None


def _recv_line(sock: socket.socket, limit: int = MAX_MSG) -> bytes:
    buf = b""
    while b"\n" not in buf:
        if len(buf) >= limit:
            raise SignerError("signer protocol error")
        chunk = sock.recv(min(4096, limit - len(buf)))
        if not chunk:
            break
        buf += chunk
    return buf.split(b"\n", 1)[0]


def _send_refuse(conn: socket.socket) -> None:
    try:
        conn.sendall(b'{"ok":false,"error":"unavailable"}\n')
    except OSError:
        return


def _handle_conn(conn: socket.socket, signer: InProcessSigner) -> None:
    conn.settimeout(2.0)
    try:
        line = _recv_line(conn)
        req = json.loads(line.decode("utf-8"))
        if not isinstance(req, dict):
            raise ValueError
        op = req.get("op")
        if op == "ping":
            conn.sendall(b'{"ok":true}\n')
            return
        if op == "hmac":
            material_hex = req.get("material_hex")
            if not isinstance(material_hex, str) or len(material_hex) > MAX_MATERIAL * 2:
                raise ValueError
            material = bytes.fromhex(material_hex)
            if len(material) > MAX_MATERIAL:
                raise ValueError
            digest = signer.hmac_sha256(material)
            body = json.dumps({"ok": True, "hmac": digest}, separators=(",", ":"))
            conn.sendall(body.encode("utf-8") + b"\n")
            return
        raise ValueError
    except Exception:  # noqa: BLE001 — protocol errors are redacted
        _send_refuse(conn)
