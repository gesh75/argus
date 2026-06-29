"""Parameter-bound, fail-closed approval tokens for high-risk run modes (#6).

A token authorizes a specific SET of modes (e.g. ``local`` and/or ``arm``) against an
EXACT set of targets until a hard expiry. It is an HMAC over
``(canonical-modes, canonical-sorted-targets, expiry)`` keyed by the audit signing key, so:

  * only an operator who holds the key can mint one (the LLM/agent never can),
  * it cannot be replayed against different targets, and
  * it stops working after it expires.

Best practice: bind approval to the exact action and fail closed — telling the model
"stay in scope" is not enforcement (OWASP AI Agent Security Cheat Sheet; ROE Gate).
Wildcard / open-ended grants are intentionally impossible: every token names its
targets and carries a TTL.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import time

from .guardrail import canon_network


class ApprovalError(Exception):
    """Raised when an approval token is missing, malformed, expired, or mismatched."""


def _norm_modes(modes: str | list[str]) -> list[str]:
    return [modes] if isinstance(modes, str) else list(modes)


def _canon_modes(modes: str | list[str]) -> str:
    """Canonical mode string: deduped + sorted so {arm,local} == {local,arm}."""
    return "+".join(sorted(set(_norm_modes(modes))))


def _canon_targets(targets: list[str]) -> str:
    """Normalize targets to canonical networks, deduped + sorted, so the token binds to
    the same set regardless of ordering or obfuscation (decimal/hex/leading-zero)."""
    nets = sorted({str(canon_network(t)) for t in targets})
    return ",".join(nets)


def _body(modes: str | list[str], targets: list[str], expiry: int) -> str:
    return f"v1|{_canon_modes(modes)}|{_canon_targets(targets)}|{expiry}"


def mint(modes: str | list[str], targets: list[str], key: str, *, ttl: int = 3600,
         now: float | None = None) -> str:
    """Mint a base64 token authorizing `modes` against `targets` for `ttl` seconds."""
    if ttl <= 0:
        raise ApprovalError("ttl must be positive")
    expiry = int((time.time() if now is None else now) + ttl)
    mac = hmac.new(key.encode(), _body(modes, targets, expiry).encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{expiry}.{mac}".encode()).decode()


def verify(token: str, modes: str | list[str], targets: list[str], key: str,
           *, now: float | None = None) -> None:
    """Raise ApprovalError unless `token` authorizes exactly `modes`+`targets` and is unexpired."""
    if not token:
        raise ApprovalError(
            f"{_canon_modes(modes)} mode requires an approval token (mint one with `aegis approve`)")
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        expiry_s, mac = raw.split(".", 1)
        expiry = int(expiry_s)
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise ApprovalError("malformed approval token") from exc
    now = time.time() if now is None else now
    if now > expiry:
        raise ApprovalError("approval token expired — mint a fresh one")
    expect = hmac.new(key.encode(), _body(modes, targets, expiry).encode(), hashlib.sha256).hexdigest()
    # compare_digest over the full token guards target/mode tampering AND a forged MAC.
    if not hmac.compare_digest(mac, expect):
        raise ApprovalError("approval token does not authorize this mode/target set")
