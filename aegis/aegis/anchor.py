"""External anchoring of the audit-chain tip (#5).

In-file HMAC chaining proves tamper-evidence *only while the signing key is secret*.
If the key leaks, an attacker can rewrite the whole log and recompute every HMAC so it
re-verifies. Anchoring defends against that: the latest chain tip ``{seq, tip, ts}`` is
written to a SEPARATE file that production points at a write-once store the tool runner
cannot rewrite (S3 Object Lock compliance mode, a KMS-signed object, or a WORM volume
owned by a different uid). ``aegis audit`` then cross-checks the live chain against the
anchor, so a full-log rewrite is still detectable unless the attacker also forges the
out-of-band anchor — which the runner has no path to.

Best practice: "HMAC alone does not defend against a compromised app — layer append-only
storage and external anchoring on top" (Tracehold; CloudTrail log-file validation).

This module owns only the small, infra-agnostic anchor file format. The production WORM
target is an operational choice (point ``audit.anchor_path`` at the mounted WORM path).
"""
from __future__ import annotations

import json
from pathlib import Path


def write_anchor(path: Path, seq: int, tip: str, ts: float) -> None:
    """Overwrite the anchor with the current chain tip. One small JSON object, no chaining
    (the anchor's protection comes from living on a write-once medium, not from a MAC)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"seq": seq, "tip": tip, "ts": round(ts, 3)},
                               separators=(",", ":")) + "\n")


def read_anchor(path: Path) -> dict | None:
    """Return the anchor record, or None if absent/unreadable."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
