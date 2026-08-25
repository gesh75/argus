"""AD / Identity Agent — LDAP and identity path proposals (read-only).

Idempotent: stops once ad-kind evidence exists for the operator target.
"""
from __future__ import annotations

from typing import Any

from .base import BaseAgent


class ADAgent(BaseAgent):
    name = "ad"

    def propose(self) -> list[dict[str, Any]]:
        targets = [t for t in self.default_targets if "ad" not in self.kinds_for(t)]
        if not targets:
            return []
        blob = self.blob()
        if not any(s in blob for s in ("389/tcp", "636/tcp", "445/tcp", "ldap", "smb", "ad")):
            return []
        t = targets[0]
        return [{
            "tool": "ldapsearch",
            "args": ["-x", "-H", f"ldap://{t}", "-s", "base", "namingContexts"],
            "targets": [t],
            "reason": "directory/SMB surface observed",
        }]
