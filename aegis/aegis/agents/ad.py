"""AD / Identity Agent — LDAP and identity path proposals (read-only).
"""
from __future__ import annotations

from typing import Any

from .base import BaseAgent


class ADAgent(BaseAgent):
    name = "ad"

    def propose(self) -> list[dict[str, Any]]:
        targets = list(self.default_targets)
        if not targets:
            return []
        blob = " ".join(
            f"{d.get('kind', '')} {d.get('summary', '')}"
            for _, d in self.graph.g.nodes(data=True)
        ).lower()
        if any(s in blob for s in ("389/tcp", "636/tcp", "445/tcp", "ldap", "smb", "ad")):
            t = targets[0]
            return [{
                "tool": "ldapsearch",
                "args": ["-x", "-H", f"ldap://{t}", "-s", "base", "namingContexts"],
                "targets": [t],
                "reason": "directory/SMB surface observed",
            }]
        return []
