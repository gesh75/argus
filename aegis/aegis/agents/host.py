"""Host Agent — Linux/Windows credentialed audit proposals.
"""
from __future__ import annotations

from typing import Any

from .base import BaseAgent


class HostAgent(BaseAgent):
    name = "host"

    def propose(self) -> list[dict[str, Any]]:
        targets = list(self.default_targets)
        if not targets:
            return []
        blob = " ".join(
            f"{d.get('kind', '')} {d.get('summary', '')}"
            for _, d in self.graph.g.nodes(data=True)
        ).lower()
        if "22/tcp" in blob or "ssh" in blob or "host" in blob:
            return [{
                "tool": "nmap",
                "args": ["-sV", "-p", "22", *targets],
                "targets": targets,
                "reason": "SSH/host surface observed",
            }]
        return []
