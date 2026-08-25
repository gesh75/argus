"""Host Agent — Linux/Windows credentialed audit proposals.

Idempotent: proposes a follow-up only when SSH/host surface is observed and
no host-kind evidence exists yet. Does not re-run recon nmap in a loop.
"""
from __future__ import annotations

from typing import Any

from .base import BaseAgent


class HostAgent(BaseAgent):
    name = "host"

    def propose(self) -> list[dict[str, Any]]:
        targets = [t for t in self.default_targets if "host" not in self.kinds_for(t)]
        if not targets:
            return []
        blob = self.blob()
        if not ("22/tcp" in blob or "ssh" in blob):
            return []
        return [{
            "tool": "nmap",
            "args": ["-sV", "-p", "22", *targets],
            "targets": targets,
            "reason": "SSH/host surface observed — host agent follow-up",
        }]
