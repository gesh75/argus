"""Recon Agent — network discovery proposals driven by EvidenceGraph.

Proposes only. Every action still goes through Guardrail.authorize().
Idempotent: once any network observation exists, recon does not re-propose.
"""
from __future__ import annotations

from typing import Any

from .base import BaseAgent


class ReconAgent(BaseAgent):
    name = "recon"

    def propose(self) -> list[dict[str, Any]]:
        targets = list(self.default_targets)
        if not targets:
            return []
        if "network" in self.kinds_for():
            return []
        return [{
            "tool": "nmap",
            "args": ["-sn", *targets],
            "targets": targets,
            "reason": "no network observations yet",
        }]
