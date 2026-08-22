"""Recon Agent — network discovery proposals driven by EvidenceGraph.

Proposes only. Every action still goes through Guardrail.authorize().
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
        has_network = any(
            data.get("kind") == "network"
            for _, data in self.graph.g.nodes(data=True)
        )
        if not has_network:
            return [{
                "tool": "nmap",
                "args": ["-sn", *targets],
                "targets": targets,
                "reason": "no network observations yet",
            }]
        return []
