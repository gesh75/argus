"""Recon Agent — network discovery proposals driven by EvidenceGraph.

Proposes only. Every action still goes through Guardrail.authorize().
"""
from __future__ import annotations
from typing import Any
from .base import BaseAgent
from ..evidence import Observation


class ReconAgent(BaseAgent):
    name = "recon"

    def propose(self) -> list[dict[str, Any]]:
        # Simple evidence-driven example: if we have no network observations yet, propose discovery
        has_network = any(
            data.get("kind") == "network"
            for _, data in self.graph.g.nodes(data=True)
        )
        if not has_network:
            return [{
                "tool": "nmap",
                "args": ["-sn"],
                "targets": [],  # filled by caller from policy scope
                "reason": "no network observations yet",
            }]
        return []
