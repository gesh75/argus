"""DeltaAgent — continuous change detection over the EvidenceGraph."""
from __future__ import annotations
from typing import Any
from .base import BaseAgent


class DeltaAgent(BaseAgent):
    name = "delta"

    def __init__(self, guardrail, graph, previous_nodes: set[str] | None = None):
        super().__init__(guardrail, graph)
        self.previous_nodes = previous_nodes or set()

    def propose(self) -> list[dict[str, Any]]:
        return []  # does not propose collectors

    def compute_delta(self) -> dict[str, Any]:
        current = set(self.graph.g.nodes)
        new = current - self.previous_nodes
        closed = self.previous_nodes - current
        self.previous_nodes = current
        return {
            "new_nodes": list(new),
            "closed_nodes": list(closed),
            "new_paths": [n for n in new if str(n).startswith("path-")],
            "summary": f"+{len(new)} / -{len(closed)} nodes",
        }
