"""DeltaAgent — continuous change detection over the EvidenceGraph.

Closed-path lifecycle: nodes that leave the graph (operator-closed or
remediated) are recorded, not just new ones.
"""
from __future__ import annotations

from typing import Any

from .base import BaseAgent


class DeltaAgent(BaseAgent):
    name = "delta"

    def __init__(self, guardrail, graph, previous_nodes: set[str] | None = None):
        super().__init__(guardrail, graph)
        self.previous_nodes = previous_nodes if previous_nodes is not None else set(graph.g.nodes)

    def propose(self) -> list[dict[str, Any]]:
        return []  # does not propose collectors

    def compute_delta(self) -> dict[str, Any]:
        current = set(self.graph.g.nodes)
        new = current - self.previous_nodes
        closed = self.previous_nodes - current
        self.graph.closed.update(closed)
        self.previous_nodes = current
        closed_paths = [n for n in closed if str(n).startswith("path-")]
        new_paths = [
            n for n in new
            if str(n).startswith("path-") or self.graph.g.nodes[n].get("kind") == "path"
        ]
        return {
            "new_nodes": list(new),
            "closed_nodes": list(closed),
            "new_paths": new_paths,
            "closed_paths": closed_paths,
            "summary": f"+{len(new)} / -{len(closed)} nodes",
        }
