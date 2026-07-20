"""CorrelationAgent — builds multi-step attack paths from the EvidenceGraph.

Still fully under the Guardrail. Only reasons over existing evidence.
"""
from __future__ import annotations
from typing import Any
from .base import BaseAgent
from ..evidence import Observation, Proof


class CorrelationAgent(BaseAgent):
    name = "correlation"

    def propose(self) -> list[dict[str, Any]]:
        # Correlation does not propose new collectors; it only reasons.
        return []

    def derive_paths(self) -> list[dict[str, Any]]:
        """Walk the graph and emit high-value multi-step paths."""
        paths = []
        nodes = list(self.graph.g.nodes(data=True))

        # Simple example rules (expand in later phases)
        exposures = [n for n, d in nodes if d.get("kind") == "exposure"]
        hosts = [n for n, d in nodes if d.get("kind") in ("host", "network")]
        ads = [n for n, d in nodes if d.get("kind") == "ad"]

        if exposures and hosts:
            path_id = self.graph.add_path(
                exposures + hosts,
                proof="theoretical",
                reason="Web/credential exposure reachable to host services",
            )
            paths.append({"id": path_id, "proof": "theoretical", "name": "Exposure -> Host foothold"})

        if hosts and ads:
            path_id = self.graph.add_path(
                hosts + ads,
                proof="theoretical",
                reason="Host foothold + AD surface enables lateral movement",
            )
            paths.append({"id": path_id, "proof": "theoretical", "name": "Host -> AD pivot"})

        return paths
