"""CorrelationAgent — builds multi-step attack paths from the EvidenceGraph.

Still fully under the Guardrail. Only reasons over existing evidence.
Paths are asset-bound: nodes must share a target before they combine.
"""
from __future__ import annotations

from typing import Any

from .base import BaseAgent


class CorrelationAgent(BaseAgent):
    name = "correlation"

    def propose(self) -> list[dict[str, Any]]:
        return []

    def derive_paths(self) -> list[dict[str, Any]]:
        """Walk the graph per-target and emit high-value multi-step paths."""
        paths: list[dict[str, Any]] = []
        by_target: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        for nid, data in self.graph.g.nodes(data=True):
            if data.get("kind") == "path":
                continue
            target = data.get("target")
            if not target:
                continue
            by_target.setdefault(str(target), []).append((nid, data))

        rules: list[tuple[set[str], str, str]] = [
            ({"exposure", "host"}, "Exposure -> Host foothold",
             "Web/credential exposure reachable to host services"),
            ({"host", "ad"}, "Host -> AD pivot",
             "Host foothold + AD surface enables lateral movement"),
            ({"web", "segmentation"}, "Web -> Segmentation breach",
             "Web surface reaches management/directory planes"),
            ({"exposure", "ad"}, "Exposure -> AD credential path",
             "Exposed secrets + AD surface = high-value credential attack path"),
        ]

        for target, nodes in by_target.items():
            kinds = {d.get("kind") for _, d in nodes}
            for need, name, reason in rules:
                if not need <= kinds:
                    continue
                members = [n for n, d in nodes if d.get("kind") in need]
                path_id = self.graph.add_path(
                    members, proof="theoretical", reason=f"{reason} ({target})"
                )
                paths.append({
                    "id": path_id,
                    "proof": "theoretical",
                    "name": name,
                    "target": target,
                })
        return paths
