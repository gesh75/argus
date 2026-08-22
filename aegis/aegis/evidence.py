"""Evidence Graph — shared knowledge plane for all agents.

Every Observation is a node. Attack paths are edges.
Proof tags (observed | theoretical) are mandatory.
Path identifiers are deterministic so persistence and delta stay stable.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

try:
    import networkx as nx
except ImportError:  # optional at scaffold time
    nx = None  # type: ignore

Proof = Literal["observed", "theoretical"]
Kind = Literal[
    "network", "host", "ad", "web", "exposure",
    "segmentation", "ai-service", "path"
]


@dataclass(frozen=True)
class Observation:
    id: str
    kind: Kind
    target: str
    summary: str
    evidence: dict[str, Any]
    proof: Proof
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    parent_ids: tuple[str, ...] = ()
    agent: str = "unknown"


class EvidenceGraph:
    def __init__(self) -> None:
        if nx is None:
            raise ImportError("networkx is required for EvidenceGraph")
        self.g = nx.DiGraph()
        self.closed: set[str] = set()

    def add(self, obs: Observation) -> None:
        self.g.add_node(obs.id, **obs.__dict__)
        self.closed.discard(obs.id)
        for parent in obs.parent_ids:
            if parent in self.g:
                self.g.add_edge(parent, obs.id, proof=obs.proof)

    def add_path(self, nodes: list[str], proof: Proof, reason: str) -> str:
        material = json.dumps(
            {"nodes": sorted(nodes), "proof": proof, "reason": reason},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        path_id = "path-" + hashlib.sha256(material).hexdigest()[:12]
        if path_id not in self.g:
            self.g.add_node(path_id, kind="path", proof=proof, reason=reason)
            for n in nodes:
                if n in self.g:
                    self.g.add_edge(n, path_id, proof=proof)
        self.closed.discard(path_id)
        return path_id

    def close_node(self, node_id: str) -> bool:
        """Mark a node remediated/closed. Used by the delta lifecycle."""
        if node_id not in self.g:
            return False
        self.g.remove_node(node_id)
        self.closed.add(node_id)
        return True

    def observed_paths(self) -> list[dict]:
        return [
            data for _, data in self.g.nodes(data=True)
            if data.get("kind") == "path" and data.get("proof") == "observed"
        ]

    def summary_for_llm(self) -> str:
        """Compact, redacted summary safe to send to any model."""
        lines = []
        for nid, data in self.g.nodes(data=True):
            if data.get("kind") != "path":
                lines.append(f"[{data.get('proof')}] {data.get('kind')}: {data.get('summary')}")
        return "\n".join(lines)
