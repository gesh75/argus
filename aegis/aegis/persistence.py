"""Simple JSON persistence for EvidenceGraph between continuous runs."""
from __future__ import annotations
import json
from pathlib import Path
from .evidence import EvidenceGraph, Observation
from datetime import datetime


def save_graph(graph: EvidenceGraph, path: Path) -> None:
    data = {
        "nodes": [
            {"id": n, **{k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in d.items()}}
            for n, d in graph.g.nodes(data=True)
        ],
        "edges": [{"source": u, "target": v, **d} for u, v, d in graph.g.edges(data=True)],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str))


def load_graph(path: Path) -> EvidenceGraph:
    from .evidence import EvidenceGraph
    g = EvidenceGraph()
    if not path.exists():
        return g
    data = json.loads(path.read_text())
    for node in data.get("nodes", []):
        nid = node.pop("id")
        g.g.add_node(nid, **node)
    for edge in data.get("edges", []):
        g.g.add_edge(edge["source"], edge["target"], **{k: v for k, v in edge.items() if k not in ("source", "target")})
    return g
