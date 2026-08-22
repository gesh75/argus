"""JSON persistence for EvidenceGraph between continuous runs.

Writes are atomic (temp file + os.replace). This is still experimental V2
scaffolding — not a transactional, checksummed store.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from .evidence import EvidenceGraph

SCHEMA_VERSION = 1


def save_graph(graph: EvidenceGraph, path: Path) -> None:
    data = {
        "schema_version": SCHEMA_VERSION,
        "nodes": [
            {
                "id": n,
                **{k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in d.items()},
            }
            for n, d in graph.g.nodes(data=True)
        ],
        "edges": [
            {"source": u, "target": v, **d}
            for u, v, d in graph.g.edges(data=True)
        ],
    }
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, dest)


def load_graph(path: Path) -> EvidenceGraph:
    g = EvidenceGraph()
    src = Path(path)
    if not src.exists():
        return g
    data = json.loads(src.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return g
    for node in data.get("nodes", []):
        if not isinstance(node, dict) or "id" not in node:
            continue
        node = dict(node)
        nid = node.pop("id")
        node.pop("schema_version", None)
        g.g.add_node(nid, **node)
    for edge in data.get("edges", []):
        if not isinstance(edge, dict):
            continue
        src_id, dst_id = edge.get("source"), edge.get("target")
        if src_id is None or dst_id is None:
            continue
        rest = {k: v for k, v in edge.items() if k not in ("source", "target")}
        g.g.add_edge(src_id, dst_id, **rest)
    return g
