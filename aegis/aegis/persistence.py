"""JSON persistence for EvidenceGraph between continuous runs.

Writes are atomic (temp file + os.replace) and checksummed. This is still
experimental V2 scaffolding — not an independently administered WORM store.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

from .evidence import EvidenceGraph

SCHEMA_VERSION = 1


def _canonical(data: dict) -> str:
    body = {k: v for k, v in data.items() if k != "checksum"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)


def save_graph(graph: EvidenceGraph, path: Path) -> None:
    data = {
        "schema_version": SCHEMA_VERSION,
        "closed": sorted(graph.closed),
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
    data["checksum"] = hashlib.sha256(_canonical(data).encode("utf-8")).hexdigest()
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
    try:
        data = json.loads(src.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return g
    if not isinstance(data, dict):
        return g
    if data.get("schema_version") != SCHEMA_VERSION:
        return g
    digest = data.get("checksum")
    if not isinstance(digest, str) or digest != hashlib.sha256(
        _canonical(data).encode("utf-8")
    ).hexdigest():
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
    closed = data.get("closed", [])
    if isinstance(closed, list):
        g.closed = {str(x) for x in closed}
    return g
