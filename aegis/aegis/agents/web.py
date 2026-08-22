"""Web / API Agent — read-only web recon proposals.
"""
from __future__ import annotations

from typing import Any

from .base import BaseAgent


class WebAgent(BaseAgent):
    name = "web"

    def propose(self) -> list[dict[str, Any]]:
        targets = list(self.default_targets)
        if not targets:
            return []
        blob = " ".join(
            f"{d.get('kind', '')} {d.get('summary', '')}"
            for _, d in self.graph.g.nodes(data=True)
        ).lower()
        if any(s in blob for s in ("80/tcp", "443/tcp", "3000/tcp", "8080", "http", "web")):
            return [{
                "tool": "whatweb",
                "args": [f"http://{t}" for t in targets],
                "targets": targets,
                "reason": "web surface observed",
            }]
        return []
