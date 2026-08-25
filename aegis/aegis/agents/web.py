"""Web / API Agent — read-only web recon proposals.

Idempotent: stops once web-kind evidence exists for the operator targets.
"""
from __future__ import annotations

from typing import Any

from .base import BaseAgent


class WebAgent(BaseAgent):
    name = "web"

    def propose(self) -> list[dict[str, Any]]:
        targets = [t for t in self.default_targets if "web" not in self.kinds_for(t)]
        if not targets:
            return []
        blob = self.blob()
        if not any(s in blob for s in ("80/tcp", "443/tcp", "3000/tcp", "8080", "http", "web")):
            return []
        return [{
            "tool": "whatweb",
            "args": [f"http://{t}" for t in targets],
            "targets": targets,
            "reason": "web surface observed",
        }]
