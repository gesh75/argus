"""Web / API Agent — read-only web recon proposals.
"""
from __future__ import annotations
from typing import Any
from .base import BaseAgent


class WebAgent(BaseAgent):
    name = "web"

    def propose(self) -> list[dict[str, Any]]:
        return []
