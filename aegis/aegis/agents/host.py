"""Host Agent — Linux/Windows credentialed audit proposals.
"""
from __future__ import annotations
from typing import Any
from .base import BaseAgent


class HostAgent(BaseAgent):
    name = "host"

    def propose(self) -> list[dict[str, Any]]:
        return []
