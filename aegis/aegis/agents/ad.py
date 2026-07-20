"""AD / Identity Agent — LDAP and identity path proposals (read-only).
"""
from __future__ import annotations
from typing import Any
from .base import BaseAgent


class ADAgent(BaseAgent):
    name = "ad"

    def propose(self) -> list[dict[str, Any]]:
        return []
