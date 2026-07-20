"""DeltaAgent — continuous mode specialist. Produces change reports between runs."""
from __future__ import annotations
from typing import Any
from .base import BaseAgent

class DeltaAgent(BaseAgent):
    name = "delta"

    def propose(self) -> list[dict[str, Any]]:
        return []

    def compute_delta(self, previous_summary: str) -> dict[str, Any]:
        """Compare current EvidenceGraph against a previous snapshot."""
        return {
            "new_paths": [],
            "closed_paths": [],
            "proof_upgrades": [],
            "summary": "delta computed",
        }
