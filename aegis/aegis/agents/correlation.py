"""CorrelationAgent — synthesizes proof-annotated attack paths from the Evidence Graph."""
from __future__ import annotations
from typing import Any
from .base import BaseAgent

class CorrelationAgent(BaseAgent):
    name = "correlation"

    def propose(self) -> list[dict[str, Any]]:
        # Correlation never emits network actions; it only reasons over the graph.
        return []

    def derive_paths(self) -> list[str]:
        """Inspect the EvidenceGraph and write path nodes with proof tags.

        Combines the existing deterministic chains engine with structured
        LLM hypotheses. Any verification step still goes through the Guardrail.
        """
        return []
