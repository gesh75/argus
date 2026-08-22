"""Base agent — the only legal way for specialized agents to act.

The agent proposes. The Guardrail disposes.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from typing import Any

from ..evidence import EvidenceGraph, Observation
from ..guardrail import Guardrail

Collector = Callable[[str, list[str], list[str]], Sequence[Observation]]


class BaseAgent(ABC):
    name: str = "base"

    def __init__(
        self,
        guardrail: Guardrail,
        graph: EvidenceGraph,
        *,
        collector: Collector | None = None,
        default_targets: Sequence[str] | None = None,
    ):
        self.guardrail = guardrail
        self.graph = graph
        self.collector = collector
        self.default_targets = [t for t in (default_targets or []) if t]

    @abstractmethod
    def propose(self) -> list[dict[str, Any]]:
        """Return list of proposed actions (tool + args + targets).
        Never execute — only propose.
        """
        ...

    def run_authorized(self, tool: str, args: list[str], targets: list[str]) -> list[Observation]:
        """The only way an agent may touch the world."""
        resolved = list(targets) or list(self.default_targets)
        self.guardrail.authorize(tool, args, resolved)
        if self.collector is None:
            return []
        results = list(self.collector(tool, args, resolved) or [])
        for obs in results:
            self.graph.add(obs)
        return results
