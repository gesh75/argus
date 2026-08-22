"""Base agent — the only legal way for specialized agents to act.

The agent proposes. The Guardrail disposes.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from typing import Any

from ..evidence import EvidenceGraph, Observation

Collector = Callable[[str, list[str], list[str]], Sequence[Observation]]


class BaseAgent(ABC):
    name: str = "base"

    def __init__(
        self,
        guardrail,
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

    def kinds_for(self, target: str | None = None) -> set[str]:
        kinds: set[str] = set()
        for _, data in self.graph.g.nodes(data=True):
            if target and str(data.get("target") or "") != target:
                continue
            kind = data.get("kind")
            if kind:
                kinds.add(str(kind))
        return kinds

    def blob(self) -> str:
        return " ".join(
            f"{d.get('kind', '')} {d.get('summary', '')}"
            for _, d in self.graph.g.nodes(data=True)
        ).lower()

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
