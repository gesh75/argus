"""Base agent — the only legal way for specialized agents to act.

The agent proposes. The Guardrail disposes.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any

from ..guardrail import Guardrail
from ..evidence import EvidenceGraph, Observation


class BaseAgent(ABC):
    name: str = "base"

    def __init__(self, guardrail: Guardrail, graph: EvidenceGraph):
        self.guardrail = guardrail
        self.graph = graph

    @abstractmethod
    def propose(self) -> list[dict[str, Any]]:
        """Return list of proposed actions (tool + args + targets).
        Never execute — only propose.
        """
        ...

    def run_authorized(self, tool: str, args: list[str], targets: list[str]) -> None:
        """The only way an agent may touch the world."""
        self.guardrail.authorize(tool, args, targets)
        # Collectors and Observation recording happen after this point.
