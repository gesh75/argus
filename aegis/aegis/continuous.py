"""Continuous / Delta mode for Argus V2.

Runs the specialized agents on a schedule and produces delta reports
while every single tool call remains under the 7-layer Guardrail.
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .evidence import EvidenceGraph, Observation
from .guardrail import Guardrail
from .agents.base import BaseAgent


@dataclass
class DeltaReport:
    run_id: str
    timestamp: datetime
    new_observations: list[str] = field(default_factory=list)
    new_paths: list[str] = field(default_factory=list)
    closed_paths: list[str] = field(default_factory=list)
    summary: str = ""


class ContinuousRunner:
    """Orchestrates repeated authorized runs and delta computation."""

    def __init__(self, guardrail: Guardrail, agents: list[BaseAgent], graph: EvidenceGraph):
        self.guardrail = guardrail
        self.agents = agents
        self.graph = graph
        self.previous_nodes: set[str] = set()

    def one_cycle(self) -> DeltaReport:
        before = set(self.graph.g.nodes)
        for agent in self.agents:
            proposals = agent.propose()
            for prop in proposals:
                # Every proposal is still forced through the Guardrail
                tool = prop.get("tool")
                args = prop.get("args", [])
                targets = prop.get("targets", [])
                if tool and targets:
                    try:
                        agent.run_authorized(tool, args, targets)
                    except Exception as exc:  # GuardrailError or other
                        # Logged by Guardrail; continue safely
                        pass
        after = set(self.graph.g.nodes)
        new = after - before
        report = DeltaReport(
            run_id=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
            timestamp=datetime.now(timezone.utc),
            new_observations=[n for n in new if not str(n).startswith("path-")],
            new_paths=[n for n in new if str(n).startswith("path-")],
            summary=f"{len(new)} new nodes this cycle",
        )
        self.previous_nodes = after
        return report

    def run_loop(self, interval_seconds: int = 3600, max_runs: int = 0) -> None:
        runs = 0
        while True:
            report = self.one_cycle()
            print(f"[continuous] {report.summary}")
            runs += 1
            if max_runs and runs >= max_runs:
                break
            time.sleep(interval_seconds)
