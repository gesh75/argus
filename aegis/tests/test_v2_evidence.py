"""Tests for V2 EvidenceGraph and CorrelationAgent."""
import pytest
from aegis.evidence import EvidenceGraph, Observation
from aegis.agents.correlation import CorrelationAgent
from aegis.guardrail import Guardrail
from aegis.config import Policy, DEFAULT_POLICY


def test_evidence_graph_add_and_path():
    g = EvidenceGraph()
    obs1 = Observation(id="o1", kind="exposure", target="172.30.0.11", summary=".env found", evidence={}, proof="observed")
    obs2 = Observation(id="o2", kind="host", target="172.30.0.11", summary="SSH open", evidence={}, proof="observed")
    g.add(obs1)
    g.add(obs2)
    path_id = g.add_path(["o1", "o2"], proof="theoretical", reason="test path")
    assert path_id in g.g
    assert len(g.observed_paths()) == 0  # theoretical
    assert "o1" in g.g


def test_correlation_agent_derives_paths():
    policy = Policy.load(DEFAULT_POLICY)
    # Minimal guardrail for test (will fail without key, so we mock carefully)
    # For unit test we only exercise derive_paths which does not call authorize
    g = EvidenceGraph()
    g.add(Observation(id="e1", kind="exposure", target="x", summary="secret path", evidence={}, proof="observed"))
    g.add(Observation(id="h1", kind="host", target="x", summary="ssh", evidence={}, proof="observed"))
    # Create a dummy guardrail-less agent for pure reasoning test
    class DummyGuard:
        pass
    agent = CorrelationAgent(DummyGuard(), g)  # type: ignore
    paths = agent.derive_paths()
    assert len(paths) >= 1
    assert any("Exposure" in p["name"] for p in paths)
