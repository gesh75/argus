"""V2 specialized-agent, persistence, delta, and signer-adjacent gaps."""
from __future__ import annotations

import json
from pathlib import Path

from aegis.agents.ad import ADAgent
from aegis.agents.base import BaseAgent
from aegis.agents.correlation import CorrelationAgent
from aegis.agents.delta import DeltaAgent
from aegis.agents.host import HostAgent
from aegis.agents.recon import ReconAgent
from aegis.agents.web import WebAgent
from aegis.continuous import ContinuousRunner
from aegis.evidence import EvidenceGraph, Observation
from aegis.persistence import load_graph, save_graph


class _DummyGuard:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str], list[str]]] = []

    def authorize(self, tool: str, args: list[str], targets: list[str]) -> None:
        self.calls.append((tool, args, targets))


def test_recon_proposes_operator_targets() -> None:
    g = EvidenceGraph()
    agent = ReconAgent(_DummyGuard(), g, default_targets=["172.30.0.10"])  # type: ignore[arg-type]
    props = agent.propose()
    assert props
    assert props[0]["targets"] == ["172.30.0.10"]
    assert props[0]["args"][-1] == "172.30.0.10"


def test_recon_is_idempotent_after_network_evidence() -> None:
    g = EvidenceGraph()
    agent = ReconAgent(_DummyGuard(), g, default_targets=["172.30.0.10"])  # type: ignore[arg-type]
    g.add(Observation(
        id="n1", kind="network", target="172.30.0.10",
        summary="host up", evidence={}, proof="observed",
    ))
    assert agent.propose() == []


def test_specialized_agents_propose_from_evidence() -> None:
    g = EvidenceGraph()
    g.add(Observation(
        id="n1", kind="network", target="172.30.0.10",
        summary="3000/tcp http", evidence={}, proof="observed",
    ))
    g.add(Observation(
        id="n2", kind="network", target="172.30.0.20",
        summary="22/tcp ssh", evidence={}, proof="observed",
    ))
    g.add(Observation(
        id="n3", kind="network", target="172.30.0.21",
        summary="389/tcp ldap", evidence={}, proof="observed",
    ))
    web = WebAgent(_DummyGuard(), g, default_targets=["172.30.0.10"])  # type: ignore[arg-type]
    host = HostAgent(_DummyGuard(), g, default_targets=["172.30.0.20"])  # type: ignore[arg-type]
    ad = ADAgent(_DummyGuard(), g, default_targets=["172.30.0.21"])  # type: ignore[arg-type]
    assert web.propose()
    assert host.propose()
    assert ad.propose()
    g.add(Observation(
        id="w1", kind="web", target="172.30.0.10",
        summary="Express", evidence={}, proof="observed",
    ))
    g.add(Observation(
        id="h1", kind="host", target="172.30.0.20",
        summary="NOPASSWD sudo", evidence={}, proof="observed",
    ))
    g.add(Observation(
        id="a1", kind="ad", target="172.30.0.21",
        summary="anonymous bind", evidence={}, proof="observed",
    ))
    assert web.propose() == []
    assert host.propose() == []
    assert ad.propose() == []


def test_run_authorized_records_collector_observations() -> None:
    guard = _DummyGuard()
    g = EvidenceGraph()

    def collector(tool: str, args: list[str], targets: list[str]) -> list[Observation]:
        return [Observation(
            id="o1", kind="network", target=targets[0],
            summary="host up", evidence={"tool": tool, "args": args},
            proof="observed",
        )]

    class Probe(BaseAgent):
        name = "probe"

        def propose(self) -> list[dict]:
            return []

    agent = Probe(guard, g, collector=collector, default_targets=["172.30.0.10"])  # type: ignore[arg-type]
    got = agent.run_authorized("nmap", ["nmap", "-sn", "172.30.0.10"], ["172.30.0.10"])
    assert guard.calls
    assert got and got[0].id == "o1"
    assert "o1" in g.g


def test_correlation_is_asset_bound() -> None:
    g = EvidenceGraph()
    g.add(Observation(id="e1", kind="exposure", target="172.30.0.10",
                      summary="secret path", evidence={}, proof="observed"))
    g.add(Observation(id="h1", kind="host", target="172.30.0.20",
                      summary="ssh", evidence={}, proof="observed"))
    agent = CorrelationAgent(_DummyGuard(), g)  # type: ignore[arg-type]
    assert agent.derive_paths() == []

    g.add(Observation(id="h2", kind="host", target="172.30.0.10",
                      summary="ssh", evidence={}, proof="observed"))
    paths = agent.derive_paths()
    assert any("Exposure" in p["name"] for p in paths)
    assert all(p.get("target") == "172.30.0.10" for p in paths if "Exposure" in p["name"])
    again = agent.derive_paths()
    ids = [p["id"] for p in paths]
    assert [p["id"] for p in again] == ids


def test_graph_persistence_is_atomic_and_checksummed(tmp_path: Path) -> None:
    g = EvidenceGraph()
    g.add(Observation(id="n1", kind="network", target="172.30.0.10",
                      summary="up", evidence={}, proof="observed"))
    dest = tmp_path / "graph.json"
    save_graph(g, dest)
    assert dest.exists()
    assert not dest.with_name("graph.json.tmp").exists()
    raw = json.loads(dest.read_text())
    assert raw["schema_version"] == 1
    assert isinstance(raw["checksum"], str) and len(raw["checksum"]) == 64
    loaded = load_graph(dest)
    assert "n1" in loaded.g


def test_load_graph_fails_closed_on_checksum_mismatch(tmp_path: Path) -> None:
    g = EvidenceGraph()
    g.add(Observation(id="n1", kind="network", target="172.30.0.10",
                      summary="up", evidence={}, proof="observed"))
    dest = tmp_path / "graph.json"
    save_graph(g, dest)
    data = json.loads(dest.read_text())
    data["nodes"][0]["summary"] = "tampered"
    dest.write_text(json.dumps(data))
    loaded = load_graph(dest)
    assert list(loaded.g.nodes) == []


def test_path_ids_are_deterministic() -> None:
    g = EvidenceGraph()
    g.add(Observation(id="e1", kind="exposure", target="172.30.0.10",
                      summary="x", evidence={}, proof="observed"))
    g.add(Observation(id="h1", kind="host", target="172.30.0.10",
                      summary="y", evidence={}, proof="observed"))
    a = g.add_path(["e1", "h1"], "theoretical", "same")
    b = g.add_path(["h1", "e1"], "theoretical", "same")
    assert a == b
    assert a.startswith("path-")


def test_delta_records_closed_paths() -> None:
    g = EvidenceGraph()
    g.add(Observation(id="e1", kind="exposure", target="172.30.0.10",
                      summary="x", evidence={}, proof="observed"))
    agent = DeltaAgent(_DummyGuard(), g, previous_nodes=set())  # type: ignore[arg-type]
    path_id = g.add_path(["e1"], "theoretical", "demo")
    first = agent.compute_delta()
    assert path_id in first["new_paths"] or path_id in first["new_nodes"]
    assert g.close_node(path_id)
    second = agent.compute_delta()
    assert path_id in second["closed_paths"]
    assert path_id in g.closed


def test_continuous_runner_reports_closed_paths(tmp_path: Path) -> None:
    g = EvidenceGraph()
    g.add(Observation(id="e1", kind="exposure", target="172.30.0.10",
                      summary="x", evidence={}, proof="observed"))
    path_id = g.add_path(["e1"], "theoretical", "demo")
    runner = ContinuousRunner(
        guardrail=_DummyGuard(),  # type: ignore[arg-type]
        agents=[],
        graph=g,
        persist_path=tmp_path / "graph.json",
        experimental=True,
    )
    first = runner.one_cycle()
    assert path_id not in first.closed_paths
    g.close_node(path_id)
    second = runner.one_cycle()
    assert path_id in second.closed_paths
