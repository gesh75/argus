"""V2 specialized-agent and persistence gaps closed in this increment."""
from __future__ import annotations

from pathlib import Path

from aegis.agents.ad import ADAgent
from aegis.agents.base import BaseAgent
from aegis.agents.correlation import CorrelationAgent
from aegis.agents.host import HostAgent
from aegis.agents.recon import ReconAgent
from aegis.agents.web import WebAgent
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


def test_specialized_agents_propose_from_evidence() -> None:
    g = EvidenceGraph()
    g.add(Observation(
        id="n1", kind="network", target="172.30.0.10",
        summary="3000/tcp http", evidence={}, proof="observed",
    ))
    g.add(Observation(
        id="h1", kind="host", target="172.30.0.20",
        summary="22/tcp ssh", evidence={}, proof="observed",
    ))
    g.add(Observation(
        id="a1", kind="ad", target="172.30.0.21",
        summary="389/tcp ldap", evidence={}, proof="observed",
    ))
    web = WebAgent(_DummyGuard(), g, default_targets=["172.30.0.10"])  # type: ignore[arg-type]
    host = HostAgent(_DummyGuard(), g, default_targets=["172.30.0.20"])  # type: ignore[arg-type]
    ad = ADAgent(_DummyGuard(), g, default_targets=["172.30.0.21"])  # type: ignore[arg-type]
    assert web.propose()
    assert host.propose()
    assert ad.propose()


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


def test_graph_persistence_is_atomic(tmp_path: Path) -> None:
    g = EvidenceGraph()
    g.add(Observation(id="n1", kind="network", target="172.30.0.10",
                      summary="up", evidence={}, proof="observed"))
    dest = tmp_path / "graph.json"
    save_graph(g, dest)
    assert dest.exists()
    assert not dest.with_name("graph.json.tmp").exists()
    loaded = load_graph(dest)
    assert "n1" in loaded.g
