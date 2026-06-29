"""End-to-end: a scan auto-enriches with shadow-AI, segmentation, cred-exposure, chains."""
import os

os.environ.setdefault("PENTEST_AUDIT_HMAC_KEY", "k" * 32)

from dataclasses import dataclass

import pytest

from aegis.config import DEFAULT_POLICY, Policy
from aegis.guardrail import Guardrail
from aegis.orchestrator import Orchestrator, ScanStep


@dataclass
class _Exec:
    exit_code: int
    stdout: str
    tool_missing: bool = False


class _FakeSandbox:
    """Returns canned nmap-XML exposing AI + DB + SMB ports so enrichment fires."""

    XML = """<?xml version="1.0"?><nmaprun><host><address addr="172.30.0.20"/>
    <ports>
      <port protocol="tcp" portid="11434"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="3306"><state state="open"/><service name="mysql"/></port>
      <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
    </ports></host></nmaprun>"""

    def run(self, argv, timeout=300):
        return _Exec(0, self.XML)


@pytest.fixture
def _orch(tmp_path, monkeypatch):
    # Isolate the audit chain to a temp file so verify() never replays stale entries.
    monkeypatch.setenv("PENTEST_AUDIT_HMAC_KEY", "k" * 32)
    pol = Policy.load(DEFAULT_POLICY)
    object.__setattr__(pol, "audit_path", tmp_path / "audit.ndjson")
    guard = Guardrail(pol)
    return Orchestrator(guard, _FakeSandbox()), guard


def test_scan_surfaces_shadow_ai_segmentation_and_chains(_orch):
    orch, _ = _orch
    res = orch.run([ScanStep("nmap_service", "172.30.0.20")])
    kinds = {o.kind for o in res.observations}
    assert "ai-service" in kinds          # Ollama:11434 discovered
    assert "segmentation" in kinds        # mysql/ssh/smb sensitive planes
    titles = " ".join(f.title.lower() for f in res.findings)
    assert "shadow ai" in titles and "segmentation" in titles
    paths = res.correlation.get("attack_paths", [])
    assert any("segmentation" in p["name"].lower() for p in paths)
    assert all("proof" in p for p in paths if "segmentation" in p["name"].lower())


def test_audit_chain_stays_valid_through_enrichment(_orch):
    orch, guard = _orch
    orch.run([ScanStep("nmap_service", "172.30.0.20")])
    assert guard.audit.verify()
