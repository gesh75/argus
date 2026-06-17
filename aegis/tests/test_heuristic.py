"""Offline heuristic analyzer — SMB/SNMP findings + mitigation enrichment."""
from __future__ import annotations

from aegis.ai_analyzer import _enrich, _heuristic
from aegis.tools import Observation


def _by_title(findings):
    return {f.title: f for f in findings}


def test_snmp_default_community_finding():
    fs = _enrich(_heuristic([Observation("172.30.0.12", "snmp", "172.30.0.12 [public] Juniper")]))
    f = next(f for f in fs if "default community" in f.title)
    assert f.severity == "Medium"
    assert "T1602" in f.mitre_attack
    assert f.mitigation_steps  # platform playbook attached


def test_smb_guest_share_finding():
    fs = _enrich(_heuristic([Observation("172.30.0.12", "smb", "Disk  public  READ ONLY guest ok")]))
    f = next(f for f in fs if "null/guest" in f.title)
    assert f.severity == "Medium"
    assert "T1135" in f.mitre_attack
    assert f.mitigation_steps


def test_smb_user_enum_finding():
    fs = _enrich(_heuristic([Observation("172.30.0.12", "smb", "user: administrator (RID 500)")]))
    f = next(f for f in fs if "enumeration" in f.title.lower())
    assert "T1087" in f.mitre_attack


def test_every_finding_has_platform_and_steps():
    obs = [Observation("172.30.0.12", "snmp", "[public] community"),
           Observation("172.30.0.11", "tls", "weak protocol enabled: TLSv1.0"),
           Observation("172.30.0.12", "smb", "guest ok = yes")]
    for f in _enrich(_heuristic(obs)):
        assert f.platform and f.mitigation_steps
