"""Host-audit module — parsers + credentialed-check authorization."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("PENTEST_AUDIT_HMAC_KEY", "k" * 32)

from aegis.config import Policy  # noqa: E402
from aegis.guardrail import Guardrail, GuardrailError  # noqa: E402
from aegis.host import audits  # noqa: E402
from aegis.host.parsers import parse_host  # noqa: E402

POLICY = Path(__file__).resolve().parents[2] / "targets" / "scope-policy.yaml"


@pytest.fixture
def guard(tmp_path, monkeypatch):
    monkeypatch.setenv("PENTEST_AUDIT_HMAC_KEY", "k" * 32)
    pol = Policy.load(POLICY)
    object.__setattr__(pol, "audit_path", tmp_path / "audit.ndjson")
    return Guardrail(pol)


def test_suid_gtfobins_flagged():
    obs = parse_host("privesc", "suid", "/usr/local/bin/rootbash\n/usr/bin/passwd\n", "172.30.0.20")
    assert any("rootbash" in o.detail for o in obs)
    assert all(o.kind == "privesc" for o in obs)
    assert not any("passwd" in o.detail for o in obs)  # passwd is normal, not GTFOBins


def test_sudo_nopasswd_flagged():
    obs = parse_host("privesc", "sudo_rights",
                     "(ALL) NOPASSWD: /usr/bin/find\n", "172.30.0.20")
    assert obs and "sudo privilege escalation" in obs[0].detail


def test_ssh_weak_config_flagged():
    obs = parse_host("config", "ssh_config",
                     "permitrootlogin yes\npasswordauthentication yes\n", "172.30.0.20")
    kinds = " ".join(o.detail.lower() for o in obs)
    assert "root login" in kinds and "password" in kinds


def test_host_authorize_in_scope_and_catalog(guard):
    guard.authorize_host("172.30.0.20", "suid", audits.LINUX_CATALOG)  # no raise


def test_host_authorize_out_of_scope_denied(guard):
    with pytest.raises(GuardrailError):
        guard.authorize_host("10.0.0.20", "suid", audits.LINUX_CATALOG)


def test_host_authorize_unknown_check_denied(guard):
    with pytest.raises(GuardrailError):
        guard.authorize_host("172.30.0.20", "rm_rf_everything", audits.LINUX_CATALOG)
