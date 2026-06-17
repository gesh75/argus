"""Windows + AD module parsers, catalogs, and authorization."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("PENTEST_AUDIT_HMAC_KEY", "k" * 32)

from aegis.config import Policy  # noqa: E402
from aegis.guardrail import Guardrail, GuardrailError  # noqa: E402
from aegis.host import ad, windows  # noqa: E402
from aegis.host.win_parsers import parse_windows  # noqa: E402

POLICY = Path(__file__).resolve().parents[2] / "targets" / "scope-policy.yaml"


@pytest.fixture
def guard(tmp_path, monkeypatch):
    monkeypatch.setenv("PENTEST_AUDIT_HMAC_KEY", "k" * 32)
    pol = Policy.load(POLICY)
    object.__setattr__(pol, "audit_path", tmp_path / "audit.ndjson")
    return Guardrail(pol)


# ---- Windows parsers ----
def test_win_smb_signing_flagged():
    out = "EnableSMB1Protocol      : True\nRequireSecuritySignature : False\n"
    obs = parse_windows("config", "smb_signing", out, "172.30.0.30")
    txt = " ".join(o.detail.lower() for o in obs)
    assert "smbv1" in txt and "signing not required" in txt


def test_win_always_install_elevated():
    obs = parse_windows("privesc", "always_install_elevated", "1\n1\n", "172.30.0.30")
    assert obs and "alwaysinstallelevated" in obs[0].detail.lower()


def test_win_wdigest_cleartext():
    obs = parse_windows("config", "wdigest", "1", "172.30.0.30")
    assert obs and "cleartext" in obs[0].detail.lower()


def test_win_default_winrm_is_https_strict():
    from aegis.host.winrm_collector import WinRMCreds
    c = WinRMCreds(user="a", password="b")
    assert c.https is True and c.verify_cert is True   # strict by default


# ---- AD parsers ----
def test_ad_anonymous_users_flagged():
    out = "dn: uid=jsmith,ou=people,dc=ecp,dc=lab\ncn: John Smith\nuid: jsmith\n"
    obs = ad._parse("anon_users", out, "172.30.0.21")
    assert obs and "user enumeration" in obs[0].detail.lower()


def test_ad_rootdse_naming_context():
    out = "namingContexts: dc=ecp,dc=lab\nsupportedLDAPVersion: 3\n"
    obs = ad._parse("rootdse", out, "172.30.0.21")
    assert obs and "rootdse" in obs[0].detail.lower()


# ---- authorization over the new catalogs ----
def test_windows_check_authorized_in_scope(guard):
    guard.authorize_host("172.30.0.30", "smb_signing", windows.WINDOWS_CATALOG)


def test_ad_check_unknown_denied(guard):
    with pytest.raises(GuardrailError):
        guard.authorize_host("172.30.0.21", "dump_everything", ad.AD_CATALOG)
