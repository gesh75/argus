"""Guardrail tests — prove the bypass holes from the adversarial review are closed."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("PENTEST_AUDIT_HMAC_KEY", "test-key-0123456789")

from aegis.config import Policy  # noqa: E402
from aegis.guardrail import Guardrail, GuardrailError, canon_network  # noqa: E402

POLICY = Path(__file__).resolve().parents[2] / "targets" / "scope-policy.yaml"


@pytest.fixture
def guard(tmp_path, monkeypatch):
    monkeypatch.setenv("PENTEST_AUDIT_HMAC_KEY", "k" * 32)
    pol = Policy.load(POLICY)
    object.__setattr__(pol, "audit_path", tmp_path / "audit.ndjson")
    return Guardrail(pol)


# ---- canonicalization defeats IP obfuscation ------------------------------
def test_decimal_ip_canonicalizes():
    # 172.30.0.1 as a 32-bit integer — tools accept this; guardrail must canonicalize it.
    assert str(canon_network("2887647233")) == "172.30.0.1/32"


def test_hex_ip_canonicalizes():
    assert str(canon_network("0xAC1E0001")) == "172.30.0.1/32"


def test_leading_zero_octet_rejected():
    with pytest.raises(ValueError):
        canon_network("172.030.0.1")  # octal ambiguity


def test_host_bits_cidr_rejected():
    with pytest.raises(ValueError):
        canon_network("172.30.0.5/24")  # host bits set with strict=True


# ---- scope guard: in-scope allowed, everything else denied -----------------
def test_in_scope_target_ok(guard):
    assert guard.check_target("172.30.0.10").allowed


def test_out_of_scope_denied(guard):
    assert not guard.check_target("10.0.0.5").allowed


def test_decimal_obfuscated_out_of_scope_denied(guard):
    # 10.0.0.5 in decimal — must still be rejected after canonicalization
    assert not guard.check_target("167772165").allowed


def test_broad_cidr_denied(guard):
    assert not guard.check_target("172.30.0.0/8").allowed


def test_denied_carveout_inside_allowed_is_rejected(guard):
    # A more-specific deny carved out *inside* the allowed lab /24 must win (e.g. a
    # production/clinical host the operator excluded). Longest-prefix-match: /32 > /24.
    import ipaddress
    object.__setattr__(guard.policy, "denied_networks",
                       guard.policy.denied_networks + (ipaddress.ip_network("172.30.0.50/32"),))
    assert not guard.check_target("172.30.0.50").allowed     # denied carve-out wins
    assert guard.check_target("172.30.0.10").allowed         # rest of lab still in scope


# ---- authorize(): hostnames, file inputs, NSE, metachars all fail closed ---
def test_hostname_arg_denied(guard):
    with pytest.raises(GuardrailError):
        guard.authorize("nmap", ["nmap", "evil.corp"], ["evil.corp"])


def test_file_input_flag_denied(guard):
    with pytest.raises(GuardrailError):
        guard.authorize("nmap", ["nmap", "-iL", "targets.txt"], ["172.30.0.10"])


def test_nse_script_flag_denied(guard):
    with pytest.raises(GuardrailError):
        guard.authorize("nmap", ["nmap", "--script", "exploit", "172.30.0.10"],
                        ["172.30.0.10"])


def test_shell_metachar_denied(guard):
    with pytest.raises(GuardrailError):
        guard.authorize("nmap", ["nmap", "172.30.0.10; curl evil"], ["172.30.0.10"])


def test_no_target_denied(guard):
    with pytest.raises(GuardrailError):
        guard.authorize("nmap", ["nmap"], [])


def test_denied_tool(guard):
    # dnscat2 is in the policy denied list
    with pytest.raises(GuardrailError):
        guard.authorize("dnscat2", ["dnscat2", "172.30.0.10"], ["172.30.0.10"])


def test_clean_scan_authorized(guard):
    guard.authorize("nmap", ["nmap", "-sT", "172.30.0.10"], ["172.30.0.10"])  # no raise


def test_ldapsearch_dash_x_allowed_url_host_in_scope(guard):
    # ldapsearch -x is benign simple-auth; ldap://<in-scope-ip> host must validate.
    guard.authorize("ldapsearch",
                    ["ldapsearch", "-x", "-H", "ldap://172.30.0.12", "-b", ""],
                    ["172.30.0.12"])  # no raise


def test_file_path_arg_not_flagged_as_hostname(guard):
    # onesixtyone dict path has dots but is a path, not a DNS name — must not be denied.
    guard.authorize("onesixtyone",
                    ["onesixtyone", "172.30.0.12", "public"], ["172.30.0.12"])  # no raise


def test_nmap_script_denied_per_tool(guard):
    with pytest.raises(GuardrailError):
        guard.authorize("nmap", ["nmap", "--script", "vuln", "172.30.0.10"], ["172.30.0.10"])


def test_binary_name_with_dot_not_flagged(guard):
    # argv[0] 'testssl.sh' must not be denied as a hostname; in-scope target is fine.
    guard.authorize("testssl.sh", ["testssl.sh", "--quiet", "172.30.0.11"], ["172.30.0.11"])


def test_url_with_out_of_scope_ip_denied(guard):
    with pytest.raises(GuardrailError):
        guard.authorize("ldapsearch", ["ldapsearch", "-H", "ldap://10.0.0.9"], ["10.0.0.9"])


# ---- audit chain is tamper-evident ----------------------------------------
def test_audit_chain_valid_then_tamper(guard):
    guard.authorize("nmap", ["nmap", "-sT", "172.30.0.10"], ["172.30.0.10"])
    assert guard.audit.verify()
    p = guard.audit._path
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:-1]) + '\n{"event":"forged","hmac":"deadbeef"}\n')
    assert not guard.audit.verify()
