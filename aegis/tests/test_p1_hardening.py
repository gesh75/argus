"""P1 hardening suite: approval gate (#6), anchoring (#5), egress (#7),
pre-flight (#8), and audit-key strength (#4)."""
import os

os.environ.setdefault("PENTEST_AUDIT_HMAC_KEY", "k" * 32)

import pytest

from aegis import anchor, approval, egress, preflight
from aegis.config import DEFAULT_POLICY, Policy
from aegis.guardrail import AuditLog, GuardrailError

KEY = "k" * 32


# ---- #6 approval gate -------------------------------------------------------
def test_approval_roundtrip_ok():
    tok = approval.mint("local", ["172.30.0.10", "172.30.0.11"], KEY, ttl=60)
    # order/representation independence: same set, different order/form verifies.
    approval.verify(tok, "local", ["172.30.0.11", "172.30.0.10"], KEY)


def test_approval_rejects_different_targets():
    tok = approval.mint("local", ["172.30.0.10"], KEY, ttl=60)
    with pytest.raises(approval.ApprovalError):
        approval.verify(tok, "local", ["172.30.0.99"], KEY)


def test_approval_rejects_extra_target():
    tok = approval.mint("local", ["172.30.0.10"], KEY, ttl=60)
    with pytest.raises(approval.ApprovalError):
        approval.verify(tok, "local", ["172.30.0.10", "172.30.0.11"], KEY)


def test_approval_rejects_wrong_key():
    tok = approval.mint("local", ["172.30.0.10"], KEY, ttl=60)
    with pytest.raises(approval.ApprovalError):
        approval.verify(tok, "local", ["172.30.0.10"], "z" * 32)


def test_approval_combined_modes_exact_match():
    tok = approval.mint(["local", "arm"], ["172.30.0.10"], KEY, ttl=60)
    # order-independent within the set
    approval.verify(tok, ["arm", "local"], ["172.30.0.10"], KEY)
    # a {local,arm} token must NOT satisfy a {local}-only requirement (exact match, fail closed)
    with pytest.raises(approval.ApprovalError):
        approval.verify(tok, ["local"], ["172.30.0.10"], KEY)


def test_approval_arm_mode_distinct_from_local():
    tok = approval.mint("arm", ["172.30.0.10"], KEY, ttl=60)
    approval.verify(tok, "arm", ["172.30.0.10"], KEY)
    with pytest.raises(approval.ApprovalError):
        approval.verify(tok, "local", ["172.30.0.10"], KEY)


def test_approval_expired():
    tok = approval.mint("local", ["172.30.0.10"], KEY, ttl=10, now=1000)
    with pytest.raises(approval.ApprovalError, match="expired"):
        approval.verify(tok, "local", ["172.30.0.10"], KEY, now=2000)


def test_approval_missing_and_malformed():
    with pytest.raises(approval.ApprovalError):
        approval.verify("", "local", ["172.30.0.10"], KEY)
    with pytest.raises(approval.ApprovalError):
        approval.verify("not-a-token", "local", ["172.30.0.10"], KEY)


# ---- #4 audit-key strength --------------------------------------------------
def test_short_audit_key_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("PENTEST_AUDIT_HMAC_KEY", "tooshort")
    pol = Policy.load(DEFAULT_POLICY)
    object.__setattr__(pol, "audit_path", tmp_path / "a.ndjson")
    with pytest.raises(GuardrailError, match="too short"):
        AuditLog(pol)


# ---- #5 anchoring -----------------------------------------------------------
def _audit(tmp_path, monkeypatch):
    monkeypatch.setenv("PENTEST_AUDIT_HMAC_KEY", KEY)
    pol = Policy.load(DEFAULT_POLICY)
    object.__setattr__(pol, "audit_path", tmp_path / "audit.ndjson")
    object.__setattr__(pol, "audit_anchor_path", tmp_path / "anchor.json")
    return AuditLog(pol), pol


def test_anchor_tracks_chain_tip(tmp_path, monkeypatch):
    log, _ = _audit(tmp_path, monkeypatch)
    log.write({"event": "a"})
    log.write({"event": "b"})
    ok, reason = log.cross_check_anchor()
    assert ok, reason
    rec = anchor.read_anchor(log._anchor_path)
    assert rec["seq"] == 2 and rec["tip"] == log._prev


def test_anchor_detects_log_rewrite(tmp_path, monkeypatch):
    log, pol = _audit(tmp_path, monkeypatch)
    log.write({"event": "a"})
    log.write({"event": "b"})
    # Attacker truncates the log to drop the last entry; anchor still records seq=2.
    lines = pol.audit_path.read_text().splitlines()
    pol.audit_path.write_text(lines[0] + "\n")
    ok, reason = log.cross_check_anchor()
    assert not ok and "mismatch" in reason.lower()


def test_anchor_detects_missing_anchor(tmp_path, monkeypatch):
    log, _ = _audit(tmp_path, monkeypatch)
    log.write({"event": "a"})
    log._anchor_path.unlink()
    ok, reason = log.cross_check_anchor()
    assert not ok and "missing" in reason.lower()


# ---- #7 egress rules --------------------------------------------------------
def test_egress_ruleset_from_policy():
    pol = Policy.load(DEFAULT_POLICY)
    rs = egress.nftables_ruleset(pol)
    assert "policy drop" in rs                       # fail-closed default
    assert "172.30.0.0/24" in rs                      # the lab allow-list CIDR
    assert 'oifname "lo" accept' in rs
    # a denied range is dropped explicitly
    assert "10.0.0.0/8 drop" in rs


# ---- #8 pre-flight ----------------------------------------------------------
def test_preflight_flags_public_ip():
    pol = Policy.load(DEFAULT_POLICY)
    warns = preflight.check(["8.8.8.8"], pol)
    assert any("PUBLIC IP" in w for w in warns)


def test_preflight_clean_for_inscope_lab_ip():
    pol = Policy.load(DEFAULT_POLICY)
    # in-scope private lab IP with the tight default /24 policy → no target-level warning
    warns = preflight.check(["172.30.0.10"], pol)
    assert not any("PUBLIC IP" in w for w in warns)


def test_preflight_flags_broad_scope(tmp_path, monkeypatch):
    import ipaddress
    pol = Policy.load(DEFAULT_POLICY)
    object.__setattr__(pol, "allowed_networks", (ipaddress.ip_network("172.30.0.0/16"),))
    warns = preflight.check(["172.30.0.10"], pol)
    assert any("allow-list spans" in w for w in warns)
