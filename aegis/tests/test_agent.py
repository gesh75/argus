"""Modules 2, 3, 3b, PoC — cred exposure, chaining, planner, hard-gated PoC."""
import os

import pytest

os.environ.setdefault("PENTEST_AUDIT_HMAC_KEY", "k" * 32)

from aegis.agent import chains, planner
from aegis.agent.poc_runner import PoCRefused, gate_check, verify
from aegis.ai_analyzer import Finding
from aegis.config import DEFAULT_POLICY, Policy
from aegis.guardrail import Guardrail
from aegis.recon import cred_exposure
from aegis.tools import Observation


def _guard(armed=None):
    return Guardrail(Policy.load(DEFAULT_POLICY), armed=armed)


# ---- Module 2: credential exposure -----------------------------------------
def test_gpp_cpassword_detected():
    obs = [Observation("10.0.0.5", "smb", "SYSVOL/Policies/Groups.xml cpassword=...")]
    out = cred_exposure.detect(obs)
    assert any("GPP cpassword" in o.detail for o in out)


def test_env_exposure_detected_and_redacted():
    g = _guard()
    obs = [Observation("172.30.0.10", "exposure", "secret: http://x/.env password=hunter2")]
    out = cred_exposure.detect(obs, sanitize=g.sanitize)
    assert out and "exposure" == out[0].kind


def test_no_false_positive_on_clean_evidence():
    obs = [Observation("10.0.0.9", "service", "80/tcp http nginx")]
    assert cred_exposure.detect(obs) == []


# ---- Module 3: chaining engine ---------------------------------------------
def test_privesc_chain_is_critical_and_observed():
    findings = [Finding("Exposed service: 22/tcp ssh", "Info", affected_asset="172.30.0.20"),
                Finding("Privesc: NOPASSWD sudo", "High", affected_asset="172.30.0.20")]
    cs = chains.derive_chains(findings)
    pe = [c for c in cs if "privilege escalation" in c.name.lower()]
    assert pe and pe[0].severity == "Critical" and pe[0].proof == "observed"


def test_segmentation_chain_observed():
    findings = [Finding("Segmentation gap: database plane reachable", "High",
                        affected_asset="10.0.0.5")]
    cs = chains.derive_chains(findings)
    assert any("segmentation" in c.name.lower() and c.proof == "observed" for c in cs)


def test_web_to_host_theoretical_without_service():
    findings = [Finding("Web exposure: secret: /.env", "High", affected_asset="172.30.0.10")]
    cs = chains.derive_chains(findings)
    w = [c for c in cs if "web secret" in c.name.lower()]
    assert w and w[0].proof == "theoretical"


def test_relay_chain_theoretical_without_weak_tls():
    # smb + ad present but no weak-TLS coercion path observed -> theoretical, not observed.
    findings = [Finding("SMBv1 enabled", "High", affected_asset="172.30.0.11"),
                Finding("AD/LDAP: anonymous bind", "Medium", affected_asset="172.30.0.21")]
    cs = chains.derive_chains(findings)
    relay = [c for c in cs if "relay" in c.name.lower()]
    assert relay and relay[0].proof == "theoretical"


def test_relay_chain_observed_with_weak_tls():
    findings = [Finding("Weak TLS: SSLv3 enabled", "High", affected_asset="172.30.0.11"),
                Finding("SMBv1 enabled", "High", affected_asset="172.30.0.11"),
                Finding("AD/LDAP: anonymous bind", "Medium", affected_asset="172.30.0.21")]
    cs = chains.derive_chains(findings)
    relay = [c for c in cs if "relay" in c.name.lower()]
    assert relay and relay[0].proof == "observed"


def test_chains_correlation_shape():
    findings = [Finding("Privesc: SUID", "High", affected_asset="172.30.0.20"),
                Finding("Exposed service: ssh", "Info", affected_asset="172.30.0.20")]
    corr = chains.chains_to_correlation(findings)
    assert "executive_summary" in corr and "attack_paths" in corr
    assert corr["attack_paths"]


# ---- Module 3b: planner loop -----------------------------------------------
def test_planner_expands_from_web_evidence():
    g = _guard()

    def collect(profile, target):
        if profile == "discovery":
            return [Observation(target, "service", "80/tcp http")]
        if profile == "web":
            return [Observation(target, "web", "HTTP 200 :: Apache")]
        return []

    p = planner.Planner(g, collect, max_depth=4)
    run = p.run("172.30.0.10", seed_profile="discovery")
    profiles_run = [s.profile for s in run.steps if s.authorized]
    assert "discovery" in profiles_run and "web" in profiles_run


def test_planner_denies_out_of_scope_target():
    g = _guard()
    p = planner.Planner(g, lambda prof, tgt: [], max_depth=3)
    run = p.run("8.8.8.8", seed_profile="discovery")
    assert all(not s.authorized for s in run.steps)


def test_planner_respects_max_depth():
    g = _guard()

    def collect(profile, target):
        return [Observation(target, "service", "80/tcp http"),
                Observation(target, "smb", "445/tcp microsoft-ds"),
                Observation(target, "snmp", "161/tcp snmp")]

    p = planner.Planner(g, collect, max_depth=2)
    run = p.run("172.30.0.10")
    assert len([s for s in run.steps]) <= 2
    assert run.stopped_because


# ---- PoC runner: three hard gates ------------------------------------------
def test_poc_refused_when_not_armed():
    g = _guard()  # not armed
    with pytest.raises(PoCRefused, match="not armed"):
        gate_check(g, "172.30.0.20", "service_reachable")


def test_poc_refused_outside_lab_net():
    g = _guard(armed=frozenset({"poc"}))
    os.environ["AEGIS_POC_CONFIRM_ISOLATED"] = "1"
    with pytest.raises(PoCRefused, match="lab-only|not inside lab"):
        gate_check(g, "10.0.0.5", "service_reachable")


def test_poc_refused_without_isolation_attestation():
    g = _guard(armed=frozenset({"poc"}))
    os.environ.pop("AEGIS_POC_CONFIRM_ISOLATED", None)
    with pytest.raises(PoCRefused, match="isolation|isolated"):
        gate_check(g, "172.30.0.20", "service_reachable")


def test_poc_refused_for_uncatalogued_check():
    g = _guard(armed=frozenset({"poc"}))
    os.environ["AEGIS_POC_CONFIRM_ISOLATED"] = "1"
    with pytest.raises(PoCRefused, match="catalog"):
        gate_check(g, "172.30.0.20", "rm_rf_everything")


def test_poc_runs_in_lab_with_all_gates_and_fixture_prober():
    g = _guard(armed=frozenset({"poc"}))
    os.environ["AEGIS_POC_CONFIRM_ISOLATED"] = "1"
    res = verify(g, "172.30.0.20", "service_reachable",
                 prober=lambda c, t: (True, "fixture: reachable"))
    assert res.ran and res.observed
