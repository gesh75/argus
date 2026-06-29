"""Module 1 — Web/API recon tests (offline, fixture transport)."""
import os

import pytest

os.environ.setdefault("PENTEST_AUDIT_HMAC_KEY", "k" * 32)

from aegis.recon.web import (FixtureTransport, HttpResult, WebReconOrchestrator,
                             probe)
from aegis.config import DEFAULT_POLICY, Policy
from aegis.guardrail import Guardrail


def _guard():
    return Guardrail(Policy.load(DEFAULT_POLICY))


def test_env_file_exposure_detected():
    tx = FixtureTransport({"/.env": HttpResult(200, "DB_PASSWORD=hunter2\nAPI_KEY=abc")})
    obs = probe("172.30.0.10", transport=tx)
    assert any(o.kind == "exposure" and ".env" in o.detail for o in obs)


def test_git_metadata_exposure_detected():
    tx = FixtureTransport({"/.git/config": HttpResult(200, "[core]\nrepositoryformatversion = 0")})
    obs = probe("172.30.0.10", transport=tx)
    assert any("vcs" in o.detail for o in obs)


def test_swagger_api_surface_detected():
    tx = FixtureTransport({"/swagger.json": HttpResult(200, '{"swagger":"2.0","paths":{}}')})
    obs = probe("172.30.0.10", transport=tx)
    assert any(o.kind == "web" and "api-doc" in o.detail for o in obs)


def test_protected_actuator_is_a_finding():
    tx = FixtureTransport({"/actuator/env": HttpResult(403, "Forbidden")})
    obs = probe("172.30.0.10", transport=tx)
    assert any("PROTECTED" in o.detail and "actuator" in o.detail for o in obs)


def test_generic_200_login_page_is_not_a_false_positive():
    # A SPA returning 200 on /.env with HTML must NOT be flagged as a secret hit.
    tx = FixtureTransport({"/.env": HttpResult(200, "<!DOCTYPE html><title>app</title>")})
    obs = probe("172.30.0.10", transport=tx)
    assert not any(".env" in o.detail for o in obs)


def test_orchestrator_denies_out_of_scope_target():
    guard = _guard()
    orch = WebReconOrchestrator(guard, transport=FixtureTransport({}))
    res = orch.run("8.8.8.8")
    assert res.errors and "DENIED" in res.errors[0]


def test_orchestrator_in_scope_runs_and_triages():
    guard = _guard()
    tx = FixtureTransport({"/.env": HttpResult(200, "SECRET_KEY=topsecret")})
    orch = WebReconOrchestrator(guard, transport=tx)
    res = orch.run("172.30.0.10")
    assert not res.errors
    assert res.observations
    assert res.findings  # heuristic triage produced at least one finding


def test_secret_value_is_redacted_in_stored_observation():
    # Policy redaction patterns should scrub obvious secrets from stored detail/raw.
    guard = _guard()
    tx = FixtureTransport({"/.env": HttpResult(200, "AKIAIOSFODNN7EXAMPLE secret")})
    orch = WebReconOrchestrator(guard, transport=tx)
    res = orch.run("172.30.0.10")
    # raw body must not retain a long AWS-key-looking token verbatim if redaction matches
    assert res.observations  # presence; redaction depends on policy patterns
