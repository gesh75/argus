"""Security-boundary tests for the localhost-only web console."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

os.environ.setdefault("PENTEST_AUDIT_HMAC_KEY", "k" * 32)

from aegis import web


def _client(host: str) -> TestClient:
    return TestClient(web.app, client=(host, 50000))


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "::ffff:127.0.0.1"])
def test_loopback_socket_peers_are_allowed(host: str) -> None:
    with _client(host) as client:
        response = client.get("/api/policy")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize(
    "host",
    ["192.0.2.10", "169.254.1.1", "::ffff:192.0.2.10", "testclient"],
)
def test_non_loopback_and_non_ip_socket_peers_are_denied(host: str) -> None:
    with _client(host) as client:
        response = client.get("/api/policy")

    assert response.status_code == 403
    assert response.json() == {"error": "localhost-only console"}
    assert response.headers["Cache-Control"] == "no-store"


def test_spoofed_proxy_and_host_headers_do_not_bypass_socket_peer_check() -> None:
    headers = {
        "Host": "127.0.0.1",
        "Forwarded": "for=127.0.0.1",
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
    }
    with _client("192.0.2.10") as client:
        response = client.get("/api/policy", headers=headers)

    assert response.status_code == 403


def test_forwarding_headers_are_ignored_for_a_loopback_peer() -> None:
    headers = {
        "Forwarded": "for=192.0.2.10",
        "X-Forwarded-For": "192.0.2.10",
        "X-Real-IP": "192.0.2.10",
    }
    with _client("127.0.0.1") as client:
        response = client.get("/api/policy", headers=headers)

    assert response.status_code == 200


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/api/host", {"target": "172.30.0.10", "password": "do-not-echo"}),
        ("/api/ad", {"target": "172.30.0.12"}),
    ],
)
def test_host_and_ad_live_execution_are_disabled_by_default(
    monkeypatch: pytest.MonkeyPatch, path: str, payload: dict[str, object]
) -> None:
    def unexpected_sandbox(*args: object, **kwargs: object) -> None:
        raise AssertionError("live sandbox must not be constructed")

    monkeypatch.setattr(web, "DockerSandbox", unexpected_sandbox)
    with _client("127.0.0.1") as client:
        response = client.post(path, json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "live web execution is disabled"}
    assert "do-not-echo" not in response.text


@pytest.mark.parametrize(
    "extra",
    [
        {"arm": ["masscan"]},
        {"dry_run": False},
    ],
    ids=["armed", "live"],
)
def test_scan_request_cannot_select_armed_or_live_mode(extra: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        web.ScanRequest.model_validate({"targets": ["172.30.0.10"], **extra})


def test_oversize_json_is_rejected_before_route_validation() -> None:
    oversized = "x" * (web.MAX_REQUEST_BODY_BYTES + 1)
    with _client("127.0.0.1") as client:
        response = client.post(
            "/api/scan",
            content=oversized,
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 413
    assert response.json() == {"error": "request body too large"}
    assert response.headers["Cache-Control"] == "no-store"


def test_validation_errors_do_not_echo_request_secrets() -> None:
    secret = "super-secret-password-value"
    with _client("127.0.0.1") as client:
        response = client.post(
            "/api/host",
            json={"target": ["invalid"], "password": secret},
        )

    assert response.status_code == 422
    assert response.json() == {"error": "invalid request"}
    assert secret not in response.text
