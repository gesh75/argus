"""Security-boundary tests for the localhost-only web console."""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Iterable

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

os.environ.setdefault("PENTEST_AUDIT_HMAC_KEY", "k" * 32)

from aegis import web


def _client(host: str) -> TestClient:
    return TestClient(web.app, client=(host, 50000))


def _post_body_chunks(
    chunks: Iterable[bytes], *, headers: Iterable[tuple[bytes, bytes]] = ()
) -> tuple[int, dict[str, str]]:
    """Drive the real ASGI app without an HTTP client rewriting body headers."""
    body_chunks = tuple(chunks)

    async def invoke() -> tuple[int, dict[str, str]]:
        messages = iter(
            {
                "type": "http.request",
                "body": chunk,
                "more_body": index < len(body_chunks) - 1,
            }
            for index, chunk in enumerate(body_chunks)
        )
        sent: list[dict[str, object]] = []

        async def receive() -> dict[str, object]:
            return next(messages)

        async def send(message: dict[str, object]) -> None:
            sent.append(message)

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/api/scan",
            "raw_path": b"/api/scan",
            "query_string": b"",
            "headers": ((b"content-type", b"application/json"), *tuple(headers)),
            "client": ("127.0.0.1", 50000),
            "server": ("testserver", 80),
            "root_path": "",
        }
        await web.app(scope, receive, send)
        start = next(message for message in sent if message["type"] == "http.response.start")
        body = b"".join(
            message.get("body", b"")
            for message in sent
            if message["type"] == "http.response.body"
        )
        return int(start["status"]), json.loads(body)

    return asyncio.run(invoke())


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


def test_oversized_stream_without_content_length_is_rejected() -> None:
    status, body = _post_body_chunks(
        (b"x" * web.MAX_REQUEST_BODY_BYTES, b"x")
    )

    assert status == 413
    assert body == {"error": "request body too large"}


def test_chunked_body_crossing_limit_is_rejected() -> None:
    status, body = _post_body_chunks(
        (b"x" * 32768, b"x" * 32768, b"x"),
        headers=((b"transfer-encoding", b"chunked"),),
    )

    assert status == 413
    assert body == {"error": "request body too large"}


def test_body_limit_ignores_false_small_content_length() -> None:
    status, body = _post_body_chunks(
        (b"x" * web.MAX_REQUEST_BODY_BYTES, b"x"),
        headers=((b"content-length", b"1"),),
    )

    assert status == 413
    assert body == {"error": "request body too large"}


def test_exactly_64_kib_body_reaches_route_validation() -> None:
    status, body = _post_body_chunks((b"x" * web.MAX_REQUEST_BODY_BYTES,))

    assert status == 422
    assert body == {"error": "invalid request"}


def test_64_kib_plus_one_body_is_rejected() -> None:
    status, body = _post_body_chunks((b"x" * (web.MAX_REQUEST_BODY_BYTES + 1),))

    assert status == 413
    assert body == {"error": "request body too large"}


def test_validation_errors_do_not_echo_request_secrets() -> None:
    secret = "super-secret-password-value"  # noqa: S105 - synthetic non-production fixture
    with _client("127.0.0.1") as client:
        response = client.post(
            "/api/host",
            json={"target": ["invalid"], "password": secret},
        )

    assert response.status_code == 422
    assert response.json() == {"error": "invalid request"}
    assert secret not in response.text
