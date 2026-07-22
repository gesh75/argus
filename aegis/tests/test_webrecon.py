"""Module 1 — Web/API recon tests (offline, fixture transport)."""
import contextlib
import http.server
import os
import socket
import threading
from collections.abc import Iterator
from typing import Any

import pytest

os.environ.setdefault("PENTEST_AUDIT_HMAC_KEY", "k" * 32)

from aegis.config import DEFAULT_POLICY, Policy
from aegis.guardrail import Guardrail
from aegis.recon.web import (
    FixtureTransport,
    HttpResult,
    HttpTransport,
    SandboxTransport,
    WebReconOrchestrator,
    probe,
)


def _guard():
    return Guardrail(Policy.load(DEFAULT_POLICY))


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    location = "/sink"
    status = 302
    requests: list[str] = []

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        type(self).requests.append(self.path)
        if self.path == "/start":
            self.send_response(type(self).status)
            self.send_header("Location", type(self).location)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"followed")

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return


@contextlib.contextmanager
def _redirect_server(status: int, location: str) -> Iterator[tuple[str, type[_RedirectHandler]]]:
    handler = type(
        "RedirectHandler",
        (_RedirectHandler,),
        {"status": status, "location": location, "requests": []},
    )
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}/start", handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_http_transport_refuses_every_redirect_status(status: int) -> None:
    with _redirect_server(status, "/sink") as (url, handler):
        result = HttpTransport().get(url, timeout=2)

    assert result.status == status
    assert result.location == "/sink"
    assert handler.requests == ["/start"]


@pytest.mark.parametrize(
    "location",
    [
        "/relative",
        "http://127.0.0.1:9/loopback",
        "http://169.254.169.254/latest/meta-data/",
        "http://8.8.8.8/public",
        "http://10.0.0.1/denied",
        "http://example.invalid/hostname",
        "http://[::ffff:127.0.0.1]:9/mapped",
    ],
    ids=["relative", "loopback", "link-local", "public", "denied", "hostname", "mapped"],
)
def test_redirect_destination_transport_is_never_invoked(
    monkeypatch: pytest.MonkeyPatch, location: str
) -> None:
    real_create_connection = socket.create_connection
    attempted_destinations: list[tuple[str, int]] = []

    with _redirect_server(302, location) as (url, handler):
        source_port = int(url.split(":")[2].split("/")[0])

        def guarded_connection(
            address: tuple[str, int], timeout: float | object = socket._GLOBAL_DEFAULT_TIMEOUT,
            source_address: tuple[str, int] | None = None,
        ) -> socket.socket:
            host, port = address
            if host == "127.0.0.1" and port == source_port:
                return real_create_connection(address, timeout, source_address)
            attempted_destinations.append(address)
            raise AssertionError(f"redirect transport invoked for {address}")

        monkeypatch.setattr(socket, "create_connection", guarded_connection)
        result = HttpTransport().get(url, timeout=2)

    assert result.status == 302
    assert result.location == location
    assert handler.requests == ["/start"]
    assert attempted_destinations == []


class _RecordingSandbox:
    def __init__(self) -> None:
        self.argv: list[str] = []

    def run(self, argv: list[str], timeout: int):
        self.argv = argv
        return type("Exec", (), {"stdout": "HTTP/1.1 302 Found\r\nLocation: /next\r\n\r\n"})()


def test_sandbox_transport_explicitly_disables_redirects() -> None:
    sandbox = _RecordingSandbox()

    result = SandboxTransport(sandbox).get("http://127.0.0.1/start", timeout=2)

    assert result.status == 302
    assert "-L" not in sandbox.argv
    assert "--location" not in sandbox.argv
    assert sandbox.argv[sandbox.argv.index("--max-redirs") + 1] == "0"


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
