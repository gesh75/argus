"""Argus localhost-only web console.

Run:  PENTEST_AUDIT_HMAC_KEY=$(openssl rand -hex 32) \\
        uvicorn aegis.web:app --host 127.0.0.1 --port 8800
Then open http://127.0.0.1:8800.

The application independently enforces a loopback ASGI socket peer. Proxy and Host
headers are never used for authorization. Live execution is disabled unless the server
starts with ``ARGUS_WEB_LIVE_ENABLED=1``; request JSON cannot select live or armed mode.
"""
from __future__ import annotations

import ipaddress
import os
import threading
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import DEFAULT_POLICY, Policy
from .guardrail import Guardrail, GuardrailError
from .orchestrator import Orchestrator, default_plan
from .reporting import write_all
from .sandbox import DockerSandbox, DryRunSandbox

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT.parent / "targets" / "docker-compose.yml"
OUT = ROOT / "output"
STATIC = Path(__file__).resolve().parent / "static" / "index.html"

app = FastAPI(title="Argus", version="0.1.0")

MAX_REQUEST_BODY_BYTES = 64 * 1024
WEB_LIVE_ENABLED = os.environ.get("ARGUS_WEB_LIVE_ENABLED", "").strip().lower() in {
    "1",
    "true",
    "yes",
}

_CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
    "script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'"
)

# Serialize scans: the HMAC audit chain must stay linear. Sync handlers run in a
# threadpool, so concurrent scans would fork the chain — one operator, one scan at a time.
_SCAN_LOCK = threading.Lock()


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ScanRequest(StrictRequest):
    targets: list[str] = Field(min_length=1, max_length=64)
    provider: str | None = None          # anthropic | ollama | heuristic (None = auto)
    ollama_model: str | None = None      # e.g. gemma3:4b, llama3.1:8b
    profile: str = Field(default="default", min_length=1, max_length=64)


class HostRequest(StrictRequest):
    target: str = Field(min_length=1, max_length=255)
    os: str = Field(default="linux", pattern="^(linux|windows)$")
    user: str = Field(default="pentest", min_length=1, max_length=128)
    password: str = Field(default="pentest", max_length=1024)  # noqa: S105
    profile: str = Field(default="host-linux", min_length=1, max_length=64)
    provider: str | None = None
    ollama_model: str | None = None


class ADRequest(StrictRequest):
    target: str = Field(min_length=1, max_length=255)
    base: str = Field(default="dc=ecp,dc=lab", min_length=1, max_length=512)
    provider: str | None = None
    ollama_model: str | None = None


class RequestBodyLimitMiddleware:
    """Bound API request bodies by counting ASGI bytes before route parsing."""

    _BODY_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if (
            scope["type"] != "http"
            or not scope.get("path", "").startswith("/api/")
            or scope.get("method", "GET").upper() not in self._BODY_METHODS
        ):
            await self.app(scope, receive, send)
            return

        content_length = next(
            (
                value
                for name, value in scope.get("headers", ())
                if name.lower() == b"content-length"
            ),
            None,
        )
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError:
                await _error("invalid content length", 400)(scope, receive, send)
                return
            if declared_size < 0:
                await _error("invalid content length", 400)(scope, receive, send)
                return
            if declared_size > self.max_body_bytes:
                await _error("request body too large", 413)(scope, receive, send)
                return

        buffered: list[Message] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                buffered.append(message)
                break

            total += len(message.get("body", b""))
            if total > self.max_body_bytes:
                await _error("request body too large", 413)(scope, receive, send)
                return

            buffered.append(message)
            if not message.get("more_body", False):
                break

        buffered_messages = iter(buffered)

        async def replay_receive() -> Message:
            try:
                return next(buffered_messages)
            except StopIteration:
                return await receive()

        await self.app(scope, replay_receive, send)


app.add_middleware(
    RequestBodyLimitMiddleware,
    max_body_bytes=MAX_REQUEST_BODY_BYTES,
)


def _is_loopback_peer(host: str) -> bool:
    """Accept only an IP loopback from the actual ASGI socket peer."""
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback


def _error(message: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        {"error": message},
        status_code=status_code,
        headers={"Cache-Control": "no-store"},
    )


@app.middleware("http")
async def enforce_local_console_boundary(request: Request, call_next):  # noqa: ANN001
    """Enforce the deployment boundary from the socket peer, never proxy headers."""
    peer = request.scope.get("client")
    peer_host = peer[0] if peer else ""
    if not _is_loopback_peer(peer_host):
        return _error("localhost-only console", 403)

    response = await call_next(request)
    response.headers["Content-Security-Policy"] = _CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(_request: Request, _exc: RequestValidationError) -> JSONResponse:
    """Do not reflect credentials, tokens, or complete request bodies."""
    return _error("invalid request", 422)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return STATIC.read_text()


@app.get("/architecture", response_class=HTMLResponse)
def architecture() -> str:
    return (STATIC.parent / "architecture.html").read_text()


@app.get("/api/policy")
def policy() -> dict:
    from .ai_analyzer import resolve_provider
    from .tools import PROFILES, REGISTRY
    p = Policy.load(DEFAULT_POLICY)
    return {"ai_provider": resolve_provider(),
            "allowed": [str(n) for n in p.allowed_networks],
            "tool_default": p.tool_default,
            "allowed_tools": sorted(p.tool_allowed),
            "armed_only": sorted(p.tool_armed_only),
            "profiles": {k: v for k, v in PROFILES.items()},
            "tool_count": len(REGISTRY),
            "live_enabled": WEB_LIVE_ENABLED,
            "deployment": "localhost-only; proxy headers ignored",
            "budget": {"usd": p.budget.max_usd, "wall_s": p.budget.max_wall_seconds}}


@app.get("/api/models")
def models() -> dict:
    from .ai_analyzer import available_providers
    return available_providers()


def _result_payload(result, guard, mode: str) -> dict:
    from .reporting import collapse_errors
    return {"findings": [asdict(f) for f in result.findings],
            "correlation": result.correlation,
            "errors": collapse_errors(result.errors),
            "usd": round(guard.budget.usd, 4),
            "audit_valid": guard.audit.verify(), "mode": mode}


@app.post("/api/host")
def host(req: HostRequest) -> JSONResponse:
    from .host.ad import ADOrchestrator  # noqa: F401 (kept local for symmetry)
    if not WEB_LIVE_ENABLED:
        return _error("live web execution is disabled", 403)
    try:
        guard = Guardrail(Policy.load(DEFAULT_POLICY))
    except GuardrailError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    if not guard.check_target(req.target).allowed:
        return JSONResponse({"error": f"out-of-scope target refused: {req.target}"},
                            status_code=400)
    with _SCAN_LOCK:
        if req.os == "windows":
            from .host.winrm_collector import WinHostOrchestrator, WinRMCollector, WinRMCreds
            collector = WinRMCollector(WinRMCreds(user=req.user, password=req.password))
            mode = "windows-live"
            orch = WinHostOrchestrator(guard, collector, ai_provider=req.provider,
                                       ai_ollama_model=req.ollama_model)
            prof = req.profile if req.profile.startswith("host-windows") else "host-windows"
            result = orch.run(req.target, profile=prof)
        else:
            from .host.runner import HostOrchestrator, SSHCreds
            sandbox = DockerSandbox(COMPOSE, service="sshhelper")
            orch = HostOrchestrator(guard, sandbox,
                                    SSHCreds(user=req.user, password=req.password),
                                    ai_provider=req.provider, ai_ollama_model=req.ollama_model)
            prof = req.profile if req.profile.startswith("host-linux") else "host-linux"
            result = orch.run(req.target, profile=prof)
            mode = "linux-live"
        write_all(result, OUT)
        return JSONResponse(_result_payload(result, guard, mode))


@app.post("/api/ad")
def ad(req: ADRequest) -> JSONResponse:
    from .host.ad import ADOrchestrator
    if not WEB_LIVE_ENABLED:
        return _error("live web execution is disabled", 403)
    try:
        guard = Guardrail(Policy.load(DEFAULT_POLICY))
    except GuardrailError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    if not guard.check_target(req.target).allowed:
        return JSONResponse({"error": f"out-of-scope target refused: {req.target}"},
                            status_code=400)
    with _SCAN_LOCK:
        sandbox = DockerSandbox(COMPOSE, service="sshhelper")
        orch = ADOrchestrator(guard, sandbox, base=req.base, ai_provider=req.provider,
                              ai_ollama_model=req.ollama_model)
        result = orch.run(req.target)
        write_all(result, OUT)
        return JSONResponse(_result_payload(result, guard, "ad-live"))


@app.post("/api/scan")
def scan(req: ScanRequest) -> JSONResponse:
    try:
        guard = Guardrail(Policy.load(DEFAULT_POLICY))
    except GuardrailError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    refused = [t for t in req.targets if not guard.check_target(t).allowed]
    if refused:
        return JSONResponse({"error": f"out-of-scope targets refused: {refused}"},
                            status_code=400)
    live_enabled = WEB_LIVE_ENABLED
    sandbox = DockerSandbox(COMPOSE) if live_enabled else DryRunSandbox()
    with _SCAN_LOCK:
        orch = Orchestrator(guard, sandbox, ai_provider=req.provider,
                            ai_ollama_model=req.ollama_model)
        result = orch.run(default_plan(req.targets, req.profile))
        write_all(result, OUT)
        audit_valid = guard.audit.verify()
    from .reporting import collapse_errors
    return JSONResponse({
        "findings": [asdict(f) for f in result.findings],
        "correlation": result.correlation,
        "errors": collapse_errors(result.errors),
        "usd": round(guard.budget.usd, 4),
        "audit_valid": audit_valid,
        "mode": "live" if live_enabled else "dry-run",
    })
