"""Aegis web GUI — FastAPI dashboard to launch sandbox scans and view findings.

Run:  PENTEST_AUDIT_HMAC_KEY=$(openssl rand -hex 32) \\
        uvicorn aegis.web:app --host 127.0.0.1 --port 8800
Then open http://127.0.0.1:8800  (bind localhost only — operator console).
"""
from __future__ import annotations

import threading
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

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

# Serialize scans: the HMAC audit chain must stay linear. Sync handlers run in a
# threadpool, so concurrent scans would fork the chain — one operator, one scan at a time.
_SCAN_LOCK = threading.Lock()


class ScanRequest(BaseModel):
    targets: list[str]
    dry_run: bool = True
    arm: list[str] = []
    provider: str | None = None          # anthropic | ollama | heuristic (None = auto)
    ollama_model: str | None = None      # e.g. gemma3:4b, llama3.1:8b
    profile: str = "default"             # scan profile (see orchestrator.PROFILES)


class HostRequest(BaseModel):
    target: str
    os: str = "linux"                    # linux | windows
    user: str = "pentest"
    password: str = "pentest"
    profile: str = "host-linux"
    dry_run: bool = False                # windows dry-run when no live host
    provider: str | None = None
    ollama_model: str | None = None


class ADRequest(BaseModel):
    target: str
    base: str = "dc=ecp,dc=lab"
    provider: str | None = None
    ollama_model: str | None = None


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
            if req.dry_run:
                # No real Windows host on Mac -> replay a realistic vulnerable-Windows fixture
                from .host.win_fixtures import FixtureWinRM
                collector, mode = FixtureWinRM(), "windows-fixture"
            else:
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
        guard = Guardrail(Policy.load(DEFAULT_POLICY), armed=frozenset(req.arm))
    except GuardrailError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    refused = [t for t in req.targets if not guard.check_target(t).allowed]
    if refused:
        return JSONResponse({"error": f"out-of-scope targets refused: {refused}"},
                            status_code=400)
    sandbox = DryRunSandbox() if req.dry_run else DockerSandbox(COMPOSE)
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
        "mode": "dry-run" if req.dry_run else "live",
    })
