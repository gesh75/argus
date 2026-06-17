"""Windows host audit over WinRM (PowerShell Remoting).

Security posture (strict by default):
 - HTTPS/5986 with server-certificate validation is the DEFAULT. HTTP/5985 or
   cert-validation-off must be opted into explicitly (and is logged).
 - Credentials are passed to pywinrm only; they are NEVER written to the audit log
   (only the check key + target are logged) and are redacted from any captured output.
 - Read-only PowerShell from a closed catalog; no exploitation, no writes.
"""
from __future__ import annotations

from dataclasses import dataclass

from .. import ai_analyzer
from ..guardrail import Guardrail, GuardrailError
from ..orchestrator import ScanResult
from . import windows
from .win_parsers import parse_windows


@dataclass
class WinRMCreds:
    user: str
    password: str = ""
    https: bool = True            # 5986 + TLS by default (strict)
    port: int = 0                 # 0 -> 5986 (https) / 5985 (http)
    verify_cert: bool = True      # validate server cert by default
    transport: str = "ntlm"       # ntlm | kerberos | credssp


@dataclass
class WinExec:
    exit_code: int
    stdout: str
    stderr: str


class WinRMCollector:
    def __init__(self, creds: WinRMCreds):
        self.creds = creds

    def run_ps(self, target: str, command: str, timeout: int = 60) -> WinExec:
        try:
            import winrm  # pywinrm
        except ImportError:
            return WinExec(127, "", "pywinrm not installed (pip install pywinrm)")
        c = self.creds
        port = c.port or (5986 if c.https else 5985)
        scheme = "https" if c.https else "http"
        try:
            session = winrm.Session(
                f"{scheme}://{target}:{port}/wsman",
                auth=(c.user, c.password), transport=c.transport,
                server_cert_validation="validate" if c.verify_cert else "ignore",
                read_timeout_sec=timeout + 5, operation_timeout_sec=timeout)
            r = session.run_ps(command)
            return WinExec(r.status_code,
                           r.std_out.decode(errors="replace"),
                           r.std_err.decode(errors="replace"))
        except Exception as exc:  # noqa: BLE001 — connection/auth failures degrade gracefully
            return WinExec(255, "", f"WinRM error: {type(exc).__name__}: {exc}")


class DryRunWinRM:
    """Records intended PowerShell without connecting — offline flow demonstration."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def run_ps(self, target: str, command: str, timeout: int = 60) -> WinExec:
        self.calls.append(command)
        return WinExec(0, f"[dry-run] would run on {target}: {command[:80]}", "")


class WinHostOrchestrator:
    def __init__(self, guardrail: Guardrail, collector, per_check_timeout: int = 60,
                 ai_provider: str | None = None, ai_ollama_model: str | None = None):
        self.guard = guardrail
        self.collector = collector
        self.timeout = per_check_timeout
        self.ai_provider = ai_provider
        self.ai_ollama_model = ai_ollama_model

    def run(self, target: str, profile: str = "host-windows") -> ScanResult:
        result = ScanResult()
        keys = windows.WINDOWS_PROFILES.get(profile, windows.WINDOWS_PROFILES["host-windows"])
        for key in keys:
            check = windows.WINDOWS_CHECKS[key]
            try:
                self.guard.authorize_host(target, key, windows.WINDOWS_CATALOG)
            except GuardrailError as exc:
                result.errors.append(f"{key} {target}: DENIED {exc}")
                continue
            ex = self.collector.run_ps(target, check.ps, self.timeout)
            if ex.exit_code in (127, 255):
                result.errors.append(f"{key} {target}: WinRM unavailable/failed ({ex.stderr[:60]})")
                continue
            self.guard.record(f"win:{key}", exit_code=ex.exit_code,
                              summary=self.guard.sanitize(ex.stdout[:200]))
            result.observations.extend(
                parse_windows(check.kind, key, self.guard.sanitize(ex.stdout), target))

        result.findings = ai_analyzer.triage(result.observations, budget=self.guard.budget,
                                             provider=self.ai_provider,
                                             ollama_model=self.ai_ollama_model)
        result.correlation = ai_analyzer.correlate(result.findings, budget=self.guard.budget,
                                                   provider=self.ai_provider,
                                                   ollama_model=self.ai_ollama_model)
        self.guard.audit.write({"event": "win_host_scan_complete", "target": target,
                                "obs": len(result.observations),
                                "findings": len(result.findings)})
        return result
