"""Host-audit orchestrator — credentialed SSH collection via the sandbox attacker box.

Collection runs as: docker exec attacker -> sshpass ssh user@target '<read-only cmd>'.
Aegis never touches the target directly; everything is mediated by the isolated sandbox,
so the same network boundary holds. Reuses the AI analyzer + reporting from the main flow.
"""
from __future__ import annotations

from dataclasses import dataclass

from .. import ai_analyzer
from ..guardrail import Guardrail, GuardrailError
from ..orchestrator import ScanResult
from . import audits
from .parsers import parse_host


@dataclass
class SSHCreds:
    user: str
    password: str = ""
    port: int = 22


class HostOrchestrator:
    """Runs read-only host-audit checks against one target over SSH (via the sandbox)."""

    def __init__(self, guardrail: Guardrail, sandbox, creds: SSHCreds,
                 per_check_timeout: int = 60, ai_provider: str | None = None,
                 ai_ollama_model: str | None = None):
        self.guard = guardrail
        self.sandbox = sandbox
        self.creds = creds
        self.timeout = per_check_timeout
        self.ai_provider = ai_provider
        self.ai_ollama_model = ai_ollama_model

    def _ssh_argv(self, target: str, command: str) -> list[str]:
        return ["sshpass", "-p", self.creds.password, "ssh",
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=8", "-p", str(self.creds.port),
                f"{self.creds.user}@{target}", command]

    def run(self, target: str, profile: str = "host-linux") -> ScanResult:
        result = ScanResult()
        keys = audits.HOST_PROFILES.get(profile, audits.HOST_PROFILES["host-linux"])
        for key in keys:
            check = audits.LINUX_CHECKS[key]
            try:
                self.guard.authorize_host(target, key, audits.LINUX_CATALOG)
            except GuardrailError as exc:
                result.errors.append(f"{key} {target}: DENIED {exc}")
                continue
            argv = self._ssh_argv(target, check.command)
            ex = self.sandbox.run(argv, timeout=self.timeout)
            if ex.exit_code in (5, 255):  # ssh auth/connection failure
                result.errors.append(f"{key} {target}: SSH connection/auth failed")
                continue
            self.guard.record(f"host:{key}", exit_code=ex.exit_code,
                              summary=self.guard.sanitize(ex.stdout[:200]))
            result.observations.extend(
                parse_host(check.kind, key, self.guard.sanitize(ex.stdout), target))

        result.findings = ai_analyzer.triage(result.observations, budget=self.guard.budget,
                                             provider=self.ai_provider,
                                             ollama_model=self.ai_ollama_model)
        result.correlation = ai_analyzer.correlate(result.findings, budget=self.guard.budget,
                                                   provider=self.ai_provider,
                                                   ollama_model=self.ai_ollama_model)
        self.guard.audit.write({"event": "host_scan_complete", "target": target,
                                "obs": len(result.observations),
                                "findings": len(result.findings)})
        return result
