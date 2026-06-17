"""Tool execution sandbox.

DockerSandbox runs each tool inside the isolated lab's attacker container via
`docker exec` with an argv array (NEVER shell=True) and an OS-level timeout. The
container is attached only to the `--internal` ptlab network, so even if the app
layer were bypassed, there is no route off the lab subnet.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


class DockerSandbox:
    def __init__(self, compose_file: Path | str, service: str = "attacker"):
        self.compose_file = str(compose_file)
        self.service = service
        if not shutil.which("docker"):
            raise RuntimeError("docker not found on PATH")

    def run(self, argv: list[str], timeout: int) -> ExecResult:
        cmd = ["docker", "compose", "-f", self.compose_file, "exec", "-T",
               self.service, *argv]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, check=False)  # noqa: S603 (argv, no shell)
            return ExecResult(p.returncode, p.stdout, p.stderr)
        except subprocess.TimeoutExpired as exc:
            return ExecResult(124, exc.stdout or "", "timeout", timed_out=True)


class LocalSandbox:
    """Runs each tool directly on the host (argv array, NEVER shell=True).

    For AUTHORIZED off-lab recon only — e.g. scanning approved production
    devices over a VPN that the isolated lab container cannot route to. This
    intentionally has no network isolation, so it MUST be paired with a tight
    scope policy (explicit /32 allow-list + read-only tool firewall); the
    guardrail still authorizes every target and tool and writes the audit chain
    before anything here executes. Only binaries present on the host PATH run.
    """

    def __init__(self) -> None:
        if not shutil.which("nmap") and not shutil.which("fping"):
            raise RuntimeError("no recon tools on host PATH (install nmap/fping)")

    def run(self, argv: list[str], timeout: int) -> ExecResult:
        if not shutil.which(argv[0]):
            return ExecResult(127, "", f"{argv[0]}: not installed on host")
        try:
            p = subprocess.run(argv, capture_output=True, text=True,
                               timeout=timeout, check=False)  # noqa: S603 (argv, no shell)
            return ExecResult(p.returncode, p.stdout, p.stderr)
        except subprocess.TimeoutExpired as exc:
            return ExecResult(124, exc.stdout or "", "timeout", timed_out=True)


class DryRunSandbox:
    """Records argv without executing — for offline policy testing."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, argv: list[str], timeout: int) -> ExecResult:
        self.calls.append(argv)
        return ExecResult(0, f"[dry-run] would exec: {' '.join(argv)}", "")
