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


class DryRunSandbox:
    """Records argv without executing — for offline policy testing."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, argv: list[str], timeout: int) -> ExecResult:
        self.calls.append(argv)
        return ExecResult(0, f"[dry-run] would exec: {' '.join(argv)}", "")
