"""Tool execution sandbox.

DockerSandbox runs each tool inside the isolated lab's attacker container via
`docker exec` with an argv array (NEVER shell=True) and an OS-level timeout. The
container is attached only to the `--internal` ptlab network, so even if the app
layer were bypassed, there is no route off the lab subnet.

LocalSandbox is the deliberate exception: it runs tools directly on the host with
NO network isolation, for AUTHORIZED off-lab recon only. Because it loses the
container boundary, it compensates explicitly — a scrubbed environment (so host
secrets like the audit signing key never reach a tool) and process-group teardown
on timeout (so no orphaned packets outlive the budget). See the class docstring.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


def _exec_argv(argv: list[str], timeout: int,
               env: dict[str, str] | None = None) -> ExecResult:
    """Run argv (NEVER shell=True) with an OS-level timeout.

    Spawns the child in its own session/process group (start_new_session) so a
    timeout tears down the WHOLE tree — tools like testssl.sh and sqlmap fork
    helpers that a plain run(timeout=) would orphan, leaving them sending packets
    after the budget said stop. `env=None` inherits the parent environment (used
    by DockerSandbox, whose container never sees it anyway); LocalSandbox passes a
    scrubbed allowlist.
    """
    try:
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, env=env, start_new_session=True)  # noqa: S603 (argv, no shell)
    except FileNotFoundError as exc:
        return ExecResult(127, "", str(exc))
    try:
        out, err = p.communicate(timeout=timeout)
        return ExecResult(p.returncode, out, err)
    except subprocess.TimeoutExpired:
        # Kill the entire process group, not just the direct child.
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            p.kill()
        out, err = p.communicate()
        return ExecResult(124, out or "", "timeout", timed_out=True)


class DockerSandbox:
    def __init__(self, compose_file: Path | str, service: str = "attacker"):
        self.compose_file = str(compose_file)
        self.service = service
        if not shutil.which("docker"):
            raise RuntimeError("docker not found on PATH")

    def run(self, argv: list[str], timeout: int) -> ExecResult:
        cmd = ["docker", "compose", "-f", self.compose_file, "exec", "-T",
               self.service, *argv]
        return _exec_argv(cmd, timeout)


# Minimal environment for host-spawned tools. This is an ALLOWLIST, not a
# copy-then-delete denylist: secrets that the wrapper holds (the audit HMAC
# signing key, ANTHROPIC_API_KEY, and anything else) can never be inherited by a
# recon binary because they are simply not in this set. DockerSandbox gets this
# for free — scope-policy.yaml keeps the key out of the container — but
# LocalSandbox must reconstruct it. Recon tools only need PATH + locale/HOME.
_LOCAL_ENV_ALLOWLIST = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LANGUAGE",
                        "LC_ALL", "LC_CTYPE", "TERM", "TMPDIR")


class LocalSandbox:
    """Runs each tool directly on the host (argv array, NEVER shell=True).

    For AUTHORIZED off-lab recon only — e.g. scanning approved production
    devices over a VPN that the isolated lab container cannot route to. This
    intentionally has no network isolation, so it MUST be paired with a tight
    scope policy (explicit /32 allow-list + read-only tool firewall); the
    guardrail still authorizes every target and tool and writes the audit chain
    before anything here executes. Only binaries present on the host PATH run.

    Because the container boundary is gone, two host secrets that DockerSandbox
    never exposed must be scrubbed here: the child env is rebuilt from a minimal
    allowlist (see _LOCAL_ENV_ALLOWLIST) so the audit signing key (`audit_key_env`)
    and API keys cannot leak into a tool that reads /proc/self/environ.
    """

    def __init__(self, audit_key_env: str = "PENTEST_AUDIT_HMAC_KEY") -> None:
        self._audit_key_env = audit_key_env
        if not shutil.which("nmap") and not shutil.which("fping"):
            raise RuntimeError("no recon tools on host PATH (install nmap/fping)")

    def _safe_env(self) -> dict[str, str]:
        env = {k: os.environ[k] for k in _LOCAL_ENV_ALLOWLIST if k in os.environ}
        # Defensive: drop the signing key even if the allowlist is later widened.
        env.pop(self._audit_key_env, None)
        return env

    def run(self, argv: list[str], timeout: int) -> ExecResult:
        if not argv:
            return ExecResult(127, "", "empty argv")
        if not shutil.which(argv[0]):
            return ExecResult(127, "", f"{argv[0]}: not installed on host")
        return _exec_argv(argv, timeout, env=self._safe_env())


class DryRunSandbox:
    """Records argv without executing — for offline policy testing."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, argv: list[str], timeout: int) -> ExecResult:
        self.calls.append(argv)
        return ExecResult(0, f"[dry-run] would exec: {' '.join(argv)}", "")
