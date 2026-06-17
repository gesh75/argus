"""Aegis CLI — verify | scan | audit.

Examples:
  PENTEST_AUDIT_HMAC_KEY=$(openssl rand -hex 32) \\
    python -m aegis scan 172.30.0.10 172.30.0.11 --compose ../targets/docker-compose.yml
  python -m aegis audit            # verify the HMAC audit chain
  python -m aegis scan 172.30.0.10 --dry-run   # policy test, no execution
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import DEFAULT_POLICY, Policy
from .guardrail import Guardrail, GuardrailError
from .orchestrator import Orchestrator, default_plan
from .reporting import write_all
from .sandbox import DockerSandbox, DryRunSandbox

DEFAULT_COMPOSE = Path(__file__).resolve().parents[2] / "targets" / "docker-compose.yml"


def _guard(args) -> Guardrail:
    policy = Policy.load(args.policy)
    armed = frozenset(getattr(args, "arm", None) or [])
    return Guardrail(policy, armed=armed)


def cmd_scan(args) -> int:
    guard = _guard(args)
    # Pre-validate every target through the scope guard before touching anything.
    for t in args.targets:
        d = guard.check_target(t)
        if not d.allowed:
            print(f"REFUSED target {t}: {d.reason}", file=sys.stderr)
            return 2
    sandbox = DryRunSandbox() if args.dry_run else DockerSandbox(args.compose)
    orch = Orchestrator(guard, sandbox, per_tool_timeout=args.timeout,
                        ai_provider=args.provider, ai_ollama_model=args.ollama_model)
    result = orch.run(default_plan(args.targets, args.profile))
    paths = write_all(result, args.out)
    print(f"observations={len(result.observations)} findings={len(result.findings)} "
          f"usd={guard.budget.usd:.4f}")
    for k, p in paths.items():
        print(f"  {k}: {p}")
    if result.errors:
        print(f"  guardrail denials/errors: {len(result.errors)} (see report)")
    return 0


def _refuse_if_out_of_scope(guard, target) -> bool:
    d = guard.check_target(target)
    if not d.allowed:
        print(f"REFUSED target {target}: {d.reason}", file=sys.stderr)
        return True
    return False


def cmd_host(args) -> int:
    guard = _guard(args)
    if _refuse_if_out_of_scope(guard, args.target):
        return 2
    if args.os == "windows":
        from .host.winrm_collector import DryRunWinRM, WinHostOrchestrator, WinRMCollector, WinRMCreds
        creds = WinRMCreds(user=args.user, password=args.password or "",
                           https=not args.winrm_http, verify_cert=not args.winrm_insecure)
        if args.fixture:
            from .host.win_fixtures import FixtureWinRM
            collector = FixtureWinRM()
        elif args.dry_run:
            collector = DryRunWinRM()
        else:
            collector = WinRMCollector(creds)
        orch = WinHostOrchestrator(guard, collector, per_check_timeout=args.timeout,
                                   ai_provider=args.provider, ai_ollama_model=args.ollama_model)
        result = orch.run(args.target, profile=args.profile if args.profile != "host-linux"
                          else "host-windows")
    else:
        from .host.runner import HostOrchestrator, SSHCreds
        sandbox = DockerSandbox(args.compose, service=args.ssh_service)
        creds = SSHCreds(user=args.user, password=args.password or "", port=args.port)
        orch = HostOrchestrator(guard, sandbox, creds, per_check_timeout=args.timeout,
                                ai_provider=args.provider, ai_ollama_model=args.ollama_model)
        result = orch.run(args.target, profile=args.profile)
    paths = write_all(result, args.out)
    print(f"host checks -> observations={len(result.observations)} "
          f"findings={len(result.findings)} usd={guard.budget.usd:.4f}")
    for k, p in paths.items():
        print(f"  {k}: {p}")
    for e in result.errors:
        print(f"  ! {e}")
    return 0


def cmd_ad(args) -> int:
    from .host.ad import ADOrchestrator
    guard = _guard(args)
    if _refuse_if_out_of_scope(guard, args.target):
        return 2
    sandbox = DockerSandbox(args.compose, service=args.ssh_service)
    orch = ADOrchestrator(guard, sandbox, base=args.base, per_check_timeout=args.timeout,
                          ai_provider=args.provider, ai_ollama_model=args.ollama_model)
    result = orch.run(args.target)
    paths = write_all(result, args.out)
    print(f"AD/LDAP -> observations={len(result.observations)} "
          f"findings={len(result.findings)} usd={guard.budget.usd:.4f}")
    for k, p in paths.items():
        print(f"  {k}: {p}")
    for e in result.errors:
        print(f"  ! {e}")
    return 0


def cmd_web(args) -> int:
    """Module 1 — read-only web/API recon against an in-scope target."""
    from .recon.web import SandboxTransport, WebReconOrchestrator
    guard = _guard(args)
    if _refuse_if_out_of_scope(guard, args.target):
        return 2
    # Default: probe through the sandbox container so internal-only lab nets are reachable.
    transport = None
    if not args.direct:
        transport = SandboxTransport(DockerSandbox(args.compose, service=args.service))
    orch = WebReconOrchestrator(guard, transport=transport, ai_provider=args.provider,
                                ai_ollama_model=args.ollama_model)
    result = orch.run(args.target, scheme=args.scheme, port=args.port)
    paths = write_all(result, args.out)
    print(f"web recon -> observations={len(result.observations)} "
          f"findings={len(result.findings)} usd={guard.budget.usd:.4f}")
    for k, p in paths.items():
        print(f"  {k}: {p}")
    for e in result.errors:
        print(f"  ! {e}")
    return 0


def cmd_agent(args) -> int:
    """Module 3b — agentic planner loop (read-only, guardrail-bounded)."""
    from .agent.planner import Planner
    from .orchestrator import Orchestrator, default_plan
    guard = _guard(args)
    if _refuse_if_out_of_scope(guard, args.target):
        return 2
    sandbox = DryRunSandbox() if args.dry_run else DockerSandbox(args.compose)

    def collect(profile, target):
        orch = Orchestrator(guard, sandbox, per_tool_timeout=args.timeout,
                            ai_provider="heuristic")
        return orch.run(default_plan([target], profile)).observations

    planner = Planner(guard, collect, max_depth=args.max_depth)
    run = planner.run(args.target, seed_profile=args.seed)
    print(f"agentic run -> steps={len(run.steps)} observations={len(run.observations)} "
          f"stopped={run.stopped_because!r}")
    for s in run.steps:
        mark = "✓" if s.authorized else "✗"
        print(f"  {mark} {s.profile:10} +{s.new_observations} obs  ({s.reason})")
    return 0


def cmd_audit(args) -> int:
    guard = _guard(args)
    ok = guard.audit.verify()
    print("audit chain:", "VALID ✅" if ok else "TAMPERED ❌")
    return 0 if ok else 1


def cmd_verify(args) -> int:
    """Static policy sanity check (no network)."""
    policy = Policy.load(args.policy)
    print("allowed:", [str(n) for n in policy.allowed_networks])
    print("tool default:", policy.tool_default, "| allowed:", sorted(policy.tool_allowed))
    print("budget:", policy.budget)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aegis", description="ECP Aegis pentest orchestrator")
    p.add_argument("--policy", default=str(DEFAULT_POLICY))
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="run read-only recon + AI analysis against lab targets")
    s.add_argument("targets", nargs="+")
    s.add_argument("--compose", default=str(DEFAULT_COMPOSE))
    s.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "output"))
    s.add_argument("--arm", action="append", help="explicitly arm an armed_only tool")
    s.add_argument("--profile", default="default",
                   help="scan profile: default|discovery|network|web|tls|ad-smb|snmp|vuln|full")
    s.add_argument("--provider", choices=["anthropic", "ollama", "heuristic"],
                   help="AI provider (default: auto-detect)")
    s.add_argument("--ollama-model", help="Ollama model, e.g. gemma3:4b, qwen2.5:7b-instruct")
    s.add_argument("--timeout", type=int, default=300)
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_scan)

    h = sub.add_parser("host", help="credentialed read-only host audit (Linux/SSH or Windows/WinRM)")
    h.add_argument("target")
    h.add_argument("--os", choices=["linux", "windows"], default="linux")
    h.add_argument("--user", default="pentest")
    h.add_argument("--password", default="pentest")
    h.add_argument("--port", type=int, default=22)
    h.add_argument("--profile", default="host-linux",
                   help="host-linux[-quick] | host-windows[-quick]")
    h.add_argument("--compose", default=str(DEFAULT_COMPOSE))
    h.add_argument("--ssh-service", default="sshhelper",
                   help="compose service with an SSH client used to reach Linux targets")
    h.add_argument("--winrm-http", action="store_true",
                   help="use WinRM over HTTP/5985 instead of HTTPS/5986 (NOT recommended)")
    h.add_argument("--winrm-insecure", action="store_true",
                   help="skip WinRM server-cert validation (NOT recommended)")
    h.add_argument("--dry-run", action="store_true", help="Windows: show checks without connecting")
    h.add_argument("--fixture", action="store_true",
                   help="Windows: run against a realistic vulnerable-Windows fixture (no host needed)")
    h.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "output"))
    h.add_argument("--provider", choices=["anthropic", "ollama", "heuristic"])
    h.add_argument("--ollama-model")
    h.add_argument("--timeout", type=int, default=60)
    h.set_defaults(func=cmd_host)

    ad = sub.add_parser("ad", help="read-only AD/LDAP assessment (anonymous enumeration)")
    ad.add_argument("target")
    ad.add_argument("--base", default="dc=ecp,dc=lab", help="LDAP base DN")
    ad.add_argument("--compose", default=str(DEFAULT_COMPOSE))
    ad.add_argument("--ssh-service", default="sshhelper")
    ad.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "output"))
    ad.add_argument("--provider", choices=["anthropic", "ollama", "heuristic"])
    ad.add_argument("--ollama-model")
    ad.add_argument("--timeout", type=int, default=30)
    ad.set_defaults(func=cmd_ad)

    w = sub.add_parser("web", help="read-only web/API recon (sensitive paths + API docs)")
    w.add_argument("target")
    w.add_argument("--scheme", default="http", choices=["http", "https"])
    w.add_argument("--port", type=int)
    w.add_argument("--compose", default=str(DEFAULT_COMPOSE))
    w.add_argument("--service", default="attacker",
                   help="sandbox container used to reach internal-only lab targets")
    w.add_argument("--direct", action="store_true",
                   help="probe directly from this host instead of via the sandbox")
    w.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "output"))
    w.add_argument("--provider", choices=["anthropic", "ollama", "heuristic"])
    w.add_argument("--ollama-model")
    w.set_defaults(func=cmd_web)

    ag = sub.add_parser("agent", help="agentic planner loop (read-only, guardrail-bounded)")
    ag.add_argument("target")
    ag.add_argument("--seed", default="discovery", help="seed profile")
    ag.add_argument("--max-depth", type=int, default=4)
    ag.add_argument("--compose", default=str(DEFAULT_COMPOSE))
    ag.add_argument("--timeout", type=int, default=300)
    ag.add_argument("--dry-run", action="store_true")
    ag.set_defaults(func=cmd_agent)

    a = sub.add_parser("audit", help="verify the HMAC audit chain")
    a.set_defaults(func=cmd_audit)

    v = sub.add_parser("verify", help="print loaded policy")
    v.set_defaults(func=cmd_verify)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except GuardrailError as exc:
        print(f"GUARDRAIL: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
