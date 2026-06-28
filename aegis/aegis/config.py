"""Load and validate the Aegis scope/guardrail policy (scope-policy.yaml)."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY = REPO_ROOT / "targets" / "scope-policy.yaml"


@dataclass(frozen=True)
class Budget:
    max_wall_seconds: int = 3600
    max_usd: float = 5.0
    max_tokens: int = 2_000_000
    on_breach: str = "kill_and_sign"


@dataclass(frozen=True)
class Policy:
    """Immutable view of the loaded policy. Never mutate — rebuild via load()."""

    allowed_networks: tuple[ipaddress.IPv4Network, ...]
    denied_networks: tuple[ipaddress.IPv4Network, ...]
    resolve_dns: bool
    tool_default: str
    tool_allowed: frozenset[str]
    tool_armed_only: frozenset[str]
    tool_denied: frozenset[str]
    budget: Budget
    audit_key_env: str
    audit_path: Path
    audit_chained: bool
    redact_patterns: tuple[str, ...] = field(default=())

    @staticmethod
    def load(path: Path | str = DEFAULT_POLICY) -> Policy:
        data = yaml.safe_load(Path(path).read_text())
        scope = data.get("scope", {})
        fw = data.get("tool_firewall", {})
        bud = data.get("budget", {})
        aud = data.get("audit", {})
        san = data.get("output_sanitizer", {})
        audit_path = Path(aud.get("path", "aegis/output/audit.ndjson"))
        if not audit_path.is_absolute():
            audit_path = REPO_ROOT / audit_path

        def nets(key: str) -> tuple[ipaddress.IPv4Network, ...]:
            return tuple(
                ipaddress.ip_network(c, strict=False) for c in scope.get(key, [])
            )

        return Policy(
            allowed_networks=nets("allowed_cidrs"),
            denied_networks=nets("denied_cidrs"),
            resolve_dns=bool(scope.get("resolve_dns", False)),
            tool_default=fw.get("default", "deny"),
            tool_allowed=frozenset(fw.get("allowed", [])),
            tool_armed_only=frozenset(fw.get("armed_only", [])),
            tool_denied=frozenset(fw.get("denied", [])),
            budget=Budget(
                max_wall_seconds=int(bud.get("max_wall_seconds", 3600)),
                max_usd=float(bud.get("max_usd", 5.0)),
                max_tokens=int(bud.get("max_tokens", 2_000_000)),
                on_breach=bud.get("on_breach", "kill_and_sign"),
            ),
            audit_key_env=aud.get("key_env", "PENTEST_AUDIT_HMAC_KEY"),
            audit_path=audit_path,
            audit_chained=bool(aud.get("chained", True)),
            redact_patterns=tuple(san.get("redact_patterns", [])),
        )
