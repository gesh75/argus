"""Generate an nftables egress allow-list from the scope policy (#7).

``--sandbox local`` removes the container's network boundary, leaving the app-layer scope
guard as the only thing between the tool runner and the wider network. A kernel firewall
restores defense-in-depth: permit egress ONLY to the policy's allowed CIDRs (minus the
denied ones), drop everything else. Apply this on the disposable recon host BEFORE an
off-lab run — a guardrail bug or an HTTP redirect then still cannot reach an out-of-scope
host, because the packet never leaves the box.

Best practice: enforce scope at the network layer, not just the app (Aikido); exclusions
beat authorizations (IntegSec agentic-pentest proxy). This emits the ruleset; the operator
applies it with ``nft -f`` (it does not touch the live firewall itself).
"""
from __future__ import annotations

from .config import Policy

_TABLE = "argus_egress"


def nftables_ruleset(policy: Policy) -> str:
    """Render a deterministic nftables script: allow established + loopback + the policy's
    in-scope networks (denied ones carved out first), default-drop new egress."""
    allowed = [n for n in policy.allowed_networks]
    denied = [str(d) for d in policy.denied_networks]
    lines = [
        "#!/usr/sbin/nft -f",
        "# Argus egress allow-list — generated from the scope policy. Apply on the",
        "# disposable recon host before `--sandbox local`. Fail-closed: default drop.",
        f"add table inet {_TABLE}",
        f"delete table inet {_TABLE}",
        f"table inet {_TABLE} {{",
        "  chain output {",
        "    type filter hook output priority 0; policy drop;",
        "    ct state established,related accept",
        "    oifname \"lo\" accept",
    ]
    # Denied carve-outs first so a /32 deny inside an allowed /24 wins (firewall semantics).
    for d in denied:
        lines.append(f"    ip daddr {d} drop")
    if allowed:
        joined = ", ".join(str(a) for a in allowed)
        lines.append(f"    ip daddr {{ {joined} }} accept")
    lines += [
        "    # everything else: dropped by chain policy",
        "  }",
        "}",
    ]
    return "\n".join(lines) + "\n"
