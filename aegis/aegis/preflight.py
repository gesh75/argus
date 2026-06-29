"""Pre-flight sanity checks before an un-isolated ``--sandbox local`` run (#8).

Configuration mistakes are likelier than malice: the most common way to cause harm is to
point recon at the wrong network (production, a public host, an over-broad scope). These
checks run BEFORE any packet and surface warnings so a human catches the mistake at setup
time rather than relying on runtime controls to undo it.

Best practice: "catch human error before execution starts, rather than relying on runtime
controls to fix avoidable setup mistakes" (Aikido pre-flight checks).
"""
from __future__ import annotations

import ipaddress

from .config import Policy
from .guardrail import canon_network


def check(targets: list[str], policy: Policy) -> list[str]:
    """Return human-readable warnings for an un-isolated run. Empty list = looks fine.

    Never raises on a bad target — the scope guard already rejects those; here we only
    advise. The caller decides whether to surface or hard-stop on the warnings.
    """
    warnings: list[str] = []

    for t in targets:
        try:
            net = canon_network(t)
        except ValueError:
            continue  # scope guard will reject; not our job to re-validate
        addr = net.network_address
        if addr.is_global:
            warnings.append(
                f"target {t} is a PUBLIC IP — on the un-isolated local path this sends "
                f"live packets across the internet; confirm written authorization")
        if not net.is_private and not addr.is_global and not addr.is_loopback:
            warnings.append(f"target {t} is a special-use address ({net}) — double-check intent")

    # An over-broad allow-list is dangerous specifically when there is no container boundary.
    total = sum(n.num_addresses for n in policy.allowed_networks)
    if total > 256:
        warnings.append(
            f"scope allow-list spans {total} addresses (> a /24) — tighten to the exact "
            f"hosts for off-lab recon (ideally /32 entries)")

    if policy.resolve_dns:
        warnings.append("resolve_dns is enabled — a name could resolve off-scope; prefer literal IPs")

    return warnings


def is_lab_only(policy: Policy) -> bool:
    """True if the loaded policy still only allows RFC-1918 space (i.e. likely the lab
    default, not a tightened off-lab scope) — used to flag a probable misconfiguration."""
    return bool(policy.allowed_networks) and all(
        n.subnet_of(ipaddress.ip_network("10.0.0.0/8"))
        or n.subnet_of(ipaddress.ip_network("172.16.0.0/12"))
        or n.subnet_of(ipaddress.ip_network("192.168.0.0/16"))
        for n in policy.allowed_networks)
