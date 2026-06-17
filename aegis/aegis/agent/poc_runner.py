"""PoC verifier — lab-only, armed-only, hard-gated proof-of-concept runner.

This is the ONLY component that may emit beyond read-only recon. It exists to upgrade a
`theoretical` chain link to `observed` by safely demonstrating it — but ONLY inside the
isolated lab. Three independent gates must ALL pass or it refuses (fail-closed):

  Gate 1  armed:    'poc' must be in the guardrail's armed set (operator --arm poc)
  Gate 2  lab-net:  the target must be inside AEGIS_LAB_NET (default 172.30.0.0/24),
                    never the live/clinical scope
  Gate 3  isolated: AEGIS_POC_CONFIRM_ISOLATED=1 must be set (operator attests the lab
                    network has no route to production/clinical systems)

Even armed, it executes only vetted, non-destructive verification probes from a closed
catalog — never arbitrary payloads.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass

LAB_NET = os.environ.get("AEGIS_LAB_NET", "172.30.0.0/24")


class PoCRefused(Exception):
    """Raised (fail-closed) when any gate fails."""


@dataclass
class PoCResult:
    check: str
    target: str
    ran: bool
    observed: bool
    detail: str


# Closed catalog of non-destructive verification probes. Each is a read/connect-only check
# that confirms a condition WITHOUT exploiting it (e.g. "can this user write here?" is tested
# by checking ACL/dir perms, not by dropping a payload).
POC_CATALOG = {
    "smb_share_writable",     # confirm a share advertises write perms (no file written)
    "service_reachable",      # TCP connect only
    "anon_ldap_bind",         # bind with empty creds, read RootDSE only
}


def _in_lab(target: str) -> bool:
    try:
        net = ipaddress.ip_network(LAB_NET, strict=False)
        addr = ipaddress.ip_address(target.split(":")[0])
        # normalize IPv4-mapped IPv6 (e.g. ::ffff:172.30.0.5) so it can't dodge an IPv4 lab net
        if isinstance(addr, ipaddress.IPv6Address):
            if addr.ipv4_mapped is None:
                return False
            addr = addr.ipv4_mapped
        return addr in net
    except (ValueError, TypeError):
        return False


def gate_check(guardrail, target: str, check: str) -> None:
    """Run the three gates. Raise PoCRefused on any failure (fail-closed)."""
    if "poc" not in getattr(guardrail, "armed", frozenset()):
        raise PoCRefused("gate1: PoC runner not armed (use --arm poc)")
    if not _in_lab(target):
        raise PoCRefused(f"gate2: target {target} is not inside lab net {LAB_NET} "
                         f"— PoC is lab-only, never live/clinical scope")
    if os.environ.get("AEGIS_POC_CONFIRM_ISOLATED") != "1":
        raise PoCRefused("gate3: set AEGIS_POC_CONFIRM_ISOLATED=1 to attest lab isolation")
    if check not in POC_CATALOG:
        raise PoCRefused(f"gate-catalog: {check} not in PoC catalog (default deny)")


def verify(guardrail, target: str, check: str, *, prober=None) -> PoCResult:
    """Gate, then run a single catalog probe in the lab. `prober(check, target) -> (bool, str)`
    is injected (real connect probe in prod, fixture in tests)."""
    gate_check(guardrail, target, check)
    # Scope + catalog also re-checked by the guardrail's own host authorizer.
    guardrail.authorize_host(target, f"poc:{check}", {f"poc:{check}"})
    if prober is None:
        from .poc_probes import default_prober
        prober = default_prober
    observed, detail = prober(check, target)
    guardrail.record(f"poc:{check}", exit_code=0,
                     summary=f"poc {check} on {target}: observed={observed}")
    return PoCResult(check, target, True, observed, detail)
