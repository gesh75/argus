"""Module 5 — Segmentation validator (read-only, network-architect view).

Re-frames the recon data as *network-architecture* findings rather than host flaws. If a
host observed in one role/zone exposes ports that belong to a more sensitive plane
(database, management, directory, hypervisor), that's a segmentation failure — a user
subnet should not be able to reach those planes directly.

Pure inference over existing Observations — no new packets. The "reachability" signal is
"we (the scanner, sitting in the assessment VLAN) observed this open port", so anything
sensitive we can see is, by definition, reachable from where we ran.
"""
from __future__ import annotations

from ..tools import Observation

# port -> (plane, service). Ports that should never be reachable from a user/workstation VLAN.
SENSITIVE_PLANES: dict[int, tuple[str, str]] = {
    # database plane
    3306: ("database", "MySQL"), 5432: ("database", "PostgreSQL"),
    1433: ("database", "MSSQL"), 1521: ("database", "Oracle"),
    27017: ("database", "MongoDB"), 6379: ("database", "Redis"),
    9200: ("database", "Elasticsearch"), 5984: ("database", "CouchDB"),
    # management plane
    22: ("management", "SSH"), 23: ("management", "Telnet"),
    3389: ("management", "RDP"), 5985: ("management", "WinRM-HTTP"),
    5986: ("management", "WinRM-HTTPS"), 161: ("management", "SNMP"),
    623: ("management", "IPMI/BMC"), 8443: ("management", "mgmt-HTTPS"),
    9090: ("management", "Cockpit/admin"),
    # directory plane
    389: ("directory", "LDAP"), 636: ("directory", "LDAPS"),
    88: ("directory", "Kerberos"), 445: ("directory", "SMB/AD"),
    # hypervisor / infra
    902: ("hypervisor", "VMware ESXi"), 2375: ("hypervisor", "Docker API (unauth)"),
    2379: ("hypervisor", "etcd"), 10250: ("hypervisor", "kubelet"),
}


def _port_of(detail: str) -> int | None:
    head = detail.strip().split("/", 1)[0]
    return int(head) if head.isdigit() else None


def validate(observations: list[Observation], *,
             source_zone: str = "assessment VLAN") -> list[Observation]:
    """Flag sensitive-plane services reachable from the source zone."""
    out: list[Observation] = []
    seen: set[tuple[str, int]] = set()
    for o in observations:
        if o.kind not in ("service", "port"):
            continue
        port = _port_of(o.detail)
        if port is None or port not in SENSITIVE_PLANES:
            continue
        key = (o.asset, port)
        if key in seen:
            continue
        seen.add(key)
        plane, svc = SENSITIVE_PLANES[port]
        out.append(Observation(
            o.asset, "segmentation",
            f"{plane} plane reachable from {source_zone}: {svc} ({port}) open on {o.asset} "
            f"— user/assessment subnet can reach the {plane} plane directly",
            o.detail[:160]))
    return out


def matrix(observations: list[Observation]) -> dict[str, list[str]]:
    """Asset -> list of sensitive planes reachable. Compact view for reporting."""
    m: dict[str, set[str]] = {}
    for o in validate(observations):
        plane = o.detail.split(" plane reachable")[0]
        m.setdefault(o.asset, set()).add(plane)
    return {asset: sorted(planes) for asset, planes in m.items()}
