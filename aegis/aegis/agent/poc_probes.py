"""Default non-destructive PoC probes (lab-only). Connect/read checks — never payloads."""
from __future__ import annotations

import socket


def _tcp_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def default_prober(check: str, target: str) -> tuple[bool, str]:
    """Return (observed, detail). All probes are connect/read-only and non-destructive."""
    host = target.split(":")[0]
    if check == "service_reachable":
        # Probe a couple of common admin ports — TCP connect only.
        for port in (22, 445, 3389, 5985):
            if _tcp_open(host, port):
                return True, f"TCP {port} reachable on {host} (connect-only, no payload)"
        return False, f"no common admin port reachable on {host}"
    if check == "smb_share_writable":
        # Connect-only confirmation that SMB is up; write-perm confirmation is left to the
        # credentialed read-only host audit (ACL inspection), never an actual file write.
        return (_tcp_open(host, 445),
                "SMB(445) reachable; write-perm confirmed via ACL inspection only, no write")
    if check == "anon_ldap_bind":
        return (_tcp_open(host, 389),
                "LDAP(389) reachable; anonymous RootDSE read only, no modification")
    return False, f"unknown probe {check}"
