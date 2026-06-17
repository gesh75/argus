"""Credentialed, READ-ONLY host-audit command catalog (Linux first).

Each check is a vetted constant shell command run on the target over SSH. All are
read-only enumeration (LinPEAS/Lynis-style) — no exploitation, no writes, no state change.
Catalog is a closed allowlist enforced by Guardrail.authorize_host().
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HostCheck:
    key: str
    profile: str
    kind: str          # system | users | privesc | patch | network | config | audit
    command: str       # trusted, read-only remote shell command


LINUX_CHECKS: dict[str, HostCheck] = {
    "os_release": HostCheck("os_release", "host-linux", "system",
        "cat /etc/os-release 2>/dev/null; uname -a"),
    "kernel": HostCheck("kernel", "host-linux", "patch",
        "uname -r; cat /proc/version 2>/dev/null"),
    "passwd": HostCheck("passwd", "host-linux", "users",
        "awk -F: '($3==0)||($3>=1000){print $1\" uid=\"$3\" shell=\"$7}' /etc/passwd"),
    "sudo_rights": HostCheck("sudo_rights", "host-linux", "privesc",
        "sudo -n -l 2>/dev/null; grep -E 'NOPASSWD|ALL=' /etc/sudoers 2>/dev/null"),
    "suid": HostCheck("suid", "host-linux", "privesc",
        "find / -perm -4000 -type f 2>/dev/null"),
    "sgid": HostCheck("sgid", "host-linux", "privesc",
        "find / -perm -2000 -type f 2>/dev/null | head -40"),
    "world_writable": HostCheck("world_writable", "host-linux", "privesc",
        "find / -xdev -perm -0002 -type f -not -path '/proc/*' 2>/dev/null | head -40"),
    "cron": HostCheck("cron", "host-linux", "privesc",
        "ls -la /etc/cron* /var/spool/cron 2>/dev/null"),
    "listening": HostCheck("listening", "host-linux", "network",
        "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"),
    "ssh_config": HostCheck("ssh_config", "host-linux", "config",
        "(sshd -T 2>/dev/null || cat /etc/ssh/sshd_config 2>/dev/null) | "
        "grep -Ei 'permitrootlogin|passwordauthentication|permitempty'"),
    "packages": HostCheck("packages", "host-linux", "patch",
        "(dpkg -l 2>/dev/null | wc -l) ; (rpm -qa 2>/dev/null | wc -l)"),
    "lynis": HostCheck("lynis", "host-linux", "audit",
        "command -v lynis >/dev/null && lynis audit system --quick --quiet --no-colors 2>/dev/null "
        "| grep -Ei 'warning|suggestion' | head -40 || echo 'lynis not installed'"),
}

HOST_PROFILES: dict[str, list[str]] = {
    "host-linux": ["os_release", "kernel", "passwd", "sudo_rights", "suid", "sgid",
                   "world_writable", "cron", "listening", "ssh_config", "packages", "lynis"],
    "host-linux-quick": ["os_release", "sudo_rights", "suid", "ssh_config", "listening"],
}

LINUX_CATALOG: set[str] = set(LINUX_CHECKS)
