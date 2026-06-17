"""Parse read-only host-audit command output into normalized Observations."""
from __future__ import annotations

from ..tools import Observation

# GTFOBins-style SUID/SGID binaries that grant escalation if set — flag these specifically.
GTFO = {"bash", "sh", "find", "vim", "nano", "less", "more", "cp", "mv", "nmap", "perl",
        "python", "python3", "awk", "env", "tar", "zip", "rsync", "dash", "ksh", "rootbash"}


def parse_host(kind: str, key: str, output: str, target: str) -> list[Observation]:
    out: list[Observation] = []
    text = output.strip()
    if not text:
        return out

    if key in ("suid", "sgid"):
        for line in text.splitlines():
            p = line.strip()
            if not p:
                continue
            name = p.rsplit("/", 1)[-1]
            if name in GTFO:
                out.append(Observation(target, "privesc",
                                       f"dangerous {key.upper()} binary: {p} (GTFOBins escalation)"))
        return out

    if key == "sudo_rights":
        for line in text.splitlines():
            low = line.lower()
            if "nopasswd" in low or "(all)" in low or "all=(all" in low:
                out.append(Observation(target, "privesc",
                                       f"sudo privilege escalation: {line.strip()[:160]}"))
        return out

    if key == "world_writable":
        for line in text.splitlines()[:20]:
            if line.strip():
                out.append(Observation(target, "privesc",
                                       f"world-writable file: {line.strip()}"))
        return out

    if key == "ssh_config":
        for line in text.splitlines():
            low = line.lower()
            if "permitrootlogin yes" in low:
                out.append(Observation(target, "config", "SSH permits root login (PermitRootLogin yes)"))
            elif "passwordauthentication yes" in low:
                out.append(Observation(target, "config", "SSH allows password authentication"))
            elif "permitemptypasswords yes" in low:
                out.append(Observation(target, "config", "SSH permits empty passwords"))
        return out

    if key == "lynis":
        for line in text.splitlines():
            s = line.strip()
            if s and "not installed" not in s.lower():
                out.append(Observation(target, "audit", s[:200]))
        return out

    # system / patch / users / network / cron — keep concise informative lines
    for line in text.splitlines()[:15]:
        s = line.strip()
        if s:
            out.append(Observation(target, kind, s[:200]))
    return out
