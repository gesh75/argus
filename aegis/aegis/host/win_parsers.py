"""Parse read-only Windows/WinRM audit output into normalized Observations."""
from __future__ import annotations

from ..tools import Observation


def parse_windows(kind: str, key: str, output: str, target: str) -> list[Observation]:
    out: list[Observation] = []
    text = (output or "").strip()
    if not text:
        return out
    low = text.lower()

    if key == "smb_signing":
        if "enablesmb1protocol" in low and "true" in low.split("enablesmb1protocol")[-1][:20]:
            out.append(Observation(target, "config", "SMBv1 protocol enabled (EnableSMB1Protocol=True)"))
        if "requiresecuritysignature" in low and \
                "false" in low.split("requiresecuritysignature")[-1][:20]:
            out.append(Observation(target, "config", "SMB signing NOT required (relay risk)"))
        return out

    if key == "always_install_elevated":
        if "1" in text.split():
            out.append(Observation(target, "privesc",
                                   "AlwaysInstallElevated enabled — any user can install as SYSTEM"))
        return out

    if key == "unquoted_services":
        for line in text.splitlines():
            s = line.strip()
            if s and "PathName" not in s and "----" not in s:
                out.append(Observation(target, "privesc", f"unquoted service path: {s[:160]}"))
        return out

    if key == "wdigest":
        if text.strip().startswith("1"):
            out.append(Observation(target, "config",
                                   "WDigest UseLogonCredential=1 — cleartext creds in LSASS"))
        return out

    if key == "uac":
        if text.strip().startswith("0"):
            out.append(Observation(target, "config", "UAC disabled (EnableLUA=0)"))
        return out

    if key == "llmnr":
        if text.strip() not in ("0", ""):
            out.append(Observation(target, "config", "LLMNR enabled — spoofing/relay primer"))
        return out

    if key == "rdp_nla":
        if text.strip().startswith("0"):
            out.append(Observation(target, "config", "RDP Network Level Authentication disabled"))
        return out

    if key == "defender":
        if "realtimeprotectionenabled" in low and \
                "false" in low.split("realtimeprotectionenabled")[-1][:20]:
            out.append(Observation(target, "config", "Defender real-time protection disabled"))
        return out

    if key == "local_admins":
        for line in text.splitlines():
            s = line.strip()
            if s and "Name" not in s and "----" not in s:
                out.append(Observation(target, "users", f"local administrator: {s[:120]}"))
        return out

    if key == "laps":
        if "true" not in low:   # AdmPwdEnabled missing/blank -> LAPS not enabled
            out.append(Observation(target, "config",
                                   "LAPS not enabled — local admin passwords may be static/shared"))
        return out

    # os_info / hotfixes — keep concise informative lines, drop header/separator noise
    for line in text.splitlines()[:12]:
        s = line.strip()
        if s and not set(s) <= set("-= ") and s not in ("HotFixID", "Name"):
            out.append(Observation(target, kind, s[:200]))
    return out
