"""Credentialed, READ-ONLY Windows host-audit catalog (run over WinRM).

Every check is a vetted, read-only PowerShell command — config/state enumeration only,
no exploitation, no writes (PrivescCheck `-Audit` / CIS-style). Closed allowlist enforced
by Guardrail.authorize_host(). Live use requires a real Windows host reachable over WinRM
(HTTPS/5986 strongly preferred); parsers are unit-tested against sample output.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WinCheck:
    key: str
    profile: str
    kind: str          # system | patch | privesc | config | users | audit
    ps: str            # read-only PowerShell


WINDOWS_CHECKS: dict[str, WinCheck] = {
    "os_info": WinCheck("os_info", "host-windows", "system",
        "Get-CimInstance Win32_OperatingSystem | "
        "Select Caption,Version,BuildNumber,OSArchitecture | Format-List"),
    "hotfixes": WinCheck("hotfixes", "host-windows", "patch",
        "(Get-HotFix | Measure-Object).Count; "
        "Get-HotFix | Sort InstalledOn -Desc | Select -First 5 HotFixID,InstalledOn"),
    "local_admins": WinCheck("local_admins", "host-windows", "users",
        "Get-LocalGroupMember -Group Administrators | Select Name,PrincipalSource"),
    "smb_signing": WinCheck("smb_signing", "host-windows", "config",
        "Get-SmbServerConfiguration | "
        "Select EnableSMB1Protocol,RequireSecuritySignature,EnableSecuritySignature | Format-List"),
    "llmnr": WinCheck("llmnr", "host-windows", "config",
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' "
        "-EA SilentlyContinue).EnableMulticast"),
    "uac": WinCheck("uac", "host-windows", "config",
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System')"
        ".EnableLUA"),
    "always_install_elevated": WinCheck("always_install_elevated", "host-windows", "privesc",
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' "
        "-EA SilentlyContinue).AlwaysInstallElevated; "
        "(Get-ItemProperty 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' "
        "-EA SilentlyContinue).AlwaysInstallElevated"),
    "unquoted_services": WinCheck("unquoted_services", "host-windows", "privesc",
        "Get-CimInstance Win32_Service | Where-Object { $_.PathName -and "
        "$_.PathName -notmatch '^\\\"' -and $_.PathName -match ' ' -and "
        "$_.PathName -notmatch 'C:\\\\Windows' } | Select Name,PathName"),
    "defender": WinCheck("defender", "host-windows", "config",
        "Get-MpComputerStatus | Select AMRunningMode,RealTimeProtectionEnabled,"
        "AntivirusEnabled,AntispywareEnabled | Format-List"),
    "wdigest": WinCheck("wdigest", "host-windows", "config",
        "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
        "-EA SilentlyContinue).UseLogonCredential"),
    "rdp_nla": WinCheck("rdp_nla", "host-windows", "config",
        "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\"
        "WinStations\\RDP-Tcp' -EA SilentlyContinue).UserAuthentication"),
    "laps": WinCheck("laps", "host-windows", "config",
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd' "
        "-EA SilentlyContinue | Select AdmPwdEnabled"),
}

WINDOWS_PROFILES: dict[str, list[str]] = {
    "host-windows": list(WINDOWS_CHECKS),
    "host-windows-quick": ["os_info", "smb_signing", "local_admins",
                           "always_install_elevated", "unquoted_services", "wdigest"],
}

WINDOWS_CATALOG: set[str] = set(WINDOWS_CHECKS)
