"""Realistic 'vulnerable Windows host' fixture for testing the Windows audit pipeline
without a real Windows kernel (Docker can't run Windows containers on macOS/arm).

The FixtureWinRM collector returns canned, realistic PowerShell output per check so the
full Windows path — parsers -> AI analysis -> mitigation playbooks -> reporting — runs live.
For a REAL live WinRM test, point WinRMCollector at a Windows VM (cloud or UTM Windows-on-ARM).
"""
from __future__ import annotations

from . import windows
from .winrm_collector import WinExec

# Simulated output of a deliberately misconfigured Windows Server 2019 host.
WINDOWS_VULN_FIXTURE: dict[str, str] = {
    "os_info": ("Caption      : Microsoft Windows Server 2019 Standard\n"
                "Version      : 10.0.17763\nBuildNumber  : 17763\nOSArchitecture : 64-bit"),
    "hotfixes": "12\n\nHotFixID   InstalledOn\n--------   -----------\nKB5005112  1/12/2023",
    "local_admins": ("Name                   PrincipalSource\n----                   ---------------\n"
                     "ECP\\Domain Admins       ActiveDirectory\n"
                     "WIN-SRV01\\Administrator  Local\nWIN-SRV01\\svc_backup     Local"),
    "smb_signing": ("EnableSMB1Protocol       : True\n"
                    "RequireSecuritySignature : False\nEnableSecuritySignature  : False"),
    "llmnr": "1",
    "uac": "0",
    "always_install_elevated": "1\n1",
    "unquoted_services": ("Name         PathName\n----         --------\n"
                          "BackupAgent  C:\\Program Files\\Backup Agent\\agent.exe"),
    "defender": ("AMRunningMode             : Normal\n"
                 "RealTimeProtectionEnabled : False\nAntivirusEnabled          : True"),
    "wdigest": "1",
    "rdp_nla": "0",
    "laps": "AdmPwdEnabled\n-------------\n",   # blank = LAPS not enabled
}


class FixtureWinRM:
    """Drop-in WinRM collector that replays the vulnerable-Windows fixture (no network)."""

    def __init__(self, fixture: dict[str, str] | None = None):
        self.fixture = fixture or WINDOWS_VULN_FIXTURE
        # reverse-map the exact PowerShell command back to its check key
        self._by_ps = {c.ps: k for k, c in windows.WINDOWS_CHECKS.items()}

    def run_ps(self, target: str, command: str, timeout: int = 60) -> WinExec:
        key = self._by_ps.get(command)
        return WinExec(0, self.fixture.get(key, ""), "")
