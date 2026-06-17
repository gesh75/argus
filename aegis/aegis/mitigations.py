"""Platform-aware, step-by-step mitigation playbooks.

Maps a finding (title + evidence + asset) to the detected platform and a concrete,
ordered remediation procedure. Used to (a) enrich any finding that lacks steps —
including offline/heuristic mode — and (b) ground the LLM's own suggestions.
Tuned for a common enterprise stack: Meraki / Juniper / Arista / Cisco network gear, Windows AD/SMB,
and common web stacks (Apache/Nginx/IIS/PHP), with HIPAA framing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Playbook:
    platform: str
    steps: tuple[str, ...]


# Ordered rules: first matching pattern wins. Patterns match title+evidence (lowercased).
_RULES: list[tuple[re.Pattern, Playbook]] = [
    (re.compile(r"smbv1|smb1|ms17-010"), Playbook("Windows / SMB", (
        "1. Confirm the host and owner via CMDB before any change.",
        "2. Audit current state: Get-SmbServerConfiguration | Select EnableSMB1Protocol.",
        "3. Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force.",
        "4. Remove the client feature: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol.",
        "5. Enforce fleet-wide via GPO (Computer > Admin Templates > MS Security Guide > SMBv1).",
        "6. Re-scan to confirm only SMBv2/3 negotiate; document for HIPAA §164.312(e) transmission security.",
    ))),
    (re.compile(r"smb signing|signing not required|smb relay|ntlm relay"), Playbook("Windows / AD", (
        "1. Enable 'Microsoft network server: Digitally sign communications (always)' via GPO.",
        "2. Enable the matching client signing policy; link the GPO to all server/workstation OUs.",
        "3. For domain controllers, require LDAP signing + channel binding (LdapEnforceChannelBinding=2).",
        "4. Disable LLMNR and NBT-NS (GPO: Turn off multicast name resolution) to kill relay primers.",
        "5. gpupdate /force, then re-test with the AD/SMB profile to confirm signing required.",
    ))),
    (re.compile(r"alwaysinstallelevated|unquoted service|wdigest|uselogoncredential|"
                r"writable service|service binary"), Playbook("Windows / privesc", (
        "1. AlwaysInstallElevated: set both HKLM and HKCU "
        "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated = 0 (via GPO).",
        "2. Unquoted service paths: quote the ImagePath in the registry; ensure no writable "
        "intermediate directory (icacls on the service folder).",
        "3. WDigest: set HKLM\\...\\WDigest\\UseLogonCredential = 0 to stop cleartext creds in LSASS.",
        "4. Fix weak service ACLs (sc sdset / icacls) so non-admins can't modify service binaries.",
        "5. Re-run the host-windows profile to confirm the escalation vector is closed.",
    ))),
    (re.compile(r"null session|null/guest|smb share|smb/ad|smb service|smb enumeration|"
                r"restrictanonymous|guest session"), Playbook("Windows / SMB", (
        "1. Identify the host/share owner and whether anonymous access is intended (it rarely is).",
        "2. Block null sessions: set 'RestrictAnonymous'=1 and 'RestrictAnonymousSAM'=1 "
        "(or 'restrict anonymous = 2' in Samba's smb.conf).",
        "3. Remove guest/anonymous from share ACLs; grant least-privilege to named groups only.",
        "4. Require SMB signing and SMB2/3 only; disable SMBv1.",
        "5. Firewall 139/445 to authorized subnets; re-run the ad-smb profile to confirm null "
        "enumeration and guest shares are gone.",
    ))),
    (re.compile(r"\bsamba\b|smbd|netbios-ssn"), Playbook("Linux / Samba", (
        "1. Identify the share owner; confirm whether the service should be network-exposed at all.",
        "2. In /etc/samba/smb.conf set: server min protocol = SMB2_10 and client min protocol = SMB2.",
        "3. Set 'server signing = mandatory' and remove any 'guest ok = yes' on sensitive shares.",
        "4. Restrict reachability: 'hosts allow = <mgmt subnet>' and host firewall on 139/445.",
        "5. Patch Samba to the current vendor release; restart smbd and re-enumerate shares.",
    ))),
    (re.compile(r"snmp|community|public|sysdescr"), Playbook("Network gear (SNMP)", (
        "1. Treat any default community (public/private) as exposed — rotate immediately.",
        "2. Meraki: Dashboard > Network-wide > General > SNMP — disable v1/v2c, enable SNMPv3 (auth+priv).",
        "3. Juniper: 'delete snmp community public'; configure 'set snmp v3' with SHA/AES; commit.",
        "4. Arista EOS: 'no snmp-server community public'; 'snmp-server group/user v3 priv'.",
        "5. Restrict SNMP to the NMS source IP via ACL and bind to the mgmt VLAN only.",
        "6. Re-run the snmp profile to confirm v1/v2c no longer respond.",
    ))),
    (re.compile(r"tls1\.0|tlsv1\.0|tls1\.1|sslv3|sslv2|rc4|weak (protocol|cipher)|poodle|beast"),
     Playbook("TLS / crypto", (
        "1. Identify the terminating service (web server, load balancer, or device mgmt UI).",
        "2. Apache: 'SSLProtocol -all +TLSv1.2 +TLSv1.3' and a modern SSLCipherSuite; reload.",
        "3. Nginx: 'ssl_protocols TLSv1.2 TLSv1.3;' with Mozilla 'intermediate' cipher list.",
        "4. Network device mgmt UIs (Meraki/Juniper/Arista): disable legacy TLS in the mgmt/HTTPS config.",
        "5. Add HSTS (max-age>=31536000) and replace expired/self-signed certs with CA-issued.",
        "6. Re-test with the tls profile; target an A grade (no TLS<1.2, no RC4). HIPAA transmission security.",
    ))),
    (re.compile(r"juniper|junos"), Playbook("Juniper (Junos)", (
        "1. Verify Junos version; check JSA/SIRT advisories for the model and patch to a fixed release.",
        "2. Lock management: 'set system services' to SSH only; disable telnet/http; HTTPS for J-Web.",
        "3. Apply a loopback firewall filter restricting mgmt to the NOC subnet.",
        "4. Enforce SNMPv3, NTP auth, and syslog to the SIEM; commit and confirm.",
    ))),
    (re.compile(r"arista|\beos\b"), Playbook("Arista (EOS)", (
        "1. Check the EOS release against Arista security advisories; schedule patch in a window.",
        "2. 'management ssh' only; disable unused 'management api http-commands' or restrict via ACL.",
        "3. Apply control-plane ACLs and management-VRF isolation for mgmt protocols.",
        "4. Enforce SNMPv3 + AAA (TACACS+/RADIUS); log to SIEM.",
    ))),
    (re.compile(r"meraki|cisco"), Playbook("Cisco / Meraki", (
        "1. Meraki: confirm firmware is current in Dashboard; review the Security Center alerts.",
        "2. Restrict Dashboard/device mgmt to SSO + MFA; scope admin roles least-privilege.",
        "3. Cisco IOS: disable telnet/http server, 'transport input ssh', apply mgmt-plane ACLs.",
        "4. Rotate SNMP to v3, set login banners, and forward logs to the SIEM.",
    ))),
    (re.compile(r"apache|httpd"), Playbook("Apache HTTP Server", (
        "1. Patch httpd to the current stable release for your distro.",
        "2. Suppress banners: 'ServerTokens Prod' and 'ServerSignature Off'.",
        "3. Disable unused modules (status, info, autoindex); restrict admin endpoints by IP.",
        "4. Add security headers (HSTS, X-Content-Type-Options, X-Frame-Options); reload and re-scan.",
    ))),
    (re.compile(r"\bphp\b"), Playbook("PHP", (
        "1. Upgrade PHP to a supported branch; remove EOL versions.",
        "2. Set 'expose_php = Off' in php.ini to suppress the X-Powered-By version banner.",
        "3. Harden: disable dangerous functions, set open_basedir, enable session Secure/HttpOnly cookies.",
        "4. Reload the SAPI (php-fpm/apache) and re-test headers.",
    ))),
    (re.compile(r"\bldap\b|naming context|rootdse|anonymous"), Playbook("Active Directory / LDAP", (
        "1. Determine whether anonymous LDAP bind is required (it rarely is).",
        "2. Set dsHeuristics to block anonymous ops; require LDAP signing + channel binding.",
        "3. Restrict 389/636 to authorized subnets; prefer LDAPS (636) for any external reach.",
        "4. Review exposed naming contexts for sensitive data; re-run the ad-smb profile.",
    ))),
    (re.compile(r"suid|sgid|gtfobins|privilege escalation|nopasswd|sudo "), Playbook("Linux / privesc", (
        "1. Confirm the host owner and whether the SUID/SGID binary or sudo grant is required.",
        "2. Remove the bit: chmod u-s,g-s <binary>; verify with 'find / -perm -4000'.",
        "3. Tighten sudoers: remove NOPASSWD and 'ALL=(ALL)' grants; scope to specific commands "
        "with full paths; run 'visudo -c' to validate.",
        "4. Replace risky GTFOBins binaries (find/vim/nmap/perl) being SUID with non-SUID equivalents.",
        "5. Re-run the host-linux profile to confirm the escalation vector is gone.",
    ))),
    (re.compile(r"permitrootlogin|password authentication|ssh permits|empty password|sshd"),
     Playbook("Linux / SSH", (
        "1. Edit /etc/ssh/sshd_config (or a drop-in in /etc/ssh/sshd_config.d/).",
        "2. Set 'PermitRootLogin no' and 'PasswordAuthentication no' (use key-based auth).",
        "3. Set 'PermitEmptyPasswords no'; restrict 'AllowUsers'/'AllowGroups' to authorized accounts.",
        "4. Reload: 'sshd -t && systemctl reload sshd'.",
        "5. Re-run the host-linux profile to confirm hardening; HIPAA access-control safeguard.",
    ))),
    (re.compile(r"login|admin panel|unauthenticated|exposed (panel|interface)"),
     Playbook("Web application", (
        "1. Confirm the page should be internet/segment reachable; if not, firewall-restrict it.",
        "2. Put admin/login behind VPN or an allow-list; enforce MFA.",
        "3. Add rate-limiting and account lockout; ensure session cookies are Secure+HttpOnly.",
        "4. Re-scan with the web profile to confirm reduced exposure.",
    ))),
]

_DEFAULT = Playbook("General", (
    "1. Validate the finding and identify the asset owner via CMDB.",
    "2. Confirm whether the service/port must be exposed on this segment; if not, firewall-restrict it.",
    "3. Patch the affected software to a vendor-supported version.",
    "4. Apply least-privilege access controls and forward logs to the SIEM.",
    "5. Re-scan to verify remediation and record the closure for the HIPAA audit trail.",
))


def suggest(title: str, evidence: str = "", asset: str = "") -> Playbook:
    """Return the platform + ordered mitigation steps for a finding."""
    hay = f"{title} {evidence} {asset}".lower()
    for pattern, pb in _RULES:
        if pattern.search(hay):
            return pb
    return _DEFAULT
