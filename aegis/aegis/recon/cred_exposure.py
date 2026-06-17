"""Module 2 — Credential EXPOSURE detection (read-only; detect, never collect).

Once Aegis has read-only host/share/web evidence, this module flags places where
credentials are *exposed* — without ever exfiltrating the secret itself. The finding
records the LOCATION and TYPE of exposure; the secret value is redacted by the Layer-7
sanitizer. This keeps the tool strictly read-only and PHI-safe while still surfacing the
single highest-value pivot in any internal assessment.

Detects (from already-collected evidence lines):
  * GPP cpassword in SYSVOL (AES-key is public -> trivially decryptable)  [Windows/AD]
  * world-readable .env / config / .git on a host or share                [Linux/Win]
  * secrets in shell history (~/.bash_history)                            [Linux]
  * stored PuTTY / VNC / WinSCP credentials in registry exports           [Windows]
  * cloud metadata token reachability (169.254.169.254)                   [cloud]
NEVER performs memory scraping (LSASS/mimikatz) — out of scope, not read-only.
"""
from __future__ import annotations

import re

from ..tools import Observation

# (regex, exposure-type, platform, why) — matched against evidence detail/raw (lowercased).
RULES: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"cpassword"), "GPP cpassword in SYSVOL", "Windows / AD",
     "Group Policy Preferences password — Microsoft's AES key is public; trivially decryptable"),
    (re.compile(r"(^|/)\.env\b"), "world-readable .env", "Linux / Web",
     "environment file readable — typically DB creds / API keys"),
    (re.compile(r"\.git/config|repositoryformatversion"), "exposed .git", "Linux / Web",
     "version-control metadata — source and embedded secrets disclosure"),
    (re.compile(r"\.bash_history|\.zsh_history"), "secret in shell history", "Linux",
     "command history may contain passwords/tokens passed on the CLI"),
    (re.compile(r"putty\\sessions|\\simon tatham"), "stored PuTTY credentials", "Windows",
     "PuTTY saved-session proxy/password in registry"),
    (re.compile(r"vnc.*passwo?r?d|winvnc"), "stored VNC password", "Windows",
     "VNC password stored with reversible/weak encoding"),
    (re.compile(r"winscp.*\\sessions|winscp.ini"), "stored WinSCP credentials", "Windows",
     "WinSCP saved-session credentials"),
    (re.compile(r"169\.254\.169\.254|metadata\.google|metadata/instance"),
     "cloud metadata endpoint reachable", "Cloud",
     "instance metadata service reachable — may yield temporary cloud credentials"),
    (re.compile(r"id_rsa\b|id_ed25519\b|\.pem\b"), "private key file present", "Linux / Win",
     "unprotected private key material on disk"),
    (re.compile(r"password\s*=|passwd\s*=|api[_-]?key\s*=|secret\s*="),
     "hardcoded secret in config", "Linux / Win",
     "credential assigned in a readable config/script"),
]


def detect(observations: list[Observation], sanitize=None) -> list[Observation]:
    """Scan evidence for credential-exposure indicators. Returns redacted Observations.

    `sanitize` (e.g. Guardrail.sanitize) is applied to every emitted detail/raw so the
    secret VALUE never persists — only the fact and location of the exposure.
    """
    out: list[Observation] = []
    seen: set[tuple[str, str]] = set()
    for o in observations:
        hay = f"{o.detail} {o.raw}".lower()
        for rx, etype, platform, why in RULES:
            if not rx.search(hay):
                continue
            key = (o.asset, etype)
            if key in seen:
                continue
            seen.add(key)
            detail = f"[{platform}] {etype} on {o.asset} — {why}"
            raw = o.detail[:120]
            if sanitize:
                detail, raw = sanitize(detail), sanitize(raw)
            out.append(Observation(o.asset, "exposure", detail, raw))
    return out
