"""Active Directory / LDAP read-only assessment (anonymous enumeration).

Detects classic AD exposures without credentials: anonymous bind, RootDSE/naming-context
disclosure, and anonymous user/object enumeration. Runs ldapsearch via the sandbox
(closed catalog, read-only). For full AD risk scoring, PingCastle (`healthcheck`) and
BloodHound/SharpHound integrate here when run against a real domain — hooks documented below.
"""
from __future__ import annotations

from dataclasses import dataclass

from .. import ai_analyzer
from ..guardrail import Guardrail, GuardrailError
from ..orchestrator import ScanResult
from ..tools import Observation


@dataclass(frozen=True)
class ADCheck:
    key: str
    builds: str        # 'rootdse' | 'anon_search'


AD_CHECKS = {"rootdse": ADCheck("rootdse", "rootdse"),
             "anon_objects": ADCheck("anon_objects", "anon_search"),
             "anon_users": ADCheck("anon_users", "anon_users")}
AD_CATALOG: set[str] = set(AD_CHECKS)
AD_PROFILES = {"ad-ldap": ["rootdse", "anon_objects", "anon_users"]}


def _argv(key: str, target: str, base: str) -> list[str]:
    if key == "rootdse":
        return ["ldapsearch", "-x", "-H", f"ldap://{target}", "-s", "base", "-b", "",
                "namingContexts", "supportedLDAPVersion", "defaultNamingContext"]
    if key == "anon_users":
        return ["ldapsearch", "-x", "-H", f"ldap://{target}", "-b", base, "-s", "sub",
                "(|(objectClass=person)(objectClass=inetOrgPerson))", "cn", "uid", "sAMAccountName"]
    return ["ldapsearch", "-x", "-H", f"ldap://{target}", "-b", base, "-s", "sub",
            "(objectClass=*)", "dn"]


def _parse(key: str, output: str, target: str) -> list[Observation]:
    text = (output or "").strip()
    out: list[Observation] = []
    if not text or "Can't contact" in text or "result: 32" in text:
        return out
    low = text.lower()
    if key == "rootdse" and "namingcontexts" in low:
        for line in text.splitlines():
            if line.lower().startswith("namingcontexts"):
                out.append(Observation(target, "ad",
                                       f"anonymous LDAP RootDSE exposes {line.strip()[:120]}"))
    if key == "anon_users":
        names = [l.strip() for l in text.splitlines()
                 if l.lower().startswith(("cn:", "uid:", "samaccountname:"))]
        if names:
            out.append(Observation(target, "ad",
                                   f"anonymous LDAP user enumeration: {len(names)} accounts "
                                   f"(e.g. {', '.join(names[:5])})"))
    if key == "anon_objects":
        dns = [l for l in text.splitlines() if l.lower().startswith("dn:")]
        if dns:
            out.append(Observation(target, "ad",
                                   f"anonymous LDAP bind permitted — {len(dns)} objects readable"))
    return out


class ADOrchestrator:
    def __init__(self, guardrail: Guardrail, sandbox, base: str = "",
                 per_check_timeout: int = 30, ai_provider: str | None = None,
                 ai_ollama_model: str | None = None):
        self.guard = guardrail
        self.sandbox = sandbox
        self.base = base
        self.timeout = per_check_timeout
        self.ai_provider = ai_provider
        self.ai_ollama_model = ai_ollama_model

    def run(self, target: str, profile: str = "ad-ldap") -> ScanResult:
        result = ScanResult()
        for key in AD_PROFILES.get(profile, AD_PROFILES["ad-ldap"]):
            try:
                self.guard.authorize_host(target, key, AD_CATALOG)
            except GuardrailError as exc:
                result.errors.append(f"{key} {target}: DENIED {exc}")
                continue
            ex = self.sandbox.run(_argv(key, target, self.base), timeout=self.timeout)
            self.guard.record(f"ad:{key}", exit_code=ex.exit_code,
                              summary=self.guard.sanitize(ex.stdout[:200]))
            result.observations.extend(_parse(key, self.guard.sanitize(ex.stdout), target))

        result.findings = ai_analyzer.triage(result.observations, budget=self.guard.budget,
                                             provider=self.ai_provider,
                                             ollama_model=self.ai_ollama_model)
        result.correlation = ai_analyzer.correlate(result.findings, budget=self.guard.budget,
                                                   provider=self.ai_provider,
                                                   ollama_model=self.ai_ollama_model)
        self.guard.audit.write({"event": "ad_scan_complete", "target": target,
                                "obs": len(result.observations),
                                "findings": len(result.findings)})
        return result
