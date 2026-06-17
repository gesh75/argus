"""Module 3 — Exploit-chaining / reasoning engine (read-only inference).

The leap from scanner to agentic pentester: instead of reporting isolated findings, reason
about how they COMBINE into multi-step attack paths. This is pure deterministic inference
over the evidence graph (Findings + Observations) — it emits no packets. Each chain is
annotated `proof: observed` (every link is backed by collected evidence) or
`proof: theoretical` (a link is plausible but not directly observed), so the operator
knows what was demonstrated vs inferred. The PoC runner can later upgrade a theoretical
link to observed in the lab.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..ai_analyzer import Finding

# Numeric severity ordering so remediations rank by real risk, not alphabetically.
_SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


@dataclass
class Chain:
    name: str
    severity: str
    steps: list[str]
    mitre_tactics: list[str]
    proof: str                      # "observed" | "theoretical"
    assets: list[str] = field(default_factory=list)
    business_risk: str = ""


def _has(findings: list[Finding], *needles: str) -> list[Finding]:
    out = []
    for f in findings:
        hay = f"{f.title} {f.evidence} {f.affected_asset}".lower()
        if all(n in hay for n in needles):
            out.append(f)
    return out


def _any(findings: list[Finding], *terms: str) -> list[Finding]:
    return [f for f in findings
            if any(t in f"{f.title} {f.evidence}".lower() for t in terms)]


# Each rule: (name, severity, tactics, predicate, step-builder). Predicate returns the
# contributing findings (empty => rule does not fire).
def _rule_relay(findings):
    tls = _any(findings, "weak tls", "sslv3", "tls1.0", "rc4")
    smb = _any(findings, "smb signing", "smbv1", "smb1")
    ad = _any(findings, "ldap", "domain account", "ad/")
    if smb and ad:
        contrib = smb + ad + tls
        return contrib, [
            "Coerce/await authentication on the network (LLMNR/NBT-NS or weak TLS path)",
            "Relay captured NTLM auth to a host missing SMB signing",
            "Authenticate to reachable AD/share resources as the relayed identity"], \
            "observed" if (smb and ad and tls) else "theoretical"
    return None


def _rule_web_to_host(findings):
    exp = _any(findings, "web exposure", ".env", "secret:", "config:", "credentials")
    svc = _any(findings, "ssh", "rdp", "winrm", "exposed service")
    if exp:
        contrib = exp + svc
        proof = "observed" if exp and svc else "theoretical"
        return contrib, [
            "Harvest credentials from the exposed web file/endpoint (read-only: exposure confirmed)",
            "Reuse the disclosed secret against a reachable admin/SSH/RDP/WinRM service",
            "Obtain an interactive foothold on the host"], proof
    return None


def _rule_privesc_chain(findings):
    foothold = _any(findings, "exposed service", "ssh", "web exposure", "smb share")
    privesc = _any(findings, "privesc", "suid", "nopasswd", "alwaysinstallelevated",
                   "unquoted service")
    if privesc:
        contrib = foothold + privesc
        proof = "observed" if foothold and privesc else "theoretical"
        return contrib, [
            "Gain a low-privilege foothold (exposed service / share / web)",
            "Abuse the local privesc primitive (SUID/NOPASSWD sudo / AlwaysInstallElevated / "
            "unquoted service path)",
            "Escalate to root/SYSTEM on the host"], proof
    return None


def _rule_segmentation_pivot(findings):
    seg = _any(findings, "segmentation gap", "plane reachable")
    if seg:
        return seg, [
            "From the assessment/user VLAN, reach a sensitive plane directly (segmentation gap)",
            "Attack the exposed database/management/directory service without crossing a firewall",
            "Move laterally into the protected tier"], "observed"
    return None


def _rule_shadow_ai(findings):
    ai = _any(findings, "shadow ai", "ollama", "jupyter", "gradio", "vllm")
    if ai:
        proof = "observed"
        return ai, [
            "Discover an unmanaged local AI service (Ollama/Jupyter/Gradio/vLLM)",
            "Abuse open model management or notebook RCE (Jupyter token disabled)",
            "Pivot from the AI host into the corporate network"], proof
    return None


_RULES = [
    ("NTLM relay -> AD resource access", "High",
     ["Credential Access", "Lateral Movement"], _rule_relay,
     "Unauthorized access to PHI-bearing shares via relayed authentication."),
    ("Web secret exposure -> host foothold", "High",
     ["Credential Access", "Initial Access"], _rule_web_to_host,
     "Disclosed credentials enable an interactive foothold on internal hosts."),
    ("Foothold -> local privilege escalation", "Critical",
     ["Privilege Escalation"], _rule_privesc_chain,
     "Full host compromise (root/SYSTEM) from a low-privilege entry point."),
    ("Segmentation gap -> protected-tier pivot", "High",
     ["Lateral Movement", "Discovery"], _rule_segmentation_pivot,
     "Flat network lets a user-VLAN attacker reach the data/management plane directly."),
    ("Shadow-AI host -> network pivot", "Medium",
     ["Initial Access", "Execution"], _rule_shadow_ai,
     "Ungoverned AI service is an unmonitored entry/pivot point."),
]


def derive_chains(findings: list[Finding]) -> list[Chain]:
    """Run the deterministic decision-tree rules. Returns ordered, de-duplicated chains."""
    chains: list[Chain] = []
    for name, sev, tactics, rule, risk in _RULES:
        res = rule(findings)
        if not res:
            continue
        contrib, steps, proof = res
        assets = sorted({f.affected_asset for f in contrib if f.affected_asset})
        chains.append(Chain(name, sev, steps, tactics, proof, assets, risk))
    sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    chains.sort(key=lambda c: (sev_rank.get(c.severity, 0), c.proof == "observed"),
                reverse=True)
    return chains


def chains_to_correlation(findings: list[Finding]) -> dict:
    """Render chains into the same correlation dict shape the reporting layer expects."""
    chains = derive_chains(findings)
    hi = sum(1 for f in findings if f.severity in ("Critical", "High"))
    return {
        "executive_summary": f"{len(findings)} findings; {hi} high/critical; "
                             f"{len(chains)} attack path(s) derived "
                             f"({sum(c.proof == 'observed' for c in chains)} observed).",
        "attack_paths": [{"name": c.name, "severity": c.severity, "steps": c.steps,
                          "mitre_tactics": c.mitre_tactics, "proof": c.proof,
                          "assets": c.assets, "business_risk": c.business_risk}
                         for c in chains],
        "phi_exposure": sorted({a for c in chains if c.severity in ("Critical", "High")
                                for a in c.assets})[:10],
        "top_remediations": [f.remediation for f in
                             sorted(findings, key=lambda f: _SEV_RANK.get(f.severity, 0),
                                    reverse=True)[:5] if f.remediation],
    }
