"""Registry of READ-ONLY reconnaissance tools (curated from Kali, Aegis research).

Each tool builds an argv list (never a shell string) from one validated target, and a
parser turns raw stdout into normalized Observations. Curated non-intrusive: no
exploitation, no credential spraying, no writes, no DoS. Credentialed tools use
null/guest/anonymous sessions only.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass

# defusedxml hardens against XXE / billion-laughs — tool output is UNTRUSTED.
try:
    from defusedxml import ElementTree as ET  # type: ignore
    from defusedxml.ElementTree import ParseError  # type: ignore
except ImportError:  # fallback keeps the module importable; install defusedxml for safety
    import xml.etree.ElementTree as ET  # noqa: S405
    from xml.etree.ElementTree import ParseError


@dataclass(frozen=True)
class Observation:
    asset: str
    kind: str          # port | service | tls | web | smb | snmp | dns | cve | info
    detail: str
    raw: str = ""


@dataclass(frozen=True)
class Tool:
    key: str
    binary: str                       # firewall keys on this
    profile: str
    read_only: bool
    needs_root: bool
    build: Callable[[str], list[str]]
    parse: Callable[[str, str], list[Observation]]   # (stdout, target) -> observations


# ---- parsers ---------------------------------------------------------------
# nmap's static service table mislabels some common dev/app ports when -sV can't
# fingerprint (e.g. 3000 -> 'ppp'). Correct the obvious HTTP-ish ones for readability.
_PORT_HINT = {"3000": "http(dev)", "8080": "http-alt", "5000": "http(dev)",
              "9090": "http(dev)", "3001": "http(dev)"}


def _nmap_xml(text: str, target: str) -> list[Observation]:
    obs: list[Observation] = []
    try:
        root = ET.fromstring(text)  # nosec B314 ET is defusedxml (see import)  # noqa: S314
    except ParseError:
        return obs
    for host in root.findall("host"):
        addr_el = host.find("address")
        asset = addr_el.get("addr", target) if addr_el is not None else target
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            portid = port.get("portid", "")
            pid = f"{portid}/{port.get('protocol')}"
            name = svc.get("name", "?") if svc is not None else "?"
            # Correct nmap's static mislabel (e.g. 3000 'ppp') when no real product was found.
            product_empty = svc is None or not svc.get("product")
            if product_empty and portid in _PORT_HINT and name in ("ppp", "?", ""):
                name = _PORT_HINT[portid]
            product = " ".join(filter(None, [
                svc.get("product", "") if svc is not None else "",
                svc.get("version", "") if svc is not None else "",
            ])).strip()
            obs.append(Observation(asset, "service", f"{pid} {name} {product}".strip()))
        for script in host.findall(".//script"):
            out = (script.get("output") or "").strip()
            for cve in re.findall(r"CVE-\d{4}-\d{4,7}", out):
                obs.append(Observation(asset, "cve", cve, out[:300]))
    return obs


def _nuclei_jsonl(text: str, target: str) -> list[Observation]:
    obs: list[Observation] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = ev.get("info", {})
        obs.append(Observation(
            ev.get("host", target), "web",
            f"{ev.get('template-id', '?')} [{info.get('severity', '?')}] {info.get('name', '')}",
            json.dumps(ev)[:300]))
    return obs


def _whatweb_json(text: str, target: str) -> list[Observation]:
    obs: list[Observation] = []
    rows: list = []
    stripped = text.strip()
    try:
        parsed = json.loads(stripped)
        rows = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        for line in stripped.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{"):
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    for r in rows:
        if not isinstance(r, dict):
            continue
        techs = []
        for name, meta in (r.get("plugins", {}) or {}).items():
            ver = ""
            if isinstance(meta, dict) and meta.get("version"):
                v = meta["version"]
                ver = "/".join(v) if isinstance(v, list) else str(v)
            techs.append(f"{name}{('/' + ver) if ver else ''}")
        status = r.get("http_status", "")
        detail = f"HTTP {status} :: " + ", ".join(sorted(techs)) if techs else f"HTTP {status}"
        obs.append(Observation(r.get("target", target), "web", detail[:400]))
    return obs


_WEAK_PROTO = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")


def _sslscan_text(text: str, target: str) -> list[Observation]:
    obs: list[Observation] = []
    host = target
    m = re.search(r"Connected to ([\d.]+)", text)
    if m:
        host = m.group(1)
    for proto in _WEAK_PROTO:
        if re.search(rf"(?:Accepted\s+{re.escape(proto)})|(?:{re.escape(proto)}\s+enabled)", text):
            obs.append(Observation(host, "tls", f"weak protocol enabled: {proto}"))
    if re.search(r"Accepted.*RC4", text):
        obs.append(Observation(host, "tls", "weak cipher: RC4 accepted"))
    for line in text.splitlines():
        if "expired" in line.lower() or "self-signed" in line.lower():
            obs.append(Observation(host, "tls", line.strip()[:160]))
    return obs


def _snmpwalk(text: str, target: str) -> list[Observation]:
    obs = []
    for line in text.splitlines():
        line = line.strip()
        if line and "No Such" not in line and "Timeout" not in line:
            obs.append(Observation(target, "snmp", line[:200]))
    return obs[:25]


# A line that is ONLY separators / brackets / spinner chars / digits — pure noise.
_NOISE = re.compile(r"^[\s\-=*_|/\\\[\].]+$")
_ANSI = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def _lines(kind: str, maxn: int = 30) -> Callable[[str, str], list[Observation]]:
    """Generic parser: keep informative stdout lines (ANSI/spinner-stripped)."""
    def parse(text: str, target: str) -> list[Observation]:
        out: list[Observation] = []
        seen: set[str] = set()
        # split on newlines AND carriage returns (spinner output uses \r)
        for raw in re.split(r"[\r\n]+", _ANSI.sub("", text)):
            s = raw.strip()
            if not s or len(s) < 4 or _NOISE.match(s) or s in seen:
                continue
            seen.add(s)
            out.append(Observation(target, kind, s[:200]))
            if len(out) >= maxn:
                break
        return out
    return parse


# ---- registry --------------------------------------------------------------
def _t(key, binary, profile, root, build, parse):
    return Tool(key, binary, profile, True, root, build, parse)


REGISTRY: dict[str, Tool] = {
    # discovery
    "nmap_discovery": _t("nmap_discovery", "nmap", "discovery", False,
        lambda t: ["nmap", "-sn", "-PE", "-oX", "-", t], _nmap_xml),
    "fping": _t("fping", "fping", "discovery", False,
        lambda t: ["fping", "-a", "-q", t], _lines("discovery")),
    "nbtscan": _t("nbtscan", "nbtscan", "discovery", False,
        lambda t: ["nbtscan", t], _lines("smb")),
    # network
    "nmap_service": _t("nmap_service", "nmap", "network", False,
        lambda t: ["nmap", "-sT", "-sV", "-Pn", "-T3", "--top-ports", "1000", "-oX", "-", t],
        _nmap_xml),
    "masscan": _t("masscan", "masscan", "network", True,
        lambda t: ["masscan", "-p1-1000", "--rate", "1000", t], _lines("port")),
    # web
    "whatweb": _t("whatweb", "whatweb", "web", False,
        lambda t: ["whatweb", "-a", "1", "--log-json=-", t], _whatweb_json),
    "wafw00f": _t("wafw00f", "wafw00f", "web", False,
        lambda t: ["wafw00f", t], _lines("web")),
    "nikto_tuned": _t("nikto_tuned", "nikto", "web", False,
        lambda t: ["nikto", "-h", t, "-Tuning", "bde", "-maxtime", "300s"], _lines("web")),
    # tls
    "sslscan": _t("sslscan", "sslscan", "tls", False,
        lambda t: ["sslscan", "--no-colour", t], _sslscan_text),
    "testssl": _t("testssl", "testssl.sh", "tls", False,
        lambda t: ["testssl.sh", "--quiet", "--color", "0", t], _lines("tls")),
    # ad-smb (null/guest/anonymous only)
    "enum4linux_ng": _t("enum4linux_ng", "enum4linux-ng", "ad-smb", False,
        lambda t: ["enum4linux-ng", "-A", t], _lines("smb")),
    "smbmap": _t("smbmap", "smbmap", "ad-smb", False,
        lambda t: ["smbmap", "-H", t, "-u", "guest", "-p", "", "--no-banner"], _lines("smb")),
    "ldapsearch": _t("ldapsearch", "ldapsearch", "ad-smb", False,
        lambda t: ["ldapsearch", "-x", "-H", f"ldap://{t}", "-s", "base", "-b", "",
                   "(objectclass=*)", "namingContexts"], _lines("smb")),
    # snmp (read community only, never SET)
    "onesixtyone": _t("onesixtyone", "onesixtyone", "snmp", False,
        lambda t: ["onesixtyone", t, "public"], _lines("snmp")),
    "snmpwalk": _t("snmpwalk", "snmpwalk", "snmp", False,
        lambda t: ["snmpwalk", "-v2c", "-c", "public", "-Oqv", "-t", "2", "-r", "1", t, "system"],
        _snmpwalk),
    "snmp_check": _t("snmp_check", "snmp-check", "snmp", False,
        lambda t: ["snmp-check", "-c", "public", t], _lines("snmp")),
    # vuln (non-intrusive exposures/misconfig)
    "nuclei_exposures": _t("nuclei_exposures", "nuclei", "vuln", False,
        lambda t: ["nuclei", "-u", t, "-tags", "exposure,misconfig,tech",
                   "-severity", "info,low,medium,high,critical", "-jsonl", "-silent"],
        _nuclei_jsonl),
}


# Scan profiles — ordered tool keys per intent. 'default' is a safe quick sweep.
PROFILES: dict[str, list[str]] = {
    "default": ["nmap_service", "sslscan", "whatweb", "nuclei_exposures"],
    "discovery": ["nmap_discovery", "fping", "nbtscan"],
    "network": ["nmap_service", "masscan"],
    "web": ["whatweb", "wafw00f", "nikto_tuned", "nuclei_exposures"],
    "tls": ["sslscan"],            # testssl available if installed (see registry); sslscan is default
    "ad-smb": ["nbtscan", "enum4linux_ng", "smbmap", "ldapsearch"],
    "snmp": ["onesixtyone", "snmpwalk", "snmp_check"],
    "vuln": ["nmap_service", "nuclei_exposures"],
    "full": ["nmap_service", "sslscan", "whatweb", "wafw00f", "nikto_tuned",
             "nuclei_exposures", "nbtscan", "enum4linux_ng", "smbmap", "snmpwalk"],
}
