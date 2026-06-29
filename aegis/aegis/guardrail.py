"""Phantom-style 7-layer guardrail enforcement (hardened).

Every tool invocation passes through Guardrail.authorize() BEFORE execution and
Guardrail.record() after. Fails CLOSED: any ambiguity is a denial.

Hardening (from adversarial review):
 - Scope guard default-DENIES on unparseable / no-in-scope-IP targets (never falls open).
 - Targets canonicalized through decimal/hex/octal/leading-zero normalization before
   subnet membership; CIDRs must be subnet_of(allowed) with prefix >= 24 and no host bits.
 - Hostnames / URLs with names are denied (resolve_dns is false — no off-subnet pivot).
 - File-based target inputs (-iL, @file, --*-file) and dangerous flags (--script, -x,
   --config/-K, -e, ProxyCommand) are denied so an allowed binary can't spawn a denied action.
 - Exec is argv-only (see sandbox.py: never shell=True); shell metachars rejected here too.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import time
from dataclasses import dataclass

from .config import Policy

_SHELL_METACHARS = re.compile(r"[;&|`$><\n\r\\]|\$\(")
_DOTTED = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:/(\d{1,2}))?$")
_PURE_INT = re.compile(r"^\d+$")
_HEX = re.compile(r"^0x[0-9a-fA-F]+$")
# A bare DNS-name token: a dotted name with a letter, not a path and not an IP.
def _looks_like_hostname(tok: str) -> bool:
    if "/" in tok:                      # path or URL remnant — not a bare hostname
        return False
    return "." in tok and bool(re.search(r"[A-Za-z]", tok)) and not _DOTTED.match(tok)


def _host_candidate(arg: str) -> str:
    """Extract the host from a positional arg or URL (ldap://1.2.3.4 -> 1.2.3.4)."""
    if "://" in arg:
        return arg.split("://", 1)[1].split("/", 1)[0].split(":")[0]
    return arg

# Universally denied: file-based target lists (let an agent inject off-scope targets).
GLOBAL_DENY_FLAGS = {"-il", "--excludefile", "--include-file", "--url-file"}
# Substrings never legitimate in read-only recon (command spawn via ssh options, etc.).
GLOBAL_DENY_SUBSTR = ("proxycommand", "localcommand", "preexec")
# Per-binary denied flags — a flag dangerous for one tool may be benign for another
# (e.g. ldapsearch -x = simple auth is fine; msfconsole -x = run-command is not).
PER_TOOL_DENY = {
    "nmap": {"--script", "--script-args", "--script-help"},   # NSE = arbitrary Lua
    "curl": {"-k", "--config"},                               # reads request from file
    "msfconsole": {"-x"}, "msfvenom": {"-x"},
    "find": {"-exec", "-execdir"},
    "ssh": {"-o"},                                            # belt: -o ProxyCommand=
}


class GuardrailError(Exception):
    """Raised when an action is denied. Caller MUST abort the action."""


@dataclass
class Decision:
    allowed: bool
    reason: str
    layer: str


def canon_network(token: str) -> ipaddress.IPv4Network:
    """Canonicalize a target token to an IPv4Network, defeating obfuscation.

    Raises ValueError on anything that is not an unambiguous IPv4 literal/CIDR.
    """
    t = token
    if _HEX.match(t):
        return ipaddress.ip_network(ipaddress.ip_address(int(t, 16)))
    if _PURE_INT.match(t):  # decimal integer form, e.g. 2887778305
        return ipaddress.ip_network(ipaddress.ip_address(int(t)))
    m = _DOTTED.match(t)
    if not m:
        raise ValueError(f"not an unambiguous IPv4 literal: {token!r}")
    octets = m.group(1, 2, 3, 4)
    for o in octets:
        if len(o) > 1 and o[0] == "0":
            raise ValueError(f"leading-zero octet (octal ambiguity): {token!r}")
        if int(o) > 255:
            raise ValueError(f"octet > 255: {token!r}")
    prefix = m.group(5)
    if prefix is None:
        return ipaddress.ip_network(".".join(octets) + "/32")
    # strict=True raises if host bits are set (blocks 172.30.0.5/24 style sloppiness)
    return ipaddress.ip_network(f"{'.'.join(octets)}/{int(prefix)}", strict=True)


# Minimum audit-key length (#4). The documented key is `openssl rand -hex 32` (64 chars);
# we fail closed below 32 so a weak/placeholder key can't sign a "tamper-evident" chain.
MIN_AUDIT_KEY_LEN = 32


class AuditLog:
    """HMAC-SHA256 chained, append-only, tamper-evident audit trail."""

    def __init__(self, policy: Policy):
        key = os.environ.get(policy.audit_key_env)
        if not key:
            raise GuardrailError(
                f"audit key env {policy.audit_key_env} unset — refusing to run unaudited"
            )
        if len(key) < MIN_AUDIT_KEY_LEN:
            raise GuardrailError(
                f"audit key too short ({len(key)}<{MIN_AUDIT_KEY_LEN} chars) — a weak key "
                f"makes the chain forgeable; generate one with `openssl rand -hex 32`"
            )
        self._key = key.encode()
        self._path = policy.audit_path
        self._chained = policy.audit_chained
        self._anchor_path = policy.audit_anchor_path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._prev, self._seq = self._last_state()

    def _last_state(self) -> tuple[str, int]:
        """Return (last_hmac, entry_count) by replaying the existing log."""
        if not self._path.exists():
            return "genesis", 0
        last, seq = "genesis", 0
        for line in self._path.read_text().splitlines():
            if line.strip():
                try:
                    last = json.loads(line)["hmac"]
                    seq += 1
                except (json.JSONDecodeError, KeyError):
                    continue
        return last, seq

    def write(self, event: dict) -> str:
        entry = {"ts": round(time.time(), 3),
                 "prev": self._prev if self._chained else None, **event}
        body = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        signed = (self._prev + body) if self._chained else body
        mac = hmac.new(self._key, signed.encode(), hashlib.sha256).hexdigest()
        entry["hmac"] = mac
        with self._path.open("a") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
        self._prev = mac
        self._seq += 1
        # Update the out-of-band anchor so the chain tip is mirrored to a WORM store (#5).
        if self._anchor_path is not None:
            from . import anchor
            anchor.write_anchor(self._anchor_path, self._seq, mac, entry["ts"])
        return mac

    def cross_check_anchor(self) -> tuple[bool, str]:
        """Compare the live chain tip against the out-of-band anchor (#5).

        Detects a full-log rewrite that the in-file HMAC alone cannot (an attacker with the
        leaked key recomputes every MAC, but cannot also forge the WORM anchor).
        """
        if self._anchor_path is None:
            return True, "no anchor configured"
        from . import anchor
        rec = anchor.read_anchor(self._anchor_path)
        if rec is None:
            return False, "anchor missing — chain tip was never anchored or anchor was deleted"
        tip, seq = self._last_state()
        if rec.get("tip") != tip or rec.get("seq") != seq:
            return (False, f"anchor mismatch — anchor=(seq={rec.get('seq')}, "
                    f"tip={str(rec.get('tip'))[:8]}…) chain=(seq={seq}, tip={tip[:8]}…)")
        return True, f"anchor matches chain tip (seq={seq})"

    def verify(self) -> bool:
        """Replay the chain; False if any entry was altered, reordered, or removed."""
        prev = "genesis"
        for line in self._path.read_text().splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            stored = entry.pop("hmac")
            body = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            signed = (prev + body) if self._chained else body
            expect = hmac.new(self._key, signed.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(stored, expect):
                return False
            prev = stored
        return True


class Budget:
    """Wall-clock + token + dollar ceilings. Breach => GuardrailError. Monotonic ledger."""

    def __init__(self, policy: Policy):
        self._b = policy.budget
        self._start = time.monotonic()
        self.tokens = 0
        self.usd = 0.0

    def charge(self, *, tokens: int = 0, usd: float = 0.0) -> None:
        self.tokens += max(0, tokens)
        self.usd += max(0.0, usd)
        self.check()

    def remaining_seconds(self) -> float:
        return max(0.0, self._b.max_wall_seconds - (time.monotonic() - self._start))

    def check(self) -> None:
        if self.remaining_seconds() <= 0:
            raise GuardrailError("budget: wall-clock deadline exceeded")
        if self.tokens > self._b.max_tokens:
            raise GuardrailError("budget: token ceiling exceeded")
        if self.usd > self._b.max_usd:
            raise GuardrailError("budget: usd ceiling exceeded")


class Guardrail:
    def __init__(self, policy: Policy, armed: frozenset[str] | None = None):
        self.policy = policy
        self.armed = armed or frozenset()
        self.audit = AuditLog(policy)
        self.budget = Budget(policy)

    # ---- Layer 1: scope guard (default DENY) ---------------------------------
    def _in_scope(self, net: ipaddress.IPv4Network) -> bool:
        allow = [a for a in self.policy.allowed_networks if net.subnet_of(a)]
        if not allow:
            return False
        # Longest-prefix-match wins (firewall semantics): the most specific matching
        # rule decides. A lab /24 allow correctly overrides a broad /12 deny, while a
        # /32 deny carved out *inside* the allowed /24 still wins and is rejected.
        deny = [d for d in self.policy.denied_networks if net.subnet_of(d)]
        if deny and max(d.prefixlen for d in deny) >= max(a.prefixlen for a in allow):
            return False
        return net.prefixlen >= 24 or net.num_addresses == 1

    def check_target(self, token: str) -> Decision:
        try:
            net = canon_network(token)
        except ValueError as exc:
            return Decision(False, f"scope: {exc}", "scope")
        if net.prefixlen < 24:
            return Decision(False, f"scope: CIDR {token} broader than /24", "scope")
        if not self._in_scope(net):
            return Decision(False, f"scope: {net} outside allowed scope", "scope")
        return Decision(True, f"scope ok: {net}", "scope")

    # ---- Layer 2: tool firewall ----------------------------------------------
    def _check_tool(self, tool: str) -> Decision:
        if tool in self.policy.tool_denied:
            return Decision(False, f"tool {tool} denied", "firewall")
        if tool in self.policy.tool_armed_only and tool not in self.armed:
            return Decision(False, f"tool {tool} requires --arm", "firewall")
        if tool in self.policy.tool_allowed or tool in self.armed:
            return Decision(True, "tool allowed", "firewall")
        if self.policy.tool_default == "allow":
            return Decision(True, "tool default-allow", "firewall")
        return Decision(False, f"tool {tool} not allowlisted (default deny)", "firewall")

    # ---- arg hygiene: metachars, dangerous flags, hostnames, file inputs ------
    def _check_args(self, tool: str, args: list[str]) -> Decision:
        per_tool = PER_TOOL_DENY.get(tool, set())
        for a in args:
            low = a.lower()
            base = low.split("=")[0]
            if _SHELL_METACHARS.search(a):
                return Decision(False, f"arg {a!r} has shell metacharacters", "argshield")
            if base in GLOBAL_DENY_FLAGS:
                return Decision(False, f"arg {a!r} is a denied file-input flag", "argshield")
            if any(s in low for s in GLOBAL_DENY_SUBSTR):
                return Decision(False, f"arg {a!r} contains a command-spawn directive", "argshield")
            if base in per_tool:
                return Decision(False, f"arg {a!r} denied for {tool}", "argshield")
            if a.startswith("@"):
                return Decision(False, f"arg {a!r} is a file input (@)", "argshield")
        return Decision(True, "args clean", "argshield")

    def authorize(self, tool: str, args: list[str], targets: list[str]) -> None:
        """Pre-exec layers. Raise GuardrailError on ANY denial (fail closed)."""
        self.budget.check()
        if not targets:
            self._deny(tool, args, "scope", "no target supplied (default deny)")
        decisions = [self._check_args(tool, args), self._check_tool(tool)]
        decisions += [self.check_target(_host_candidate(t)) for t in targets]
        # Re-scan positional args for stray host/IP literals that bypass the targets list.
        # Skip argv[0] (the binary itself — already vetted by the tool firewall); its name
        # may legitimately look like a host, e.g. 'testssl.sh', 'enum4linux-ng'.
        for a in args[1:]:
            if a.startswith("-"):
                continue                        # flags handled by _check_args
            cand = _host_candidate(a)
            # Dotted IPs are always candidate targets. Bare integers/hex only count as
            # packed-IP obfuscation above 65535 (avoids flagging port/rate/timing values).
            if _DOTTED.match(cand):
                decisions.append(self.check_target(cand))
            elif (_PURE_INT.match(cand) and int(cand) > 65535) or _HEX.match(cand):
                decisions.append(self.check_target(cand))
            elif _looks_like_hostname(cand):
                decisions.append(Decision(False, f"hostname token {cand!r} denied (no DNS)", "scope"))
        for d in decisions:
            if not d.allowed:
                self._deny(tool, args, d.layer, d.reason)
        self.audit.write({"event": "authorize", "tool": tool, "args": args, "targets": targets})

    def authorize_host(self, target: str, check_key: str, catalog: set[str]) -> None:
        """Authorize a credentialed host-audit check.

        Host checks run a vetted, read-only command from a CLOSED catalog over SSH/WinRM.
        We validate target scope + that check_key is in the catalog, and log it — but skip
        the arg-metachar rule, because the remote command is a trusted constant (pipes,
        2>/dev/null are intentional), not agent-supplied input.
        """
        self.budget.check()
        d = self.check_target(_host_candidate(target))
        if not d.allowed:
            self._deny(check_key, [target], d.layer, d.reason)
        if check_key not in catalog:
            self._deny(check_key, [target], "firewall",
                       f"host check {check_key} not in audit catalog (default deny)")
        self.audit.write({"event": "authorize_host", "check": check_key, "target": target})

    def _deny(self, tool: str, args: list[str], layer: str, reason: str) -> None:
        self.audit.write({"event": "deny", "tool": tool, "args": args,
                          "layer": layer, "reason": reason})
        raise GuardrailError(f"[{layer}] {reason}")

    def record(self, tool: str, *, exit_code: int, summary: str) -> None:
        self.audit.write({"event": "exec_done", "tool": tool,
                          "exit_code": exit_code, "summary": summary[:500]})

    # ---- Layer 7: output sanitizer -------------------------------------------
    def sanitize(self, text: str) -> str:
        for pat in self.policy.redact_patterns:
            text = re.sub(pat, "[REDACTED]", text)
        return text
