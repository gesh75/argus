"""Regression tests for the four CodeQL alerts opened on main (2026-07-28).

- #4 High   polynomial-redos          aegis/reporting.py  -> linear _split_denial()
- #1/2/3 Med information exposure     aegis/web.py        -> generic _error(), detail logged
"""
import os

os.environ.setdefault("PENTEST_AUDIT_HMAC_KEY", "k" * 32)

import re

import pytest

from aegis.reporting import _split_denial, collapse_errors

# The pattern _split_denial replaced. Kept ONLY as the behavioural oracle so the
# refactor is provably equivalent — it must never be used on real input again.
_LEGACY = re.compile(r"\s*\S+\s+(\S+):\s*(.*)")


def _legacy(e: str):
    m = _LEGACY.match(e)
    return (m.group(1), m.group(2)) if m else None


@pytest.mark.parametrize("line", [
    "nmap-smb 1.2.3.4: DENIED [scope] out of range",
    "  nmap 10.0.0.1:   DENIED [tool firewall]",
    "tool [fe80::1]: ipv6 target keeps its inner colons",
    "tool 1.2.3.4:DENIED  double  space  preserved",
    "tool\t1.2.3.4:\tTAB separated",
    "a b:",                      # empty reason
    "a b:c:d rest here",         # greedy \S+ binds to the LAST colon
    "no-colon-here at all",      # no match
    "single",                    # too few tokens
    "",
    "   ",
])
def test_split_denial_matches_legacy_regex(line):
    """The linear parser is byte-for-byte equivalent to the regex it replaced."""
    assert _split_denial(line) == _legacy(line)


def test_split_denial_is_linear_on_adversarial_input():
    """A long colon-free token (reachable from untrusted tool output) stays fast.

    Guards the property CodeQL flagged: no super-linear backtracking. Generous bound —
    this asserts "not pathological", not a micro-benchmark.
    """
    import time
    evil = "tool " + "A" * 200_000
    start = time.perf_counter()
    assert _split_denial(evil) is None
    assert time.perf_counter() - start < 1.0


def test_collapse_errors_still_groups_by_reason():
    """End-to-end behaviour of the caller is unchanged by the refactor."""
    out = collapse_errors([
        "nmap 1.1.1.1: DENIED [scope]",
        "nmap 2.2.2.2: DENIED [scope]",
        "nmap 3.3.3.3: DENIED [scope]",
        "curl 4.4.4.4: DENIED [tool firewall]",
    ])
    assert any("3 targets" in line and "DENIED [scope]" in line for line in out)
    assert any("4.4.4.4: DENIED [tool firewall]" == line for line in out)


def test_collapse_errors_passes_through_unparseable_lines():
    assert collapse_errors(["totally unparseable"]) == ["totally unparseable"]


# ---- web.py: exception detail must not reach the client ---------------------
def test_guardrail_error_detail_is_not_returned_to_client(monkeypatch):
    """A GuardrailError must yield a generic body — never str(exc).

    The real messages leak the audit key env var name, its length, or audit-storage
    paths; the console is localhost-only but the project's Phase 1 contract requires
    generic API errors regardless.
    """
    from fastapi.testclient import TestClient

    from aegis import web

    leaky_detail = "audit key too short (12<32 chars) at /srv/secret/path"

    def _boom(*_a, **_kw):
        raise web.GuardrailError(leaky_detail)

    monkeypatch.setattr(web, "Guardrail", _boom)
    # loopback peer: the console enforces its deployment boundary from the socket peer
    client = TestClient(web.app, client=("127.0.0.1", 50000))
    resp = client.post("/api/scan", json={"targets": ["172.30.0.10"]})

    assert resp.status_code == 400
    body = resp.text
    assert leaky_detail not in body
    assert "32 chars" not in body
    assert "/srv/secret/path" not in body
    assert resp.json() == {"error": "guardrail initialization failed"}
    # the generic helper also applies the no-store header the raw handler skipped
    assert resp.headers.get("Cache-Control") == "no-store"
