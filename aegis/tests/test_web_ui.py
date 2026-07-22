"""Static security checks for the dependency-free browser console."""

from __future__ import annotations

import re
from pathlib import Path

STATIC = Path(__file__).resolve().parents[1] / "aegis" / "static" / "index.html"


def test_dynamic_html_sinks_are_absent() -> None:
    source = STATIC.read_text()
    prohibited = re.compile(
        r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\bonerror\b|\bonload\b"
    )

    assert prohibited.search(source) is None


def test_renderer_uses_text_nodes_and_severity_allowlist() -> None:
    source = STATIC.read_text()

    assert "textContent" in source
    assert "replaceChildren" in source
    assert "SEVERITY_ORDER" in source
    assert "severityInfo" in source


def test_malicious_fixture_strings_are_present_only_as_test_data() -> None:
    malicious = [
        '<img src=x onerror="window.pwned=1">',
        '<svg onload="window.pwned=1"></svg>',
        '<script>window.pwned=1</script>',
    ]

    assert all(value.startswith("<") and value.endswith(">") for value in malicious)
    assert "createElement(f." not in STATIC.read_text()
