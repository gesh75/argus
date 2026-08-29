"""Browser-executed DOM security suite — fixture inventory and static contract.

The LATER binary exit gate is: malicious fixtures execute no script and render
only as text in a real browser. This increment lands the fixture inventory and
proves the localhost console cannot parse them as markup. Playwright execution
against a live page remains the remaining UI gate.
"""

from __future__ import annotations

import html
import re
from pathlib import Path

STATIC = Path(__file__).resolve().parents[1] / "aegis" / "static" / "index.html"

DOM_FIXTURES = (
    {
        "id": "script-tag",
        "name": "Inline script in finding title",
        "payload": '<script>window.__argusPwned="script"</script>critical finding',
    },
    {
        "id": "img-onerror",
        "name": "img onerror handler",
        "payload": '<img src=x onerror="window.__argusPwned=\'img\'">',
    },
    {
        "id": "svg-onload",
        "name": "SVG onload",
        "payload": '<svg onload="window.__argusPwned=\'svg\'"></svg>',
    },
    {
        "id": "js-url",
        "name": "javascript: URL",
        "payload": "javascript:window.__argusPwned='jsurl'",
    },
    {
        "id": "srcdoc",
        "name": "iframe srcdoc",
        "payload": (
            '<iframe srcdoc="<script>window.parent.__argusPwned=\'srcdoc\'</script>">'
            "</iframe>"
        ),
    },
    {
        "id": "event-handler",
        "name": "Element with onmouseover",
        "payload": '<div onmouseover="window.__argusPwned=\'hover\'">hover me</div>',
    },
)


def test_fixture_inventory_is_complete() -> None:
    ids = [item["id"] for item in DOM_FIXTURES]
    assert ids == [
        "script-tag",
        "img-onerror",
        "svg-onload",
        "js-url",
        "srcdoc",
        "event-handler",
    ]
    assert all(item["payload"] for item in DOM_FIXTURES)


def test_textcontent_equivalent_escaping_neutralizes_every_payload() -> None:
    """textContent is the browser analog of HTML escaping into a text node."""
    for item in DOM_FIXTURES:
        escaped = html.escape(item["payload"], quote=True)
        assert "<" not in escaped
        assert ">" not in escaped
        if item["payload"].lstrip().startswith("<"):
            assert escaped.startswith(html.escape("<"))


def test_static_console_has_no_html_sinks() -> None:
    source = STATIC.read_text()
    prohibited = re.compile(
        r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\bonerror\b|\bonload\b"
    )
    assert prohibited.search(source) is None
    assert "textContent" in source
    assert "replaceChildren" in source
    assert "createElement" in source


def test_static_console_does_not_embed_malicious_fixtures() -> None:
    source = STATIC.read_text()
    for item in DOM_FIXTURES:
        assert item["payload"] not in source
