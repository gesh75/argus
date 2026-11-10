"""Browser-executed DOM security suite — fixture inventory, static contract, and Playwright execution.

The LATER binary exit gate is: malicious fixtures execute no script and render
only as text in a real browser. Malicious fixtures execute zero script and render
only as safe text under Playwright against the live localhost FastAPI console with
strict CSP.
"""

from __future__ import annotations

import html
import re
import shutil
import socket
import threading
import time
from pathlib import Path

import pytest
import uvicorn

from aegis.web import _CSP, app

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
        "payload": "<img src=x onerror=\"window.__argusPwned='img'\">",
    },
    {
        "id": "svg-onload",
        "name": "SVG onload",
        "payload": "<svg onload=\"window.__argusPwned='svg'\"></svg>",
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
            "<iframe srcdoc=\"<script>window.parent.__argusPwned='srcdoc'</script>\"></iframe>"
        ),
    },
    {
        "id": "event-handler",
        "name": "Element with onmouseover",
        "payload": "<div onmouseover=\"window.__argusPwned='hover'\">hover me</div>",
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


def test_playwright_live_console_executes_no_malicious_fixtures() -> None:
    # Optional extra: skip this test only. A module-level importorskip would
    # drop the static fixture/contract tests that CI must still collect.
    playwright_sync_api = pytest.importorskip("playwright.sync_api")
    sync_playwright = playwright_sync_api.sync_playwright
    chromium_path = shutil.which("chromium") or shutil.which("chromium-browser")
    if not chromium_path:
        pytest.skip("Chromium browser not found on host")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        assert server.started, "Live uvicorn server failed to start within 5s"

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=chromium_path,
                headless=True,
            )
            page = browser.new_page()
            response = page.goto(f"http://127.0.0.1:{port}/")
            assert response is not None
            assert response.status == 200
            headers = response.headers
            assert headers.get("content-security-policy") == _CSP
            assert headers.get("x-frame-options") == "DENY"
            assert headers.get("x-content-type-options") == "nosniff"
            assert headers.get("referrer-policy") == "no-referrer"

            findings = [
                {
                    "severity": "Critical",
                    "title": item["payload"],
                    "affected_asset": f"asset-{item['id']}",
                    "cvss31_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "mitre_attack": "T1190",
                    "confidence": "high",
                    "mitigation_steps": [f"step for {item['payload']}"],
                }
                for item in DOM_FIXTURES
            ]
            page.evaluate("findings => renderResult({ findings })", findings)

            assert page.evaluate("() => window.__argusPwned") is None

            text = page.locator("#out").inner_text()
            for item in DOM_FIXTURES:
                assert item["payload"] in text

            # Exercise mouse movement across rendered rows to verify event handler payload does not fire
            page.mouse.move(100, 200)
            page.mouse.move(200, 300)
            assert page.evaluate("() => window.__argusPwned") is None

            browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=5)
