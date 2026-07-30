"""Behavioral checks for the generated repository control dashboard."""

from __future__ import annotations

import json
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATOR = REPO_ROOT / "scripts" / "generate_control_dashboard.py"
STATUS = REPO_ROOT / "docs" / "control" / "STATUS.json"
DASHBOARD = REPO_ROOT / "docs" / "index.html"
SNAPSHOT_FILES = {
    "docs/control/STATUS.json",
    "docs/index.html",
}
SOURCE_FILES = {
    "README.md",
    "aegis/README.md",
    "aegis/SECURITY.md",
    "aegis/docs/AGENTIC_ROADMAP.md",
    "aegis/docs/NEXT_STEPS.md",
    "docs/control/AGENT_HANDOFF.md",
    "docs/control/CHANGELOG.md",
    "docs/control/DECISIONS.md",
    "docs/control/PROJECT_CONTROL.md",
    "docs/control/ROADMAP.md",
    "docs/control/RUNBOOK.md",
    "scripts/generate_control_dashboard.py",
}


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.hrefs: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.add(values["id"] or "")
        if tag == "a" and values.get("href"):
            self.hrefs.append(values["href"] or "")


def _generate(output: Path) -> bytes:
    subprocess.run(
        [sys.executable, str(GENERATOR), "--output", str(output)],
        cwd=REPO_ROOT,
        check=True,
    )
    return output.read_bytes()


def test_dashboard_generation_is_byte_identical(tmp_path: Path) -> None:
    first = _generate(tmp_path / "first.html")
    second = _generate(tmp_path / "second.html")

    assert first == second


def test_status_json_has_the_machine_readable_release_contract() -> None:
    status = json.loads(STATUS.read_text())
    required = {
        "schema_version",
        "generated_at",
        "repository",
        "current_main_sha",
        "active_branch",
        "head_sha",
        "source_commit",
        "dirty",
        "release_target",
        "maturity",
        "supported_deployment_modes",
        "unsupported_deployment_modes",
        "test_results",
        "lint_results",
        "bandit",
        "dependency_audit",
        "codeql",
        "open_pull_requests",
        "open_issues",
        "blockers",
        "next_action",
        "documentation_freshness",
    }

    assert required <= status.keys()
    assert status["schema_version"] == 1
    assert status["repository"] == "gesh75/argus"
    assert status["dirty"] is False


def test_dashboard_contains_every_required_control_section() -> None:
    html = DASHBOARD.read_text()
    required_sections = {
        "Project status",
        "Release target",
        "Git and CI state",
        "Completed milestones",
        "Phase roadmap",
        "Blocker matrix",
        "Next exact action",
        "Architecture",
        "V1 execution flow",
        "V2 experimental flow",
        "Test and security evidence",
        "Decisions",
        "Operations and rollback",
        "Source commit",
        "Last updated",
    }

    assert all(section in html for section in required_sections)


def test_dashboard_internal_links_resolve() -> None:
    parser = _LinkParser()
    parser.feed(DASHBOARD.read_text())
    missing: list[str] = []

    for href in parser.hrefs:
        parsed = urlsplit(href)
        if parsed.scheme or parsed.netloc:
            continue
        if parsed.path:
            target = (DASHBOARD.parent / unquote(parsed.path)).resolve()
            if not target.exists():
                missing.append(href)
        if parsed.fragment and not parsed.path and parsed.fragment not in parser.ids:
            missing.append(href)

    assert missing == []


def test_readme_links_to_control_pack_and_dashboard() -> None:
    readme = (REPO_ROOT / "README.md").read_text()

    assert "docs/control/PROJECT_CONTROL.md" in readme
    assert "docs/index.html" in readme


def test_generated_documentation_matches_its_source_commit() -> None:
    status = json.loads(STATUS.read_text())
    source_commit = status["source_commit"]
    source_is_available = (
        subprocess.run(
            ["git", "cat-file", "-e", f"{source_commit}^{{commit}}"],
            cwd=REPO_ROOT,
            check=False,
        ).returncode
        == 0
    )

    if not source_is_available:
        shallow = subprocess.check_output(
            ["git", "rev-parse", "--is-shallow-repository"],
            cwd=REPO_ROOT,
            text=True,
        ).strip()
        raw_head = subprocess.check_output(
            ["git", "cat-file", "commit", "HEAD"],
            cwd=REPO_ROOT,
            text=True,
        )

        assert shallow == "true"
        assert f"parent {source_commit}\n" in raw_head
        expected = _generate(DASHBOARD.parent / ".index.generated-test.html")
        try:
            assert expected == DASHBOARD.read_bytes()
        finally:
            (DASHBOARD.parent / ".index.generated-test.html").unlink()
        return

    distance = int(
        subprocess.check_output(
            ["git", "rev-list", "--count", f"{source_commit}..HEAD"],
            cwd=REPO_ROOT,
            text=True,
        ).strip()
    )

    assert distance in {0, 1}
    if distance == 1:
        changed = set(
            subprocess.check_output(
                ["git", "diff", "--name-only", f"{source_commit}..HEAD"],
                cwd=REPO_ROOT,
                text=True,
            ).splitlines()
        )
        assert changed == SNAPSHOT_FILES

    for relative_path in SOURCE_FILES:
        committed = subprocess.check_output(
            ["git", "show", f"{source_commit}:{relative_path}"],
            cwd=REPO_ROOT,
        )
        assert committed == (REPO_ROOT / relative_path).read_bytes()

    expected = _generate(DASHBOARD.parent / ".index.generated-test.html")
    try:
        assert expected == DASHBOARD.read_bytes()
    finally:
        (DASHBOARD.parent / ".index.generated-test.html").unlink()
