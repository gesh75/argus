"""Behavioral checks for the generated repository control dashboard."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
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


def _parent_headers(raw_commit: str) -> set[str]:
    return {
        line.removeprefix("parent ")
        for line in raw_commit.splitlines()
        if line.startswith("parent ")
    }


def _validate_shallow_source_topology(
    *,
    status: dict[str, Any],
    raw_head: str,
    current_head: str,
    event: dict[str, Any],
) -> None:
    parents = _parent_headers(raw_head)
    source_commit = status["source_commit"]
    if source_commit in parents:
        return

    pull_request = event.get("pull_request")
    if pull_request is not None:
        pull_request_head = pull_request["head"]
        assert pull_request_head["sha"] in parents
        assert pull_request_head["ref"] == status["active_branch"]
        return

    assert event["ref"] == "refs/heads/main"
    assert event["after"] == current_head
    assert status["current_main_sha"] in parents
    assert len(parents) == 2


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
    assert "Generation HEAD" in html
    assert "Active HEAD" not in html


def test_v2_docs_match_failure_propagation_behavior() -> None:
    paths = [
        REPO_ROOT / "docs" / "control" / "PROJECT_CONTROL.md",
        REPO_ROOT / "docs" / "V2_ROADMAP_STATUS.md",
        REPO_ROOT / "docs" / "V2_ARCHITECTURE.md",
    ]

    for path in paths:
        content = path.read_text()
        assert "broad exceptions are suppressed" not in content
        assert "collector failures" in content


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


def test_shallow_source_topology_accepts_pull_request_merge() -> None:
    status = {
        "source_commit": "source",
        "current_main_sha": "base",
        "active_branch": "fix/release",
    }
    raw_head = "tree tree\nparent base\nparent carrier\n\nPR merge"
    event = {
        "pull_request": {
            "head": {
                "ref": "fix/release",
                "sha": "carrier",
            }
        }
    }

    _validate_shallow_source_topology(
        status=status,
        raw_head=raw_head,
        current_head="synthetic-merge",
        event=event,
    )


def test_shallow_source_topology_accepts_main_push_merge() -> None:
    status = {
        "source_commit": "source",
        "current_main_sha": "base",
        "active_branch": "fix/release",
    }
    raw_head = "tree tree\nparent base\nparent carrier\n\nMerged PR"
    event = {
        "ref": "refs/heads/main",
        "after": "merge",
    }

    _validate_shallow_source_topology(
        status=status,
        raw_head=raw_head,
        current_head="merge",
        event=event,
    )


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
        current_head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            text=True,
        ).strip()
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        event = json.loads(Path(event_path).read_text()) if event_path else {}

        assert shallow == "true"
        _validate_shallow_source_topology(
            status=status,
            raw_head=raw_head,
            current_head=current_head,
            event=event,
        )

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

    assert distance in {0, 1, 2}
    if distance:
        changed = set(
            subprocess.check_output(
                ["git", "diff", "--name-only", f"{source_commit}..HEAD"],
                cwd=REPO_ROOT,
                text=True,
            ).splitlines()
        )
        assert changed == SNAPSHOT_FILES
    if distance == 2:
        first_parent = subprocess.check_output(
            ["git", "rev-parse", "HEAD^1"],
            cwd=REPO_ROOT,
            text=True,
        ).strip()
        feature_source = subprocess.check_output(
            ["git", "rev-parse", "HEAD^2^"],
            cwd=REPO_ROOT,
            text=True,
        ).strip()

        assert first_parent == status["current_main_sha"]
        assert feature_source == source_commit

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
