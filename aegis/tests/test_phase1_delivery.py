"""Delivery-contract tests for Phase 1 dependencies, packaging, and documentation."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AEGIS_ROOT = REPO_ROOT / "aegis"


def test_networkx_is_a_declared_runtime_dependency() -> None:
    requirements = (AEGIS_ROOT / "requirements.txt").read_text().lower()
    project = tomllib.loads((AEGIS_ROOT / "pyproject.toml").read_text())["project"]
    dependencies = [dependency.lower() for dependency in project["dependencies"]]

    assert re.search(r"^networkx[^\n]*$", requirements, re.MULTILINE)
    assert any(dependency.startswith("networkx") for dependency in dependencies)
    assert project["version"] != "0.0.0"


def test_networkx_is_hash_locked() -> None:
    lock = (AEGIS_ROOT / "requirements.lock").read_text().lower()

    assert re.search(r"^networkx==[^\n]+\\$", lock, re.MULTILINE)


def test_no_active_documentation_uses_the_invalid_short_audit_key() -> None:
    weak_command = "PENTEST_AUDIT_HMAC_KEY=" + "test"
    active_files = [
        REPO_ROOT / "README.md",
        AEGIS_ROOT / "README.md",
        AEGIS_ROOT / "BUILD_AND_TEST_LOG.md",
        *sorted((REPO_ROOT / "docs").glob("*.md")),
    ]

    offenders = [str(path.relative_to(REPO_ROOT)) for path in active_files if weak_command in path.read_text()]
    assert offenders == []


def test_phase1_documentation_states_the_enforced_boundaries() -> None:
    phase1 = REPO_ROOT / "docs" / "PHASE1_SAFETY_BOUNDARY_IMPLEMENTATION.md"
    text = phase1.read_text().lower()

    assert "all redirects" in text and "refused" in text
    assert "localhost-only" in text
    assert "live" in text and "disabled by default" in text
    assert "phase 2" in text and "not implemented" in text
