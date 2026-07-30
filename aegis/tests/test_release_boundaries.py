"""Release-candidate boundaries for supported V1 and experimental V2."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis import web
from aegis.cli import build_parser
from aegis.continuous import ContinuousRunner
from aegis.evidence import EvidenceGraph


def test_continuous_runner_requires_explicit_experimental_opt_in(
    tmp_path: Path,
) -> None:
    with pytest.raises(RuntimeError, match="experimental"):
        ContinuousRunner(
            guardrail=object(),  # type: ignore[arg-type]
            agents=[],
            graph=EvidenceGraph(),
            persist_path=tmp_path / "graph.json",
        )


def test_experimental_continuous_runner_does_not_suppress_execution_failure(
    tmp_path: Path,
) -> None:
    class FailingAgent:
        def propose(self) -> list[dict[str, object]]:
            return [{"tool": "synthetic", "args": [], "targets": ["192.0.2.1"]}]

        def run_authorized(
            self, tool: str, args: list[str], targets: list[str]
        ) -> None:
            raise RuntimeError("synthetic collector failure")

    runner = ContinuousRunner(
        guardrail=object(),  # type: ignore[arg-type]
        agents=[FailingAgent()],  # type: ignore[list-item]
        graph=EvidenceGraph(),
        persist_path=tmp_path / "graph.json",
        experimental=True,
    )

    with pytest.raises(RuntimeError, match="synthetic collector failure"):
        runner.one_cycle()


def test_top_level_cli_help_warns_that_v2_is_experimental() -> None:
    help_text = build_parser().format_help()

    assert "V2 continuous mode is experimental and unsupported" in help_text


def test_localhost_console_identifies_v2_as_experimental() -> None:
    with TestClient(web.app, client=("127.0.0.1", 50000)) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "V2 continuous mode is experimental and unsupported" in response.text
