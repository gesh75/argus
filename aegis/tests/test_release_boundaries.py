"""Release-candidate boundaries for supported V1 and experimental V2."""

from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from aegis import web
from aegis.cli import build_parser
from aegis.continuous import ContinuousRunner
from aegis.evidence import EvidenceGraph


def test_continuous_runner_requires_explicit_experimental_opt_in(tmp_path) -> None:
    with pytest.raises(RuntimeError, match="experimental"):
        ContinuousRunner(
            guardrail=object(),  # type: ignore[arg-type]
            agents=[],
            graph=EvidenceGraph(),
            persist_path=tmp_path / "graph.json",
        )


def test_top_level_cli_help_warns_that_v2_is_experimental() -> None:
    help_text = build_parser().format_help()

    assert "V2 continuous mode is experimental and unsupported" in help_text


def test_localhost_console_identifies_v2_as_experimental() -> None:
    with TestClient(web.app, client=("127.0.0.1", 50000)) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "V2 continuous mode is experimental and unsupported" in response.text
