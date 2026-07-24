from __future__ import annotations

import argparse
from pathlib import Path

import pytest
import yaml

from aegis import cli
from aegis.audit_storage import (
    AnchorState,
    AuditFailureCode,
    AuditStorageError,
    LogState,
)
from aegis.config import DEFAULT_POLICY, Policy
from aegis.guardrail import AuditLog


def policy_file(tmp_path: Path, *, anchor: bool = False) -> Path:
    data = yaml.safe_load(DEFAULT_POLICY.read_text())
    data["audit"]["path"] = str(tmp_path / "audit.ndjson")
    data["audit"]["anchor_path"] = (
        str(tmp_path / "anchor.json") if anchor else None
    )
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data))
    return path


def test_diagnostic_empty_log_is_read_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PENTEST_AUDIT_HMAC_KEY", "k" * 32)
    policy = Policy.load(policy_file(tmp_path))
    diagnostic = AuditLog._for_diagnostics(policy)
    report = diagnostic.inspect()
    assert report.log_state is LogState.EMPTY
    assert report.anchor_state is AnchorState.DISABLED
    assert report.record_count == 0
    assert not policy.audit_path.exists()
    with pytest.raises(AuditStorageError) as error:
        diagnostic.write({"event": "forbidden"})
    assert error.value.code is AuditFailureCode.WRITE_DISABLED


def test_diagnostic_classifies_malformed_without_normal_construction(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("PENTEST_AUDIT_HMAC_KEY", "k" * 32)
    policy = Policy.load(policy_file(tmp_path))
    policy.audit_path.write_bytes(b'{"event":"secret-value"}\n')
    policy.audit_path.chmod(0o600)
    report = AuditLog._for_diagnostics(policy).inspect()
    assert report.log_state is LogState.INVALID_SCHEMA
    assert report.anchor_state is AnchorState.DISABLED
    assert report.error_code is AuditFailureCode.INVALID_SCHEMA
    assert report.error_record == 1


def test_cmd_audit_does_not_construct_guardrail(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("PENTEST_AUDIT_HMAC_KEY", "k" * 32)
    monkeypatch.setattr(
        cli, "_guard", lambda _args: pytest.fail("Guardrail was constructed")
    )
    args = argparse.Namespace(
        policy=str(policy_file(tmp_path)),
        bootstrap_anchor=False,
        reconcile_anchor=False,
        confirm=False,
    )
    assert cli.cmd_audit(args) == 0
    output = capsys.readouterr().out
    assert "log_state=empty" in output
    assert "anchor_state=disabled" in output
    assert "tip=" not in output


def test_cmd_audit_maps_integrity_failure_to_one(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("PENTEST_AUDIT_HMAC_KEY", "k" * 32)
    path = policy_file(tmp_path)
    (tmp_path / "audit.ndjson").write_bytes(b'{"event":"private"}\n')
    (tmp_path / "audit.ndjson").chmod(0o600)
    args = argparse.Namespace(
        policy=str(path),
        bootstrap_anchor=False,
        reconcile_anchor=False,
        confirm=False,
    )
    assert cli.cmd_audit(args) == 1
    output = capsys.readouterr().out
    assert "error=invalid-schema" in output
    assert "private" not in output


def test_audit_help_exposes_mutually_exclusive_recovery_flags(capsys) -> None:
    parser = cli.build_parser()
    with pytest.raises(SystemExit) as exit_info:
        parser.parse_args(["audit", "--help"])
    assert exit_info.value.code == 0
    output = capsys.readouterr().out
    assert "--bootstrap-anchor" in output
    assert "--reconcile-anchor" in output
    assert "--confirm" in output
    with pytest.raises(SystemExit) as conflict:
        parser.parse_args(
            ["audit", "--bootstrap-anchor", "--reconcile-anchor"]
        )
    assert conflict.value.code == 2


def test_cli_bootstrap_requires_confirmation_then_succeeds(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("PENTEST_AUDIT_HMAC_KEY", "k" * 32)
    no_anchor_path = policy_file(tmp_path)
    policy = Policy.load(no_anchor_path)
    AuditLog(policy).write({"event": "one"})
    configured_path = policy_file(tmp_path, anchor=True)
    assert (
        cli.main(
            [
                "--policy",
                str(configured_path),
                "audit",
                "--bootstrap-anchor",
            ]
        )
        == 2
    )
    assert (
        cli.main(
            [
                "--policy",
                str(configured_path),
                "audit",
                "--bootstrap-anchor",
                "--confirm",
            ]
        )
        == 0
    )
