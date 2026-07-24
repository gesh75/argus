from __future__ import annotations

import argparse
import json
from dataclasses import fields
from inspect import signature
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


@pytest.mark.parametrize(
    ("anchor_bytes", "expected"),
    [
        (None, AnchorState.MISSING),
        (b"{broken\\n", AnchorState.MALFORMED),
        (
            json.dumps({"seq": 1, "tip": "a" * 64, "ts": 1}).encode()
            + b"\n",
            AnchorState.NOT_COMPARABLE,
        ),
    ],
)
def test_invalid_log_still_inspects_anchor_under_same_operation(
    tmp_path: Path,
    monkeypatch,
    anchor_bytes: bytes | None,
    expected: AnchorState,
) -> None:
    monkeypatch.setenv("PENTEST_AUDIT_HMAC_KEY", "k" * 32)
    policy = Policy.load(policy_file(tmp_path, anchor=True))
    policy.audit_path.write_bytes(b'{"event":"private"}\n')
    policy.audit_path.chmod(0o600)
    if anchor_bytes is not None:
        policy.audit_anchor_path.write_bytes(anchor_bytes)
        policy.audit_anchor_path.chmod(0o600)
    report = AuditLog._for_diagnostics(policy).inspect()
    assert report.error_code is AuditFailureCode.INVALID_SCHEMA
    assert report.error_record == 1
    assert report.anchor_state is expected


def test_invalid_log_with_unsafe_anchor_parent_is_operational_failure(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("PENTEST_AUDIT_HMAC_KEY", "k" * 32)
    policy = Policy.load(policy_file(tmp_path))
    policy.audit_path.write_bytes(b'{"event":"private"}\n')
    policy.audit_path.chmod(0o600)
    unsafe = tmp_path / "unsafe-anchor-parent"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    object.__setattr__(policy, "audit_anchor_path", unsafe / "anchor.json")
    with pytest.raises(AuditStorageError) as error:
        AuditLog._for_diagnostics(policy).inspect()
    assert error.value.code is AuditFailureCode.UNSAFE_MODE


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
        == 1
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


@pytest.mark.parametrize(
    "recovery_flag", ["bootstrap_anchor", "reconcile_anchor"]
)
def test_recovery_requires_confirmation(
    tmp_path: Path, monkeypatch, recovery_flag: str
) -> None:
    monkeypatch.setenv("PENTEST_AUDIT_HMAC_KEY", "k" * 32)
    args = argparse.Namespace(
        policy=str(policy_file(tmp_path, anchor=True)),
        bootstrap_anchor=recovery_flag == "bootstrap_anchor",
        reconcile_anchor=recovery_flag == "reconcile_anchor",
        confirm=False,
    )
    assert cli.cmd_audit(args) == 1
    assert not (tmp_path / "audit.ndjson").exists()
    assert not (tmp_path / "anchor.json").exists()


@pytest.mark.parametrize(
    "raw",
    [
        b"{broken\n",
        b"[]\n",
        b"\xff\n",
    ],
)
def test_cli_integrity_formats_return_one(
    tmp_path: Path, monkeypatch, raw: bytes
) -> None:
    monkeypatch.setenv("PENTEST_AUDIT_HMAC_KEY", "k" * 32)
    path = policy_file(tmp_path)
    log_path = tmp_path / "audit.ndjson"
    log_path.write_bytes(raw)
    log_path.chmod(0o600)
    assert (
        cli.cmd_audit(
            argparse.Namespace(
                policy=str(path),
                bootstrap_anchor=False,
                reconcile_anchor=False,
                confirm=False,
            )
        )
        == 1
    )


@pytest.mark.parametrize(
    "code",
    [
        AuditFailureCode.LOCK_TIMEOUT,
        AuditFailureCode.UNSAFE_PARENT,
        AuditFailureCode.IO_FAILURE,
    ],
)
def test_cli_operational_storage_failures_return_two(
    tmp_path: Path, monkeypatch, code: AuditFailureCode
) -> None:
    monkeypatch.setenv("PENTEST_AUDIT_HMAC_KEY", "k" * 32)

    def fail(_policy):
        raise AuditStorageError(code)

    monkeypatch.setattr(AuditLog, "_for_diagnostics", fail)
    assert (
        cli.cmd_audit(
            argparse.Namespace(
                policy=str(policy_file(tmp_path)),
                bootstrap_anchor=False,
                reconcile_anchor=False,
                confirm=False,
            )
        )
        == 2
    )


def test_cli_missing_key_returns_two(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("PENTEST_AUDIT_HMAC_KEY", raising=False)
    assert (
        cli.cmd_audit(
            argparse.Namespace(
                policy=str(policy_file(tmp_path)),
                bootstrap_anchor=False,
                reconcile_anchor=False,
                confirm=False,
            )
        )
        == 2
    )


def test_no_operational_crash_control_exists() -> None:
    from aegis.audit_storage import AuditStorage

    parser = cli.build_parser()
    option_names = {
        option
        for action in parser._actions
        for option in action.option_strings
    }
    policy_fields = {field.name for field in fields(Policy)}
    constructor_parameters = set(signature(AuditStorage).parameters)
    surfaces = option_names | policy_fields | constructor_parameters
    assert not any(
        "crash" in name or "checkpoint" in name for name in surfaces
    )
