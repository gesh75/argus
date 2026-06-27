"""LocalSandbox: env scrubbing + process-group timeout teardown.

These lock in the two invariants LocalSandbox must reconstruct now that it runs
tools on the host without the container boundary (see sandbox.py).
"""
import sys

import pytest

from aegis.sandbox import LocalSandbox


@pytest.fixture
def _which_ok(monkeypatch):
    # LocalSandbox gates on nmap/fping being on PATH and re-checks argv[0]; in CI
    # those binaries are absent, so make shutil.which always resolve.
    monkeypatch.setattr("aegis.sandbox.shutil.which", lambda b: "/usr/bin/x")


def test_localsandbox_scrubs_secrets_from_child_env(_which_ok, monkeypatch):
    monkeypatch.setenv("PENTEST_AUDIT_HMAC_KEY", "supersecret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-leakme")
    sb = LocalSandbox(audit_key_env="PENTEST_AUDIT_HMAC_KEY")
    code = ("import os;"
            "print('HMAC=%r' % os.environ.get('PENTEST_AUDIT_HMAC_KEY'));"
            "print('API=%r' % os.environ.get('ANTHROPIC_API_KEY'));"
            "print('PATH_OK=%s' % (os.environ.get('PATH') is not None))")
    res = sb.run([sys.executable, "-c", code], timeout=30)
    assert res.exit_code == 0, res.stderr
    # The signing key and API key must NOT reach the spawned tool...
    assert "HMAC=None" in res.stdout
    assert "API=None" in res.stdout
    # ...but PATH (needed to actually run tools) must survive.
    assert "PATH_OK=True" in res.stdout


def test_localsandbox_timeout_returns_124(_which_ok):
    sb = LocalSandbox(audit_key_env="X")
    res = sb.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1)
    assert res.exit_code == 124
    assert res.timed_out is True


def test_localsandbox_missing_binary_is_clean_127(monkeypatch):
    monkeypatch.setattr("aegis.sandbox.shutil.which",
                        lambda b: "/usr/bin/nmap" if b in ("nmap", "fping") else None)
    sb = LocalSandbox(audit_key_env="X")
    res = sb.run(["definitely-not-installed", "172.30.0.10"], timeout=5)
    assert res.exit_code == 127
    assert "not installed on host" in res.stderr


def test_localsandbox_empty_argv_does_not_crash(_which_ok):
    sb = LocalSandbox(audit_key_env="X")
    res = sb.run([], timeout=5)
    assert res.exit_code == 127
