"""CLI confirmed-write path — past dry-run, through governance, onto disk.

The CLI write commands delegate real execution to the ``@governed_tool``
functions in ``mcp_server.tools``. These tests drive ``rules toggle`` PAST the
dry-run branch and the double-confirm prompts and assert the call really went
through the governed path (audit row on disk) — the regression test for the
"CLI writes were unaudited" line-wide fix.
"""

from __future__ import annotations

import sqlite3
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

import firewall_aiops.governance.audit as audit_mod
import firewall_aiops.governance.policy as policy_mod
import firewall_aiops.governance.undo as undo_mod
from firewall_aiops.platform import OPNSENSE, get_platform


@pytest.fixture
def gov_home(tmp_path, monkeypatch):
    monkeypatch.setenv("FIREWALL_AIOPS_HOME", str(tmp_path))
    audit_mod.reset_engine()
    policy_mod.reset_policy_engine()
    undo_mod.reset_undo_store()
    yield tmp_path
    audit_mod.reset_engine()
    policy_mod.reset_policy_engine()
    undo_mod.reset_undo_store()


@pytest.fixture
def fw_conn(monkeypatch):
    """A fake OPNsense connection wired into the governed write module."""
    from firewall_aiops.ops import rules as rule_ops
    from mcp_server.tools import writes as gov

    conn = MagicMock(name="conn")
    conn.target.platform = OPNSENSE
    conn.platform = get_platform(OPNSENSE)
    monkeypatch.setattr(rule_ops, "rule_detail", lambda c, u: {"uuid": u, "enabled": True})
    monkeypatch.setattr(gov, "_get_connection", lambda target=None: conn)
    return conn


def _audit_tools(db_path) -> list[str]:
    conn = sqlite3.connect(db_path)
    try:
        return [r[0] for r in conn.execute("SELECT tool FROM audit_log ORDER BY id")]
    finally:
        conn.close()


@pytest.mark.unit
def test_cli_rules_toggle_dry_run_reads_and_audits_but_never_mutates(gov_home, fw_conn):
    """The invariant: a dry_run MAY read; it must never write.

    It reads the rule (that is the only way it can report managementImpact) and
    lands an audit row like every other governed call — the MCP dry-run always
    did; the CLI silently skipping the audit was the outlier. What it must never
    do is issue the mutating POST/PATCH.
    """
    from firewall_aiops.cli import app

    result = CliRunner().invoke(app, ["rules", "toggle", "r1", "--disable", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "DRY-RUN" in result.output, "the human-readable banner must survive"
    fw_conn.post.assert_not_called(), "the one thing a dry-run may never do"
    fw_conn.patch.assert_not_called()
    assert _audit_tools(gov_home / "audit.db") == ["toggle_rule"]


@pytest.mark.unit
def test_cli_rules_toggle_dry_run_shows_the_management_warning(gov_home, fw_conn, monkeypatch):
    """The preview must surface the same lockout warning the real call reports,
    rendered into the banner rather than dumped as JSON."""
    from firewall_aiops.cli import app
    from firewall_aiops.ops import rules as rule_ops

    fw_conn.target.host = "192.168.1.1"
    fw_conn.target.port = 443
    monkeypatch.setattr(rule_ops, "rule_detail", lambda c, u: {
        "uuid": u, "action": "pass", "enabled": True, "interface": "lan",
        "destination": "192.168.1.1", "destinationPort": "443", "description": "mgmt",
    })

    result = CliRunner().invoke(app, ["rules", "toggle", "r1", "--disable", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "Management impact" in result.output
    assert "192.168.1.1:443" in result.output
    assert "{" not in result.output, "rendered, not raw JSON"
    fw_conn.post.assert_not_called()


@pytest.mark.unit
def test_cli_rules_toggle_confirmed_goes_through_governance(gov_home, fw_conn):
    """Confirmed CLI write must execute via the governed twin: the API call
    fires AND an audit row lands in audit.db (this is what the reroute fix
    bought)."""
    from firewall_aiops.cli import app

    result = CliRunner().invoke(app, ["rules", "toggle", "r1", "--disable"], input="y\ny\n")
    assert result.exit_code == 0, result.output
    fw_conn.post.assert_called_once()
    assert _audit_tools(gov_home / "audit.db") == ["toggle_rule"]


@pytest.mark.unit
def test_cli_rules_toggle_aborts_without_double_confirm(gov_home, fw_conn):
    from firewall_aiops.cli import app

    result = CliRunner().invoke(app, ["rules", "toggle", "r1", "--disable"], input="y\nn\n")
    assert result.exit_code != 0
    fw_conn.post.assert_not_called()
    fw_conn.patch.assert_not_called()
    assert not (gov_home / "audit.db").exists()
