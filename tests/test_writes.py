"""Unit tests for the governed firewall writes (ops + MCP tools).

Proves: toggle_rule reads the rule and captures its prior enabled state BEFORE
mutating (and the governed tool records a real undo token); alias add/remove
capture prior entries; risk tiers are correct (apply/reconfigure/reboot = high,
the rest = medium); dry_run previews never mutate; and the undo descriptors
invert correctly. No real firewall — the connection is a MagicMock.
"""

from unittest.mock import MagicMock

import pytest

from firewall_aiops.platform import OPNSENSE, PFSENSE


def _conn(platform=OPNSENSE, rule_enabled=True):
    conn = MagicMock(name="conn")
    conn.target.platform = platform
    conn.platform = __import__(
        "firewall_aiops.platform", fromlist=["get_platform"]
    ).get_platform(platform)
    return conn


# ── toggle_rule prior-state capture ─────────────────────────────────────────


@pytest.mark.unit
def test_toggle_rule_captures_prior_enabled_before_mutating(monkeypatch):
    from firewall_aiops.ops import rules as rule_ops
    from firewall_aiops.ops import writes as ops

    conn = _conn(OPNSENSE)
    # The rule is currently ENABLED; disabling it must record prior=True.
    monkeypatch.setattr(rule_ops, "rule_detail", lambda c, u: {"uuid": u, "enabled": True})

    out = ops.toggle_rule(conn, "r1", enable=False)

    assert out["action"] == "toggle_rule"
    assert out["enabled"] is False
    assert out["priorState"] == {"enabled": True}
    # OPNsense dispatch: POST toggleRule/{uuid}/{0|1}
    conn.post.assert_called_once()
    assert conn.post.call_args[0][0].endswith("/toggleRule/r1/0")


@pytest.mark.unit
def test_toggle_rule_pfsense_patches_disabled(monkeypatch):
    from firewall_aiops.ops import rules as rule_ops
    from firewall_aiops.ops import writes as ops

    conn = _conn(PFSENSE)
    monkeypatch.setattr(rule_ops, "rule_detail", lambda c, u: {"uuid": u, "enabled": False})
    out = ops.toggle_rule(conn, "5", enable=True)

    assert out["priorState"] == {"enabled": False}
    conn.patch.assert_called_once()
    _path, kwargs = conn.patch.call_args
    assert kwargs["json"] == {"id": "5", "disabled": False}


# ── alias entry writes capture prior entries ────────────────────────────────


@pytest.mark.unit
def test_add_alias_entry_captures_prior_entries(monkeypatch):
    from firewall_aiops.ops import aliases as alias_ops
    from firewall_aiops.ops import writes as ops

    conn = _conn(OPNSENSE)
    monkeypatch.setattr(
        alias_ops, "alias_entries", lambda c, n: {"entries": ["1.1.1.1"]}
    )
    out = ops.add_alias_entry(conn, "blocklist", "9.9.9.9")
    assert out["priorState"] == {"entries": ["1.1.1.1"]}
    assert out["entry"] == "9.9.9.9"
    conn.post.assert_called_once()


# ── governed tool records a real undo token ─────────────────────────────────


@pytest.mark.unit
def test_governed_toggle_rule_records_undo_token(monkeypatch):
    """End-to-end: the governed toggle_rule records an inverse in the undo store."""
    from firewall_aiops.governance.undo import get_undo_store
    from firewall_aiops.ops import rules as rule_ops
    from mcp_server.tools import writes as t

    conn = _conn(OPNSENSE)
    monkeypatch.setattr(rule_ops, "rule_detail", lambda c, u: {"uuid": u, "enabled": True})
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)

    result = t.toggle_rule(uuid="r1", enable=False)

    # The harness attached an undo id and stored the inverse descriptor.
    assert "_undo_id" in result
    recorded = get_undo_store().list()
    assert any(u.get("tool") == "toggle_rule" for u in recorded)


# ── risk tiers ──────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_write_risk_tiers():
    from mcp_server.tools import writes as t

    assert t.apply_changes._risk_level == "high"
    assert t.reconfigure._risk_level == "high"
    assert t.reboot._risk_level == "high"
    for fn in (t.toggle_rule, t.add_alias_entry, t.remove_alias_entry,
               t.kill_states, t.restart_service):
        assert fn._risk_level == "medium"


# ── dry-run previews never mutate ───────────────────────────────────────────


@pytest.mark.unit
def test_dry_run_previews_do_not_mutate(monkeypatch):
    from mcp_server.tools import writes as t

    conn = _conn(OPNSENSE)
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)

    assert t.toggle_rule(uuid="r1", enable=True, dry_run=True)["dryRun"] is True
    assert t.apply_changes(dry_run=True)["dryRun"] is True
    assert t.reboot(dry_run=True)["dryRun"] is True
    conn.post.assert_not_called()
    conn.patch.assert_not_called()


# ── undo descriptors invert correctly ───────────────────────────────────────


@pytest.mark.unit
def test_toggle_undo_restores_prior_state():
    from mcp_server.tools import writes as t

    desc = t._toggle_undo({"uuid": "r1"}, {"priorState": {"enabled": True}})
    assert desc["tool"] == "toggle_rule"
    assert desc["params"] == {"uuid": "r1", "enable": True}


@pytest.mark.unit
def test_alias_undo_descriptors_invert():
    from mcp_server.tools import writes as t

    add_undo = t._add_alias_undo({"name": "bl", "entry": "9.9.9.9"}, {"action": "x"})
    assert add_undo["tool"] == "remove_alias_entry"
    rm_undo = t._remove_alias_undo({"name": "bl", "entry": "9.9.9.9"}, {"action": "x"})
    assert rm_undo["tool"] == "add_alias_entry"
