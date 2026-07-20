"""Extra governed-write ops coverage (ops.writes) — the platform-specific write
dispatch and central path encoding, proven against a MagicMock connection (never
a live firewall). Asserts the *exact* endpoint + params each write sends on each
platform, and that reversible writes capture prior state.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from firewall_aiops.ops import aliases as alias_ops
from firewall_aiops.ops import writes as ops
from firewall_aiops.platform import OPNSENSE, PFSENSE, get_platform


def _conn(platform=OPNSENSE):
    conn = MagicMock(name="conn")
    conn.target.platform = platform
    conn.platform = get_platform(platform)
    return conn


# ── alias remove (both platforms) ────────────────────────────────────────────


@pytest.mark.unit
def test_remove_alias_entry_opnsense_posts_delete_path(monkeypatch):
    conn = _conn(OPNSENSE)
    monkeypatch.setattr(
        alias_ops, "alias_entries", lambda c, n: {"entries": ["9.9.9.9", "1.1.1.1"]}
    )
    out = ops.remove_alias_entry(conn, "blocklist", "9.9.9.9")
    assert out["action"] == "remove_alias_entry"
    assert out["priorState"] == {"entries": ["9.9.9.9", "1.1.1.1"]}
    conn.post.assert_called_once()
    path, kwargs = conn.post.call_args
    assert path[0].endswith("/alias_util/delete/blocklist")
    assert kwargs["json"] == {"address": "9.9.9.9"}


@pytest.mark.unit
def test_remove_alias_entry_pfsense_uses_delete_verb(monkeypatch):
    conn = _conn(PFSENSE)
    monkeypatch.setattr(alias_ops, "alias_entries", lambda c, n: {"entries": ["1.1.1.1"]})
    out = ops.remove_alias_entry(conn, "bl", "1.1.1.1")
    conn.delete.assert_called_once()
    _path, kwargs = conn.delete.call_args
    assert kwargs["json"] == {"name": "bl", "address": ["1.1.1.1"]}
    assert out["priorState"] == {"entries": ["1.1.1.1"]}


@pytest.mark.unit
def test_add_alias_entry_pfsense_wraps_address_list(monkeypatch):
    conn = _conn(PFSENSE)
    monkeypatch.setattr(alias_ops, "alias_entries", lambda c, n: {"entries": []})
    ops.add_alias_entry(conn, "bl", "2.2.2.2")
    _path, kwargs = conn.post.call_args
    assert kwargs["json"] == {"name": "bl", "address": ["2.2.2.2"]}


@pytest.mark.unit
def test_capture_alias_survives_non_dict():
    """A best-effort snapshot returns [] when the read returns no dict."""
    conn = _conn(OPNSENSE)
    conn.get.return_value = {}
    # alias_ops.alias_entries returns a dict normally; force a non-dict via monkeypatch-free path
    entries = ops._capture_alias(conn, "missing")
    assert isinstance(entries, list)


# ── apply / reconfigure ──────────────────────────────────────────────────────


@pytest.mark.unit
def test_apply_changes_posts_apply_path():
    conn = _conn(OPNSENSE)
    out = ops.apply_changes(conn)
    assert out["action"] == "apply_changes"
    assert out["platform"] == OPNSENSE
    assert out["applied"] is True
    assert out["override"] is False
    # No staged rule threatens the management path here (see test_lockout_guards).
    assert out["managementImpact"] is None
    conn.post.assert_called_once_with("/api/firewall/filter/apply")


@pytest.mark.unit
def test_reconfigure_sends_subsystem():
    conn = _conn(PFSENSE)
    out = ops.reconfigure(conn, "nat")
    assert out["subsystem"] == "nat" and out["platform"] == PFSENSE
    _path, kwargs = conn.post.call_args
    assert kwargs["json"] == {"subsystem": "nat"}


# ── kill_states (both platforms) ─────────────────────────────────────────────


@pytest.mark.unit
def test_kill_states_opnsense_posts_filter():
    conn = _conn(OPNSENSE)
    out = ops.kill_states(conn, "9.9.9.9")
    assert out["action"] == "kill_states"
    assert out["filter"] == "9.9.9.9"
    # The flush drops this tool's own connection state; the result has to say so.
    assert "lost response" in out["note"]
    _path, kwargs = conn.post.call_args
    assert kwargs["json"] == {"filter": "9.9.9.9"}


@pytest.mark.unit
def test_kill_states_pfsense_uses_delete_and_all_default():
    conn = _conn(PFSENSE)
    out = ops.kill_states(conn)  # no filter → "all"
    assert out["filter"] == "all"
    conn.delete.assert_called_once()
    _path, kwargs = conn.delete.call_args
    assert kwargs["json"] is None


# ── restart_service / reboot ─────────────────────────────────────────────────


@pytest.mark.unit
def test_restart_service_encodes_service_in_path():
    conn = _conn(OPNSENSE)
    out = ops.restart_service(conn, "unbound")
    assert out == {"action": "restart_service", "service": "unbound"}
    conn.post.assert_called_once_with("/api/core/service/restart/unbound")


@pytest.mark.unit
def test_reboot_posts_reboot_path():
    conn = _conn(PFSENSE)
    out = ops.reboot(conn)
    assert out == {"action": "reboot", "platform": PFSENSE, "rebooting": True}
    conn.post.assert_called_once_with("/api/v2/diagnostics/reboot")


@pytest.mark.unit
def test_toggle_rule_prior_state_none_when_detail_errors(monkeypatch):
    from firewall_aiops.ops import rules as rule_ops

    conn = _conn(OPNSENSE)
    monkeypatch.setattr(rule_ops, "rule_detail", lambda c, u: {"error": "gone", "uuid": u})
    out = ops.toggle_rule(conn, "r1", enable=True)
    assert out["priorState"] == {"enabled": None}
