"""Extra governed-write ops coverage (ops.writes) — the platform-specific write
dispatch and central path encoding, proven against a MagicMock connection (never
a live firewall). Asserts the *exact* endpoint + params each write sends on each
platform, and that reversible writes capture prior state.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from firewall_aiops.connection import FirewallApiError
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
def test_remove_alias_entry_pfsense_patches_the_resolved_object(monkeypatch):
    """pfSense has no remove-a-member verb: the member list is PATCHed whole.

    This previously sent DELETE with a name in the body, which every real pfSense
    rejects with ``MODEL_REQUIRES_ID`` — the alias was never touched. Verified
    live on CE 2.7.2 + pfSense-pkg-RESTAPI 2.4_3.
    """
    conn = _conn(PFSENSE)
    monkeypatch.setattr(
        alias_ops, "alias_entries", lambda c, n: {"entries": ["1.1.1.1", "2.2.2.2"]}
    )
    conn.get.return_value = {
        "data": [{"id": 7, "name": "bl", "address": ["1.1.1.1", "2.2.2.2"]}]
    }
    out = ops.remove_alias_entry(conn, "bl", "1.1.1.1")
    conn.delete.assert_not_called()
    (lookup,), _ = conn.get.call_args
    assert lookup == "/api/v2/firewall/aliases?name=bl"
    (path,), kwargs = conn.patch.call_args
    assert path == "/api/v2/firewall/alias"
    assert kwargs["json"] == {"id": 7, "address": ["2.2.2.2"]}
    assert out["priorState"] == {"entries": ["1.1.1.1", "2.2.2.2"]}


@pytest.mark.unit
def test_add_alias_entry_pfsense_appends_to_the_existing_list(monkeypatch):
    """Adding a member PATCHes the whole list; POSTing the alias again is a
    *create* and a real pfSense answers ``FIELD_MUST_BE_UNIQUE`` (verified live).

    The resolved id here is ``0`` on purpose: pfSense collections are zero-indexed,
    so a truthiness check on the id would address the wrong object or refuse a
    perfectly valid one.
    """
    conn = _conn(PFSENSE)
    monkeypatch.setattr(alias_ops, "alias_entries", lambda c, n: {"entries": ["1.1.1.1"]})
    conn.get.return_value = {"data": [{"id": 0, "name": "bl", "address": ["1.1.1.1"]}]}
    ops.add_alias_entry(conn, "bl", "2.2.2.2")
    conn.post.assert_not_called()
    (path,), kwargs = conn.patch.call_args
    assert path == "/api/v2/firewall/alias"
    assert kwargs["json"] == {"id": 0, "address": ["1.1.1.1", "2.2.2.2"]}


@pytest.mark.unit
def test_add_alias_entry_pfsense_never_writes_back_an_empty_snapshot(monkeypatch):
    """A failed prior-state read must not become "the alias has no members".

    ``_capture_alias`` swallows read failures and returns ``[]`` by design (it
    only feeds the audit trail). pfSense edits an alias by PATCHing its whole
    member list, so using that snapshot as the list to write would delete every
    existing member on any read hiccup. The authoritative list is the one on the
    resolved record.
    """
    conn = _conn(PFSENSE)
    monkeypatch.setattr(alias_ops, "alias_entries", lambda c, n: {"error": "boom"})
    conn.get.return_value = {
        "data": [{"id": 2, "name": "bl", "address": ["1.1.1.1", "2.2.2.2"]}]
    }
    ops.add_alias_entry(conn, "bl", "3.3.3.3")
    _p, kwargs = conn.patch.call_args
    assert kwargs["json"]["address"] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


@pytest.mark.unit
def test_pfsense_alias_write_refuses_an_unreadable_member_list():
    """No member list on the record → refuse, rather than overwrite with a guess."""
    conn = _conn(PFSENSE)
    conn.get.return_value = {"data": [{"id": 2, "name": "bl"}]}
    with pytest.raises(ValueError, match="refusing to overwrite"):
        ops.add_alias_entry(conn, "bl", "3.3.3.3")
    conn.patch.assert_not_called()


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
def test_kill_states_pfsense_selects_with_query_params_not_a_body():
    """pfSense picks the states to drop with query parameters.

    An unfiltered mass delete is refused outright
    (``MODEL_DELETE_MANY_REQUIRES_QUERY_PARAMS``), and — worse — a made-up
    parameter such as ``?all=true`` satisfies that check while matching nothing,
    answering 200 with an empty list. "Flush everything" therefore has to be a
    real field filter that matches everything. Verified live on CE 2.7.2.
    """
    conn = _conn(PFSENSE)
    out = ops.kill_states(conn)  # no filter → "all"
    assert out["filter"] == "all"
    conn.delete.assert_called_once()
    (path,), kwargs = conn.delete.call_args
    assert path == "/api/v2/firewall/states?id__gte=0"
    assert "json" not in kwargs


@pytest.mark.unit
def test_kill_states_pfsense_filtered_matches_on_source():
    conn = _conn(PFSENSE)
    ops.kill_states(conn, "10.0.0.5")
    (path,), _ = conn.delete.call_args
    assert path == "/api/v2/firewall/states?source__contains=10.0.0.5"


@pytest.mark.unit
def test_kill_states_lost_response_is_undetermined_not_a_failure():
    """The flush drops this connection's own state, so the reply is routinely
    lost. Recording that as an error would file a change that DID happen as one
    that did not — observed live, where the DELETE times out every time.
    """
    conn = _conn(PFSENSE)
    conn.delete.side_effect = FirewallApiError("Could not reach", path="/x")
    out = ops.kill_states(conn)
    assert out["outcomeUnknown"] is True
    assert out["action"] == "kill_states"


@pytest.mark.unit
def test_kill_states_refusal_by_the_firewall_is_still_an_error():
    """Only a *transport* failure is undetermined. A firewall that answered and
    said no really did fail, and must not be laundered into "maybe it worked".
    """
    conn = _conn(PFSENSE)
    conn.delete.side_effect = FirewallApiError("nope", status_code=400, path="/x")
    with pytest.raises(FirewallApiError):
        ops.kill_states(conn)


@pytest.mark.unit
def test_restart_service_pfsense_resolves_the_numeric_id_first():
    """pfSense addresses a service by numeric id; a name-only body is rejected
    with ``MODEL_REQUIRES_ID`` (verified live).
    """
    conn = _conn(PFSENSE)
    conn.get.return_value = {"data": [{"id": 3, "name": "unbound", "status": True}]}
    out = ops.restart_service(conn, "unbound")
    assert out == {"action": "restart_service", "service": "unbound"}
    (lookup,), _ = conn.get.call_args
    assert lookup == "/api/v2/status/services?name=unbound"
    (path,), kwargs = conn.post.call_args
    assert path == "/api/v2/status/service"
    assert kwargs["json"] == {"id": 3, "action": "restart"}


@pytest.mark.unit
def test_restart_service_pfsense_unknown_name_fails_loudly():
    conn = _conn(PFSENSE)
    conn.get.return_value = {"data": []}
    with pytest.raises(ValueError, match="no-such-daemon"):
        ops.restart_service(conn, "no-such-daemon")
    conn.post.assert_not_called()


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
