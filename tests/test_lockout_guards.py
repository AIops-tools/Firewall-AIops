"""Refuse the firewall operations that destroy their own management path.

A firewall is the one appliance where a routine write can sever the connection
carrying it. Two shapes of that bug lived here:

  * ``restart_service`` had no allow-list, so ``nginx`` / ``lighttpd`` /
    ``webgui`` — the daemon answering this tool's own API — was a legal
    argument. An agent told "restart the web service" would kill the management
    path mid-request, undo included.
  * ``apply_changes`` was a blind commit: nothing in the package could read the
    staged change set, so it committed whatever was staged (including edits made
    in the web GUI) with no idea whether the staged rules cut management access.

Both guards must be EXACT and must FAIL OPEN, because over-blocking would make
the firewall's own rule engine unmanageable through the tool: only a literal
match on both the management host and port refuses; aliases, ``any`` and
interface groups warn and proceed.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from firewall_aiops.ops import lockout
from firewall_aiops.ops import writes as ops
from firewall_aiops.ops.writes import SelfLockout
from firewall_aiops.platform import OPNSENSE, PFSENSE, get_platform

HOST = "192.168.1.1"
PORT = 443


def _conn(platform=OPNSENSE, host=HOST, port=PORT):
    conn = MagicMock(name="conn")
    conn.target.platform = platform
    conn.target.host = host
    conn.target.port = port
    conn.platform = get_platform(platform)
    return conn


def _rule(**kw):
    base = {
        "uuid": "r1",
        "action": "pass",
        "enabled": True,
        "interface": "lan",
        "destination": HOST,
        "destinationPort": str(PORT),
        "description": "allow mgmt",
    }
    base.update(kw)
    return base


# ── restart_service: the API-serving daemon is refused ──────────────────────


@pytest.mark.unit
@pytest.mark.parametrize("service", ["nginx", "configd", "webgui", "web", "php-fpm"])
def test_restarting_the_opnsense_api_service_is_refused(service):
    conn = _conn(OPNSENSE)
    with pytest.raises(SelfLockout, match="own management API"):
        ops.restart_service(conn, service)
    conn.post.assert_not_called()


@pytest.mark.unit
@pytest.mark.parametrize("service", ["lighttpd", "webgui", "php-fpm"])
def test_restarting_the_pfsense_api_service_is_refused(service):
    conn = _conn(PFSENSE)
    with pytest.raises(SelfLockout):
        ops.restart_service(conn, service)
    conn.post.assert_not_called()


@pytest.mark.unit
def test_the_refusal_says_why_and_what_to_do_instead():
    with pytest.raises(SelfLockout) as ei:
        ops.restart_service(_conn(OPNSENSE), "nginx")
    msg = str(ei.value)
    assert "undo" in msg, "must name the concrete consequence"
    assert "console" in msg, "must offer a way forward"
    assert "unbound" in msg, "must show what IS safe here"


@pytest.mark.unit
@pytest.mark.parametrize("service", ["unbound", "dhcpd", "openvpn", "ipsec", "ntpd"])
def test_ordinary_services_still_restart(service):
    """Exactness: over-blocking would break the tool's day job."""
    conn = _conn(OPNSENSE)
    out = ops.restart_service(conn, service)
    assert out["service"] == service
    conn.post.assert_called_once()


@pytest.mark.unit
def test_service_matching_is_case_insensitive_and_trimmed():
    with pytest.raises(SelfLockout):
        ops.restart_service(_conn(OPNSENSE), "  NGINX ")


@pytest.mark.unit
def test_an_unknown_service_name_is_not_blocked_on_a_guess():
    """Fail open: only the descriptor's static list refuses."""
    conn = _conn(OPNSENSE)
    ops.restart_service(conn, "some-third-party-daemon")
    conn.post.assert_called_once()


@pytest.mark.unit
def test_restart_dry_run_refuses_the_api_service(monkeypatch):
    """A dry-run whose answer is 'this would be refused' must refuse, not preview.

    A green preview followed by a refusal reads to a weak model as a transient
    failure worth retrying — the exact loop this line designs against.
    """
    from mcp_server.tools import writes as gov

    conn = _conn(OPNSENSE)
    monkeypatch.setattr(gov, "_get_connection", lambda target=None: conn)

    out = gov.restart_service(service="nginx", dry_run=True)

    assert "error" in out, "the governed wrapper surfaces the refusal"
    assert "own management API" in out["error"]
    assert not conn.post.called


@pytest.mark.unit
def test_restart_dry_run_still_previews_a_safe_service(monkeypatch):
    """Fail open: a dry-run must never refuse what the real call would allow."""
    from mcp_server.tools import writes as gov

    conn = _conn(OPNSENSE)
    monkeypatch.setattr(gov, "_get_connection", lambda target=None: conn)

    out = gov.restart_service(service="unbound", dry_run=True)

    assert out["dryRun"] is True
    assert out["wouldRestart"] == {"service": "unbound"}
    assert not conn.post.called


# ── lockout assessment: exact, and fails open ───────────────────────────────


@pytest.mark.unit
def test_disabling_the_pass_rule_that_permits_management_is_certain():
    finding = lockout.assess_rule(_rule(enabled=False), HOST, PORT)
    assert finding is not None
    assert finding["certain"] is True
    assert finding["severity"] == "high"
    assert "removes this permit" in finding["finding"]


@pytest.mark.unit
def test_enabling_a_block_rule_covering_management_is_certain():
    """The mirror image — both directions must be covered."""
    finding = lockout.assess_rule(_rule(action="block", enabled=True), HOST, PORT)
    assert finding is not None
    assert finding["certain"] is True
    assert "starts blocking" in finding["finding"]


@pytest.mark.unit
def test_an_enabled_pass_rule_is_harmless():
    assert lockout.assess_rule(_rule(enabled=True), HOST, PORT) is None


@pytest.mark.unit
def test_a_disabled_block_rule_is_harmless():
    assert lockout.assess_rule(_rule(action="block", enabled=False), HOST, PORT) is None


@pytest.mark.unit
def test_a_rule_for_another_host_is_not_flagged():
    """Exactness: this is the assertion that keeps the guard usable."""
    assert lockout.assess_rule(_rule(enabled=False, destination="10.9.9.9"), HOST, PORT) is None


@pytest.mark.unit
def test_a_rule_for_another_port_is_not_flagged():
    assert lockout.assess_rule(
        _rule(enabled=False, destinationPort="8080"), HOST, PORT
    ) is None


@pytest.mark.unit
def test_an_alias_destination_fails_open_with_a_named_warning():
    finding = lockout.assess_rule(_rule(enabled=False, destination="MGMT_HOSTS"), HOST, PORT)
    assert finding is not None
    assert finding["certain"] is False, "an alias must never harden into a refusal"
    assert lockout.ALIAS_DESTINATION in finding["warnings"]


@pytest.mark.unit
def test_any_destination_fails_open_with_a_named_warning():
    finding = lockout.assess_rule(_rule(enabled=False, destination="any"), HOST, PORT)
    assert finding is not None and finding["certain"] is False
    assert lockout.ANY_DESTINATION in finding["warnings"]


@pytest.mark.unit
def test_any_port_fails_open_with_a_named_warning():
    finding = lockout.assess_rule(_rule(enabled=False, destinationPort=None), HOST, PORT)
    assert finding is not None and finding["certain"] is False
    assert lockout.ANY_PORT in finding["warnings"]


@pytest.mark.unit
def test_an_interface_group_is_named_in_the_warnings():
    finding = lockout.assess_rule(
        _rule(enabled=False, destination="MGMT", interface="any"), HOST, PORT
    )
    assert finding is not None
    assert lockout.INTERFACE_GROUP in finding["warnings"]


@pytest.mark.unit
def test_a_port_range_covering_management_is_certain():
    finding = lockout.assess_rule(_rule(enabled=False, destinationPort="440-450"), HOST, PORT)
    assert finding is not None and finding["certain"] is True


@pytest.mark.unit
def test_a_port_range_outside_management_is_not_flagged():
    assert lockout.assess_rule(
        _rule(enabled=False, destinationPort="8000-9000"), HOST, PORT
    ) is None


@pytest.mark.unit
def test_findings_are_ranked_worst_first():
    """rank is only meaningful because this list really is sorted by severity."""
    rules = [
        _rule(uuid="uncertain", enabled=False, destination="ALIAS"),
        _rule(uuid="certain", enabled=False),
    ]
    out = lockout.assess_rules(rules, HOST, PORT)
    assert [f["rank"] for f in out["findings"]] == [1, 2]
    assert out["findings"][0]["uuid"] == "certain"
    assert out["blocking"] is True
    assert out["certainCount"] == 1 and out["uncertainCount"] == 1


@pytest.mark.unit
def test_only_uncertain_findings_do_not_block():
    out = lockout.assess_rules([_rule(enabled=False, destination="ALIAS")], HOST, PORT)
    assert out["findings"], "the warning must still be reported"
    assert out["blocking"] is False, "uncertainty must never refuse"


# ── apply_changes / reconfigure guard ───────────────────────────────────────


def _staged(monkeypatch, rules, error=None):
    from firewall_aiops.ops import rules as rule_ops

    payload = {"error": error} if error else {"total": len(rules), "rules": rules}
    monkeypatch.setattr(rule_ops, "list_rules", lambda conn, interface=None: payload)


@pytest.mark.unit
def test_apply_refuses_a_staged_rule_that_would_lock_us_out(monkeypatch):
    conn = _conn()
    _staged(monkeypatch, [_rule(enabled=False)])

    with pytest.raises(SelfLockout, match="own management path"):
        ops.apply_changes(conn)

    assert not conn.post.called, "must refuse BEFORE committing"


@pytest.mark.unit
def test_the_apply_refusal_names_the_rule_and_the_way_out(monkeypatch):
    conn = _conn()
    _staged(monkeypatch, [_rule(enabled=False)])
    with pytest.raises(SelfLockout) as ei:
        ops.apply_changes(conn)
    msg = str(ei.value)
    assert "192.168.1.1:443" in msg, "must name the endpoint at risk"
    assert "override=True" in msg, "must offer the deliberate escape hatch"
    assert "pending_changes" in msg, "must point at the read that explains it"


@pytest.mark.unit
def test_apply_proceeds_for_rules_that_do_not_touch_management(monkeypatch):
    """Exactness — a normal staged change must still apply."""
    conn = _conn()
    _staged(monkeypatch, [_rule(enabled=False, destination="10.9.9.9")])

    out = ops.apply_changes(conn)

    assert out["applied"] is True
    conn.post.assert_called_once()


@pytest.mark.unit
def test_apply_fails_open_on_an_uncertain_rule_but_reports_it(monkeypatch):
    conn = _conn()
    _staged(monkeypatch, [_rule(enabled=False, destination="MGMT_ALIAS")])

    out = ops.apply_changes(conn)

    assert conn.post.call_count == 1, "uncertainty must not block the commit"
    impact = out["managementImpact"]
    assert impact["certainCount"] == 0 and impact["uncertainCount"] == 1
    assert lockout.ALIAS_DESTINATION in impact["findings"][0]["warnings"]


@pytest.mark.unit
def test_override_proceeds_despite_a_certain_finding(monkeypatch):
    conn = _conn()
    _staged(monkeypatch, [_rule(enabled=False)])

    out = ops.apply_changes(conn, override=True)

    conn.post.assert_called_once()
    assert out["override"] is True
    assert out["managementImpact"]["certainCount"] == 1


@pytest.mark.unit
def test_an_unreadable_rule_set_does_not_block_but_says_it_is_unknown(monkeypatch):
    """A probe failure must not masquerade as a clean bill of health."""
    conn = _conn()
    _staged(monkeypatch, [], error="connection refused")

    out = ops.apply_changes(conn)

    conn.post.assert_called_once()
    assert out["managementImpact"]["assessed"] is False
    assert "connection refused" in out["managementImpact"]["error"]


@pytest.mark.unit
def test_reconfigure_filter_carries_the_same_guard(monkeypatch):
    conn = _conn()
    _staged(monkeypatch, [_rule(enabled=False)])
    with pytest.raises(SelfLockout):
        ops.reconfigure(conn, "filter")
    conn.post.assert_not_called()


@pytest.mark.unit
def test_reconfigure_of_another_subsystem_is_not_guarded(monkeypatch):
    """Only the filter subsystem commits the rule set."""
    conn = _conn()
    _staged(monkeypatch, [_rule(enabled=False)])
    out = ops.reconfigure(conn, "nat")
    conn.post.assert_called_once()
    assert out["managementImpact"] is None


# ── toggle_rule warns at staging time ───────────────────────────────────────


@pytest.mark.unit
def test_toggle_warns_when_disabling_the_management_pass_rule(monkeypatch):
    from firewall_aiops.ops import rules as rule_ops

    conn = _conn()
    monkeypatch.setattr(rule_ops, "rule_detail", lambda c, u: _rule(enabled=True))

    out = ops.toggle_rule(conn, "r1", enable=False)

    impact = out["managementImpact"]
    assert impact is not None and impact["certain"] is True
    assert "Staged only" in impact["note"]
    assert conn.post.call_count == 1, "warning only — staging must still happen"


@pytest.mark.unit
def test_toggle_warns_when_enabling_a_block_rule_covering_management(monkeypatch):
    from firewall_aiops.ops import rules as rule_ops

    conn = _conn()
    monkeypatch.setattr(
        rule_ops, "rule_detail", lambda c, u: _rule(action="block", enabled=False)
    )

    out = ops.toggle_rule(conn, "r1", enable=True)

    assert out["managementImpact"]["certain"] is True


@pytest.mark.unit
def test_toggle_of_an_unrelated_rule_carries_no_warning(monkeypatch):
    from firewall_aiops.ops import rules as rule_ops

    conn = _conn()
    monkeypatch.setattr(
        rule_ops, "rule_detail", lambda c, u: _rule(destination="10.9.9.9", enabled=True)
    )

    out = ops.toggle_rule(conn, "r1", enable=False)
    assert out["managementImpact"] is None


@pytest.mark.unit
def test_toggle_survives_an_unreadable_rule(monkeypatch):
    from firewall_aiops.ops import rules as rule_ops

    conn = _conn()
    monkeypatch.setattr(rule_ops, "rule_detail", lambda c, u: {"error": "boom"})

    out = ops.toggle_rule(conn, "r1", enable=False)
    assert out["managementImpact"] is None
    assert out["priorState"]["enabled"] is None


# ── pending_changes read ────────────────────────────────────────────────────


@pytest.mark.unit
def test_pending_changes_surfaces_the_staged_set(monkeypatch):
    from firewall_aiops.ops import pending as pending_ops

    conn = _conn()
    _staged(monkeypatch, [_rule(enabled=False), _rule(uuid="r2", destination="10.0.0.5")])

    out = pending_ops.pending_changes(conn)

    assert out["stagedRuleCount"] == 2
    assert out["blocking"] is True
    assert out["managementEndpoint"] == {"host": HOST, "port": PORT}
    assert "not a diff" in out["basis"], "must not overclaim what it read"


@pytest.mark.unit
def test_pending_changes_reports_a_read_failure_as_unknown(monkeypatch):
    from firewall_aiops.ops import pending as pending_ops

    conn = _conn()
    _staged(monkeypatch, [], error="timeout")

    out = pending_ops.pending_changes(conn)

    assert out["error"] == "timeout"
    assert "UNKNOWN" in out["note"], "a failed probe is not 'nothing pending'"
    assert "blocking" not in out


@pytest.mark.unit
def test_apply_dry_run_returns_the_pending_change_set(monkeypatch):
    """The dry-run used to say only {'wouldApply': {'platform': ...}}."""
    from mcp_server.tools import writes as gov

    conn = _conn()
    # An uncertain finding: reported, but must not refuse on either path.
    _staged(monkeypatch, [_rule(enabled=False, destination="MGMT_ALIAS")])
    monkeypatch.setattr(gov, "_get_connection", lambda target=None: conn)

    preview = gov.apply_changes(dry_run=True)

    assert preview["dryRun"] is True
    pending = preview["pendingChanges"]
    assert pending["blocking"] is False
    assert pending["findings"][0]["rank"] == 1
    assert lockout.ALIAS_DESTINATION in pending["findings"][0]["warnings"]
    assert not conn.post.called


# ── dry_run must not bypass the guards ──────────────────────────────────────


@pytest.mark.unit
def test_apply_dry_run_refuses_a_certain_lockout(monkeypatch):
    """dry_run reports what WOULD happen; a refusal is what would happen."""
    from mcp_server.tools import writes as gov

    conn = _conn()
    _staged(monkeypatch, [_rule(enabled=False)])
    monkeypatch.setattr(gov, "_get_connection", lambda target=None: conn)

    out = gov.apply_changes(dry_run=True)

    assert "error" in out
    assert "own management path" in out["error"]
    assert not conn.post.called


@pytest.mark.unit
def test_apply_dry_run_honours_override_like_the_real_path(monkeypatch):
    from mcp_server.tools import writes as gov

    conn = _conn()
    _staged(monkeypatch, [_rule(enabled=False)])
    monkeypatch.setattr(gov, "_get_connection", lambda target=None: conn)

    out = gov.apply_changes(dry_run=True, override=True)

    assert out["dryRun"] is True
    assert out["pendingChanges"]["blocking"] is True
    assert not conn.post.called


@pytest.mark.unit
def test_apply_dry_run_proceeds_for_an_unrelated_rule(monkeypatch):
    """Fail open, identically to the real path."""
    from mcp_server.tools import writes as gov

    conn = _conn()
    _staged(monkeypatch, [_rule(enabled=False, destination="10.9.9.9")])
    monkeypatch.setattr(gov, "_get_connection", lambda target=None: conn)

    out = gov.apply_changes(dry_run=True)
    assert out["dryRun"] is True
    assert out["pendingChanges"]["blocking"] is False


@pytest.mark.unit
def test_reconfigure_filter_dry_run_refuses_a_certain_lockout(monkeypatch):
    from mcp_server.tools import writes as gov

    conn = _conn()
    _staged(monkeypatch, [_rule(enabled=False)])
    monkeypatch.setattr(gov, "_get_connection", lambda target=None: conn)

    out = gov.reconfigure(subsystem="filter", dry_run=True)
    assert "error" in out and "own management path" in out["error"]


@pytest.mark.unit
def test_reconfigure_nonfilter_dry_run_is_not_guarded(monkeypatch):
    from mcp_server.tools import writes as gov

    conn = _conn()
    _staged(monkeypatch, [_rule(enabled=False)])
    monkeypatch.setattr(gov, "_get_connection", lambda target=None: conn)

    out = gov.reconfigure(subsystem="nat", dry_run=True)
    assert out["dryRun"] is True
    assert "pendingChanges" not in out


# ── kill_states: a lost response, not a lockout ─────────────────────────────


@pytest.mark.unit
def test_kill_states_dry_run_warns_about_the_lost_response(monkeypatch):
    from mcp_server.tools import writes as gov

    conn = _conn()
    monkeypatch.setattr(gov, "_get_connection", lambda target=None: conn)

    out = gov.kill_states(dry_run=True)

    assert out["dryRun"] is True
    assert "lost response" in out["sessionImpact"]
    assert "not lost" in out["sessionImpact"], "must not be mistaken for a lockout"
    assert not conn.post.called


@pytest.mark.unit
def test_kill_states_is_not_refused(monkeypatch):
    """It drops our session but is NOT a lockout — it must stay available."""
    conn = _conn()
    out = ops.kill_states(conn, "")
    assert out["filter"] == "all"
    assert conn.post.call_count == 1


# ── reversible writes stash before-state for a lost response ────────────────


@pytest.mark.unit
def test_toggle_rule_captures_prior_state_before_mutating(monkeypatch):
    """Without this the inverse dies with the exception when the response is lost."""
    from firewall_aiops.governance.outcome import take_prior_state
    from firewall_aiops.ops import rules as rule_ops

    conn = _conn()
    monkeypatch.setattr(rule_ops, "rule_detail", lambda c, u: _rule(enabled=True))

    ops.toggle_rule(conn, "r1", enable=False)

    assert take_prior_state() == {"enabled": True}


@pytest.mark.unit
def test_alias_writes_capture_prior_state(monkeypatch):
    from firewall_aiops.governance.outcome import take_prior_state
    from firewall_aiops.ops import aliases as alias_ops

    conn = _conn()
    monkeypatch.setattr(alias_ops, "alias_entries", lambda c, n: {"entries": ["1.1.1.1"]})

    ops.add_alias_entry(conn, "BAD_HOSTS", "2.2.2.2")
    assert take_prior_state() == {"entries": ["1.1.1.1"]}

    ops.remove_alias_entry(conn, "BAD_HOSTS", "1.1.1.1")
    assert take_prior_state() == {"entries": ["1.1.1.1"]}
