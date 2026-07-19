"""Absent fields come back as null, not as an empty string.

An empty string reads as "this field exists and is empty"; a missing field is a
different fact. OPNsense and pfSense disagree about which keys they populate, so
``pick()`` frequently finds nothing — collapsing that into ``""`` hides it from
the caller, and a smaller local model will confidently invent the difference.

These tests pin the contract end-to-end: the helper, the ops normalisers, and
the consumers (rule-shadow signatures, gateway health, interface filtering) that
now have to cope with a null.
"""

from __future__ import annotations

import pytest

from firewall_aiops.config import TargetConfig
from firewall_aiops.governance import opt_str
from firewall_aiops.ops import analysis, diag, overview, rules, system
from firewall_aiops.ops._util import opt
from firewall_aiops.platform import OPNSENSE, get_platform


class _Conn:
    def __init__(self, responses, platform=OPNSENSE):
        self.target = TargetConfig(name="t", platform=platform, host="h", username="k")
        self.platform = self.target.platform_obj
        self._responses = responses

    def get(self, path, **_kw):
        return self._responses.get(path, {})


def _p(resource, **fmt):
    return get_platform(OPNSENSE).path(resource, **fmt)


# ── the helper ──────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_opt_str_distinguishes_absent_from_empty():
    assert opt_str(None) is None, "absent must stay absent"
    assert opt_str("") == "", "a genuinely empty value is not the same as absent"
    assert opt_str("wan", 64) == "wan"


@pytest.mark.unit
def test_opt_str_still_sanitizes_and_truncates():
    assert opt_str("a\x00b") == "ab"  # control character stripped
    assert opt_str("abcdef", 3) == "abc"


@pytest.mark.unit
def test_opt_str_accepts_non_string_values():
    assert opt_str(42) == "42"


@pytest.mark.unit
def test_ops_opt_helper_matches_opt_str():
    """``_util.opt`` is the ops-layer chokepoint; ``_util.s`` still coerces."""
    from firewall_aiops.ops._util import s

    assert opt(None) is None
    assert s(None) == "", "s() keeps its always-present semantics"


# ── the ops layer ───────────────────────────────────────────────────────────


@pytest.mark.unit
def test_rule_row_reports_absent_fields_as_none():
    """A rule row the API barely populated reports null, not ''."""
    conn = _Conn({_p("rules_search"): {"rows": [{"uuid": "r1"}]}})
    rule = rules.list_rules(conn)["rules"][0]
    assert rule["uuid"] == "r1"
    assert rule["interface"] is None
    assert rule["protocol"] is None
    assert rule["description"] is None


@pytest.mark.unit
def test_rule_row_keeps_empty_string_when_source_is_empty():
    """An explicitly empty upstream value is preserved as '' — not turned into null."""
    conn = _Conn({_p("rules_search"): {"rows": [{"uuid": "r1", "description": ""}]}})
    assert rules.list_rules(conn)["rules"][0]["description"] == ""


@pytest.mark.unit
def test_rule_row_never_drops_the_key_itself():
    """Keys are always present; only their value may be null.

    Omitting a key entirely is worse than a null — the consumer cannot tell the
    field was even considered.
    """
    conn = _Conn({_p("rules_search"): {"rows": [{}]}})
    rule = rules.list_rules(conn)["rules"][0]
    for key in ("uuid", "action", "interface", "protocol", "source", "destination"):
        assert key in rule, f"{key} must be present even when the source omitted it"


@pytest.mark.unit
def test_log_row_action_stays_null_rather_than_becoming_the_string_none():
    """The regression this guards: str(None).lower() == 'none', a fake action."""
    rows = diag.normalize_log([{"src": "9.9.9.9"}])
    assert rows[0]["action"] is None
    assert rows[0]["action"] != "none"


@pytest.mark.unit
def test_log_row_action_is_still_lowercased_when_present():
    assert diag.normalize_log([{"action": "BLOCK"}])[0]["action"] == "block"


# ── the consumers ───────────────────────────────────────────────────────────


@pytest.mark.unit
def test_interface_filter_survives_a_null_interface():
    """A rule with no reported interface must not crash the filter, nor match."""
    conn = _Conn({_p("rules_search"): {"rows": [
        {"uuid": "r1", "interface": "wan"},
        {"uuid": "r2"},  # no interface at all
    ]}})
    out = rules.list_rules(conn, interface="wan")
    assert [r["uuid"] for r in out["rules"]] == ["r1"]


@pytest.mark.unit
def test_shadow_signature_does_not_conflate_two_unpopulated_rules():
    """Two rules missing everything must not signature as 'none/none/none…'.

    If null collapsed to the literal "none", every sparsely-reported rule would
    look identical and the shadow analysis would cry duplicate.
    """
    sig_empty = analysis._sig({})
    assert sig_empty == ("", "", "", "", "", "")
    assert "none" not in sig_empty


@pytest.mark.unit
def test_gateway_with_no_status_is_not_counted_healthy():
    """Absence of a status is not evidence of health."""
    conn = _Conn({
        _p("gateways"): {"rows": [{"name": "WAN_GW"}]},  # no status reported
        _p("interfaces"): {"rows": []},
        _p("firmware"): {},
    })
    summary = overview.firewall_overview(conn)
    assert summary["gatewaysTotal"] == 1
    assert summary["gatewaysHealthy"] == 0


@pytest.mark.unit
def test_gateway_reporting_none_is_still_counted_healthy():
    """pfSense reports the literal 'none' for an unmonitored-but-fine gateway."""
    conn = _Conn({
        _p("gateways"): {"rows": [{"name": "WAN_GW", "status": "none"}]},
        _p("interfaces"): {"rows": []},
        _p("firmware"): {},
    })
    assert overview.firewall_overview(conn)["gatewaysHealthy"] == 1


@pytest.mark.unit
def test_interface_list_renders_with_null_fields():
    """The system read must survive a barely-populated interface row."""
    conn = _Conn({_p("interfaces"): {"rows": [{}]}})
    row = system.interface_status(conn)["interfaces"][0]
    assert row["name"] is None and "status" in row


@pytest.mark.unit
def test_undo_list_envelope_measures_truncation(monkeypatch):
    from mcp_server.tools import undo as undo_tools

    rows = [
        {
            "undo_id": f"u{i}",
            "ts": "2026-07-18T00:00:00Z",
            "tool": "some_tool",
            "undo_tool": "some_inverse_tool",
            "note": "",
        }
        for i in range(4)
    ]
    captured = {}

    class _Store:
        def list(self, *, status=None, limit=50):
            captured["limit"] = limit
            return rows[:limit]

    monkeypatch.setattr(undo_tools, "get_undo_store", lambda: _Store())
    result = undo_tools.undo_list(limit=3)
    assert captured["limit"] == 4, "one extra row is fetched to measure truncation"
    assert result["returned"] == 3
    assert result["limit"] == 3
    assert result["truncated"] is True
    assert len(result["undos"]) == 3
