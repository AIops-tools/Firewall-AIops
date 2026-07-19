"""MCP tool-layer coverage: governed write tools (dry-run + confirmed dispatch),
the three flagship analyses on their live-pull path, the read tools, and the
shared error-sanitisation decorator. The connection is always faked — no live
OPNsense/pfSense is contacted.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from firewall_aiops.config import TargetConfig
from firewall_aiops.platform import OPNSENSE, get_platform


class _ReadConn:
    """Fake connection for read tools: get() returns canned JSON by path."""

    def __init__(self, responses, platform=OPNSENSE):
        self.target = TargetConfig(name="t", platform=platform, host="h", username="k")
        self.platform = self.target.platform_obj
        self._responses = responses

    def get(self, path, **_kw):
        return self._responses.get(path, {})


def _p(resource, **fmt):
    return get_platform(OPNSENSE).path(resource, **fmt)


def _write_conn():
    conn = MagicMock(name="conn")
    conn.target.platform = OPNSENSE
    conn.platform = get_platform(OPNSENSE)
    return conn


# ── governed writes: dry-run previews + confirmed dispatch ───────────────────


@pytest.mark.unit
def test_apply_changes_dry_run_and_confirmed(monkeypatch):
    from mcp_server.tools import writes as t

    conn = _write_conn()
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)

    assert t.apply_changes(dry_run=True)["dryRun"] is True
    conn.post.assert_not_called()

    out = t.apply_changes()
    assert out["applied"] is True
    conn.post.assert_called_once_with("/api/firewall/filter/apply")


@pytest.mark.unit
def test_reconfigure_dry_run_and_confirmed(monkeypatch):
    from mcp_server.tools import writes as t

    conn = _write_conn()
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)

    assert t.reconfigure(subsystem="nat", dry_run=True)["dryRun"] is True
    out = t.reconfigure(subsystem="nat")
    assert out["subsystem"] == "nat"


@pytest.mark.unit
def test_kill_states_dry_run_and_confirmed(monkeypatch):
    from mcp_server.tools import writes as t

    conn = _write_conn()
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)

    prev = t.kill_states(filter_ip="1.2.3.4", dry_run=True)
    assert prev["dryRun"] is True and prev["wouldKillStates"]["filter"] == "1.2.3.4"
    out = t.kill_states(filter_ip="1.2.3.4")
    assert out["filter"] == "1.2.3.4"
    conn.post.assert_called_once()


@pytest.mark.unit
def test_restart_service_dry_run_and_confirmed(monkeypatch):
    from mcp_server.tools import writes as t

    conn = _write_conn()
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)

    assert t.restart_service(service="unbound", dry_run=True)["dryRun"] is True
    out = t.restart_service(service="unbound")
    assert out["service"] == "unbound"
    conn.post.assert_called_once_with("/api/core/service/restart/unbound")


@pytest.mark.unit
def test_reboot_confirmed_posts(monkeypatch):
    from mcp_server.tools import writes as t

    conn = _write_conn()
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)

    out = t.reboot()
    assert out["rebooting"] is True
    conn.post.assert_called_once_with("/api/core/system/reboot")


@pytest.mark.unit
def test_add_and_remove_alias_entry_dispatch(monkeypatch):
    from firewall_aiops.ops import aliases as alias_ops
    from mcp_server.tools import writes as t

    conn = _write_conn()
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)
    monkeypatch.setattr(alias_ops, "alias_entries", lambda c, n: {"entries": ["1.1.1.1"]})

    assert t.add_alias_entry(name="bl", entry="2.2.2.2", dry_run=True)["dryRun"] is True
    add = t.add_alias_entry(name="bl", entry="2.2.2.2")
    assert add["action"] == "add_alias_entry" and add["priorState"] == {"entries": ["1.1.1.1"]}

    assert t.remove_alias_entry(name="bl", entry="1.1.1.1", dry_run=True)["dryRun"] is True
    rm = t.remove_alias_entry(name="bl", entry="1.1.1.1")
    assert rm["action"] == "remove_alias_entry"


# ── flagship analyses: live-pull path (gateways/rules/log pulled from conn) ───


@pytest.mark.unit
def test_gateway_health_rca_pulls_live(monkeypatch):
    from mcp_server.tools import analysis as t

    conn = _ReadConn({
        _p("gateways"): {"rows": [
            {"name": "WAN", "status": "down", "loss": "100 %", "delay": ""},
        ]}
    })
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)
    out = t.gateway_health_rca()
    assert out["gatewaysEvaluated"] == 1 and out["downCount"] == 1


@pytest.mark.unit
def test_rule_shadow_analysis_pulls_live(monkeypatch):
    from mcp_server.tools import analysis as t

    conn = _ReadConn({
        _p("rules_search"): {"rows": [
            {"uuid": "r1", "enabled": "1", "action": "pass", "interface": "wan",
             "evaluations": 0},
        ]}
    })
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)
    out = t.rule_hit_and_shadow_analysis()
    assert out["rulesEvaluated"] == 1 and out["unusedCount"] == 1


@pytest.mark.unit
def test_blocked_traffic_rca_pulls_live(monkeypatch):
    from mcp_server.tools import analysis as t

    conn = _ReadConn({
        _p("firewall_log"): {"rows": [
            {"action": "block", "src": "9.9.9.9", "dstport": "22"},
            {"action": "block", "src": "9.9.9.9", "dstport": "22"},
        ]}
    })
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)
    out = t.blocked_traffic_rca()
    assert out["blocksEvaluated"] == 2 and out["distinctSources"] == 1


# ── read tools dispatch through _get_connection ──────────────────────────────


@pytest.mark.unit
def test_read_tools_return_normalized_payloads(monkeypatch):
    from mcp_server.tools import (
        aliases as t_alias,
    )
    from mcp_server.tools import (
        dhcp as t_dhcp,
    )
    from mcp_server.tools import (
        diag as t_diag,
    )
    from mcp_server.tools import (
        nat as t_nat,
    )
    from mcp_server.tools import (
        rules as t_rules,
    )
    from mcp_server.tools import (
        system as t_system,
    )
    from mcp_server.tools import (
        vpn as t_vpn,
    )

    conn = _ReadConn({
        _p("rules_search"): {"rows": [{"uuid": "r1", "enabled": "1", "action": "pass"}]},
        _p("rule_get", uuid="r1"): {"rule": {"uuid": "r1", "enabled": "1"}},
        _p("rule_stats"): {"rows": [{"uuid": "r1", "evaluations": 3}]},
        _p("rule_states"): {"rows": [{"src": "1.1.1.1"}]},
        _p("nat_port_forward"): {"rows": [{"uuid": "n1", "enabled": "1"}]},
        _p("nat_outbound"): {"rows": [{"uuid": "o1", "enabled": "1"}]},
        _p("nat_one_to_one"): {"rows": [{"uuid": "b1", "enabled": "1"}]},
        _p("wireguard"): {"rows": [{"name": "peer", "connected": "1"}]},
        _p("openvpn"): {"rows": [{"common_name": "vpn"}]},
        _p("ipsec"): {"rows": [{"name": "sa"}]},
        _p("dhcp_leases"): {"rows": [{"address": "10.0.0.5", "online": "1"}]},
        _p("dhcp_static"): {"rows": [{"mac": "aa", "ipaddr": "10.0.0.6"}]},
        _p("firewall_log"): {"rows": [{"action": "block", "src": "9.9.9.9"}]},
        _p("states"): {"rows": [{"src": "1.1.1.1", "bytes": 10}]},
        _p("top_talkers"): {"rows": [{"src": "1.1.1.1", "bytes": 10}]},
        _p("aliases_search"): {"rows": [{"uuid": "a1", "name": "hosts", "content": "1.1.1.1"}]},
        _p("alias_entries", name="hosts"): {"rows": [{"ip": "1.1.1.1"}]},
        _p("firmware"): {"product_version": "24.7"},
        _p("system_info"): {"hostname": "fw"},
        _p("interfaces"): {"wan": {"status": "up"}},
        _p("gateways"): {"rows": [{"name": "WAN", "status": "none"}]},
    })
    for mod in (t_alias, t_dhcp, t_diag, t_nat, t_rules, t_system, t_vpn):
        monkeypatch.setattr(mod, "_get_connection", lambda target=None: conn)

    assert t_rules.list_rules()["total"] == 1
    assert t_rules.rule_detail(uuid="r1")["uuid"] == "r1"
    assert t_rules.rule_stats()["total"] == 1
    assert t_rules.rule_states()["total"] == 1
    assert t_nat.nat_port_forwards()["total"] == 1
    assert t_nat.nat_outbound()["total"] == 1
    assert t_nat.nat_one_to_one()["total"] == 1
    assert t_vpn.wireguard_status()["total"] == 1
    assert t_vpn.openvpn_sessions()["total"] == 1
    assert t_vpn.ipsec_sas()["total"] == 1
    assert t_dhcp.dhcp_leases()["total"] == 1
    assert t_dhcp.dhcp_static_mappings()["total"] == 1
    assert t_diag.firewall_log()["returned"] == 1
    assert t_diag.states_table()["total"] == 1
    assert t_diag.top_talkers()["total"] == 1
    assert t_alias.list_aliases()["total"] == 1
    assert t_alias.alias_entries(name="hosts")["total"] == 1
    assert t_system.firmware_status()["version"] == "24.7"
    assert t_system.health_status()["hostname"] == "fw"
    assert t_system.interface_status()["total"] == 1
    assert t_system.gateway_status()["total"] == 1


# ── shared error sanitisation ────────────────────────────────────────────────


@pytest.mark.unit
def test_tool_errors_wraps_and_sanitizes_each_shape():
    from mcp_server._shared import tool_errors

    @tool_errors("dict")
    def boom_dict():
        raise ValueError("kaboom")

    @tool_errors("list")
    def boom_list():
        raise RuntimeError("secret-internal-detail")

    @tool_errors("str")
    def boom_str():
        raise KeyError("missing")

    d = boom_dict()
    assert "kaboom" in d["error"] and "hint" in d
    li = boom_list()
    # a generic (non-passthrough) exception is replaced with its type name only
    assert isinstance(li, list) and "RuntimeError" in li[0]["error"]
    s = boom_str()
    assert s.startswith("Error:")


@pytest.mark.unit
def test_get_connection_lazily_builds_manager(monkeypatch, tmp_path):
    import mcp_server._shared as shared

    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        "targets:\n  - name: fw1\n    platform: opnsense\n    host: h\n    username: k\n"
    )
    monkeypatch.setenv("FIREWALL_AIOPS_CONFIG", str(cfg_file))
    # a secret so building the session's Basic auth does not fail (no request made)
    monkeypatch.setenv("FIREWALL_FW1_SECRET", "s3cr3t")
    monkeypatch.setattr(shared, "_conn_mgr", None, raising=False)

    conn = shared._get_connection()
    assert conn.target.name == "fw1"
    # cached manager is reused on a second call
    assert shared._get_connection().target.name == "fw1"
