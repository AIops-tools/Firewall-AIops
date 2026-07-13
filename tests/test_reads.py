"""Read-path ops tests (system / rules / nat / aliases / vpn / dhcp / diag).

Uses a fake connection that returns canned JSON per path, so the cross-platform
normalisation is exercised without a live OPNsense/pfSense. The fake carries a
real Platform descriptor so ops resolve the same paths they would in production.
"""

import pytest

from firewall_aiops.config import TargetConfig
from firewall_aiops.ops import aliases, dhcp, diag, nat, overview, rules, system, vpn
from firewall_aiops.platform import OPNSENSE, PFSENSE


class _Conn:
    """Fake connection: get() looks up canned responses by path."""

    def __init__(self, responses, platform=OPNSENSE):
        self.target = TargetConfig(name="t", platform=platform, host="h", username="k")
        self.platform = self.target.platform_obj
        self._responses = responses

    def get(self, path, **_kw):
        return self._responses.get(path, {})


def _p(platform, resource, **fmt):
    from firewall_aiops.platform import get_platform

    return get_platform(platform).path(resource, **fmt)


# ── system ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_gateway_status_normalizes_loss_and_rtt():
    conn = _Conn({
        _p(OPNSENSE, "gateways"): {"rows": [
            {"name": "WAN_GW", "address": "1.1.1.1", "status": "none",
             "loss": "3.0 %", "delay": "12.4 ms"},
            {"name": "WAN2_GW", "address": "2.2.2.2", "status": "down",
             "loss": "100 %", "delay": ""},
        ]}
    })
    out = system.gateway_status(conn)
    assert out["total"] == 2
    g0 = out["gateways"][0]
    assert g0["lossPercent"] == 3.0 and g0["rttMs"] == 12.4


@pytest.mark.unit
def test_interface_status_opnsense_map_shape():
    conn = _Conn({
        _p(OPNSENSE, "interfaces"): {
            "wan": {"description": "WAN", "status": "up", "ipaddr": "1.2.3.4"},
            "lan": {"description": "LAN", "status": "down", "ipaddr": "10.0.0.1"},
        }
    })
    out = system.interface_status(conn)
    assert out["total"] == 2
    # down interfaces sort first
    assert out["interfaces"][0]["up"] is False


@pytest.mark.unit
def test_interface_status_pfsense_list_shape():
    conn = _Conn(
        {_p(PFSENSE, "interfaces"): {"data": [
            {"name": "wan", "status": "up", "ipaddr": "1.2.3.4"},
        ]}},
        platform=PFSENSE,
    )
    out = system.interface_status(conn)
    assert out["total"] == 1 and out["interfaces"][0]["up"] is True


# ── rules ───────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_list_rules_opnsense_enabled_flag():
    conn = _Conn({
        _p(OPNSENSE, "rules_search"): {"rows": [
            {"uuid": "r1", "enabled": "1", "action": "pass", "interface": "wan",
             "description": "allow web", "evaluations": 42},
            {"uuid": "r2", "enabled": "0", "action": "block", "interface": "lan"},
        ]}
    })
    out = rules.list_rules(conn)
    assert out["total"] == 2
    assert out["rules"][0]["enabled"] is True
    assert out["rules"][1]["enabled"] is False


@pytest.mark.unit
def test_list_rules_pfsense_disabled_flag_and_interface_filter():
    conn = _Conn(
        {_p(PFSENSE, "rules_search"): {"data": [
            {"id": 0, "disabled": False, "type": "pass", "interface": "wan"},
            {"id": 1, "disabled": True, "type": "block", "interface": "lan"},
        ]}},
        platform=PFSENSE,
    )
    out = rules.list_rules(conn, interface="wan")
    assert out["total"] == 1 and out["rules"][0]["enabled"] is True


@pytest.mark.unit
def test_rule_stats_sorts_busiest_first():
    conn = _Conn({
        _p(OPNSENSE, "rule_stats"): {"rows": [
            {"uuid": "a", "evaluations": 5},
            {"uuid": "b", "evaluations": 99},
        ]}
    })
    out = rules.rule_stats(conn)
    assert out["rules"][0]["uuid"] == "b"


# ── nat / aliases / vpn / dhcp ───────────────────────────────────────────────


@pytest.mark.unit
def test_nat_port_forwards_normalizes():
    conn = _Conn({
        _p(OPNSENSE, "nat_port_forward"): {"rows": [
            {"uuid": "n1", "enabled": "1", "interface": "wan", "protocol": "tcp",
             "destination_port": "443", "target": "10.0.0.5"},
        ]}
    })
    out = nat.port_forwards(conn)
    assert out["total"] == 1 and out["portForwards"][0]["target"] == "10.0.0.5"


@pytest.mark.unit
def test_alias_entries_opnsense_rows():
    conn = _Conn({
        _p(OPNSENSE, "alias_entries", name="bogons"): {"rows": [
            {"ip": "1.2.3.4"}, {"ip": "5.6.7.8"},
        ]}
    })
    out = aliases.alias_entries(conn, "bogons")
    assert out["total"] == 2 and "1.2.3.4" in out["entries"]


@pytest.mark.unit
def test_list_aliases_counts_members():
    conn = _Conn({
        _p(OPNSENSE, "aliases_search"): {"rows": [
            {"uuid": "a1", "name": "webservers", "type": "host",
             "content": "10.0.0.1\n10.0.0.2\n10.0.0.3"},
        ]}
    })
    out = aliases.list_aliases(conn)
    assert out["aliases"][0]["entries"] == 3


@pytest.mark.unit
def test_wireguard_status_normalizes():
    conn = _Conn({
        _p(OPNSENSE, "wireguard"): {"rows": [
            {"name": "peer1", "connected": "1", "transfer-rx": 100, "transfer-tx": 50},
        ]}
    })
    out = vpn.wireguard_status(conn)
    assert out["peers"][0]["connected"] is True and out["peers"][0]["transferRx"] == 100


@pytest.mark.unit
def test_dhcp_leases_online_filter():
    conn = _Conn({
        _p(OPNSENSE, "dhcp_leases"): {"rows": [
            {"address": "10.0.0.10", "mac": "aa", "online": "1"},
            {"address": "10.0.0.11", "mac": "bb", "online": "0"},
        ]}
    })
    assert dhcp.leases(conn)["total"] == 2
    assert dhcp.leases(conn, online_only=True)["total"] == 1


# ── diag ────────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_firewall_log_action_filter():
    conn = _Conn({
        _p(OPNSENSE, "firewall_log"): {"rows": [
            {"action": "block", "src": "9.9.9.9", "dstport": "22"},
            {"action": "pass", "src": "10.0.0.1", "dstport": "443"},
        ]}
    })
    out = diag.firewall_log(conn, action="block")
    assert out["total"] == 1 and out["entries"][0]["source"] == "9.9.9.9"


@pytest.mark.unit
def test_firewall_log_rejects_unknown_action():
    conn = _Conn({_p(OPNSENSE, "firewall_log"): {"rows": []}})
    with pytest.raises(ValueError):
        diag.firewall_log(conn, action="nonsense")


@pytest.mark.unit
def test_top_talkers_aggregates_by_source():
    conn = _Conn({
        _p(OPNSENSE, "top_talkers"): {"rows": [
            {"src": "9.9.9.9", "bytes": 100},
            {"src": "9.9.9.9", "bytes": 200},
            {"src": "8.8.8.8", "bytes": 50},
        ]}
    })
    out = diag.top_talkers(conn)
    assert out["topTalkers"][0]["source"] == "9.9.9.9"
    assert out["topTalkers"][0]["bytes"] == 300 and out["topTalkers"][0]["connections"] == 2


# ── overview ────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_firewall_overview_resilient_shapes():
    conn = _Conn({
        _p(OPNSENSE, "firmware"): {"product_version": "24.7", "status": "1"},
        _p(OPNSENSE, "gateways"): {"rows": [{"name": "WAN_GW", "status": "none"}]},
        _p(OPNSENSE, "interfaces"): {"wan": {"status": "up"}},
        _p(OPNSENSE, "rules_search"): {"rows": [{"uuid": "r1", "enabled": "1"}]},
    })
    out = overview.firewall_overview(conn)
    assert out["platform"] == "opnsense"
    assert out["version"] == "24.7"
    assert out["ruleCount"] == 1
    assert out["interfacesUp"] == 1
