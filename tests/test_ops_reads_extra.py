"""Extra read-path ops coverage: rules detail/states, NAT outbound/1:1, VPN
OpenVPN/IPsec, DHCP static, diag states/top-talkers, system firmware/health,
aliases list/entries, and the resilient ``{"error": ...}`` degrade path on every
read.

A fake connection returns canned JSON per platform path (never a live firewall),
carrying a real Platform descriptor so ops resolve the same central-encoded
paths (``Platform.path``) they would in production.
"""

from __future__ import annotations

import pytest

from firewall_aiops.config import TargetConfig
from firewall_aiops.ops import (
    aliases,
    dhcp,
    diag,
    nat,
    overview,
    rules,
    system,
    vpn,
)
from firewall_aiops.platform import OPNSENSE, PFSENSE, get_platform


class _Conn:
    """Fake connection: get() looks up canned responses by path; a get that
    raises simulates a transport failure so the resilient path is exercised."""

    def __init__(self, responses, platform=OPNSENSE, raise_exc=None):
        self.target = TargetConfig(name="t", platform=platform, host="h", username="k")
        self.platform = self.target.platform_obj
        self._responses = responses
        self._raise = raise_exc

    def get(self, path, **_kw):
        if self._raise is not None:
            raise self._raise
        return self._responses.get(path, {})


def _p(platform, resource, **fmt):
    return get_platform(platform).path(resource, **fmt)


# ── rules: detail + states + error ───────────────────────────────────────────


@pytest.mark.unit
def test_rule_detail_opnsense_unwraps_rule_key():
    conn = _Conn({
        _p(OPNSENSE, "rule_get", uuid="r1"): {
            "rule": {"uuid": "r1", "enabled": "1", "action": "pass", "interface": "wan"}
        }
    })
    out = rules.rule_detail(conn, "r1")
    assert out["uuid"] == "r1" and out["enabled"] is True and out["action"] == "pass"


@pytest.mark.unit
def test_rule_detail_pfsense_unwraps_data_and_fills_uuid():
    conn = _Conn(
        {_p(PFSENSE, "rule_get", uuid="7"): {"data": {"disabled": True, "type": "block"}}},
        platform=PFSENSE,
    )
    out = rules.rule_detail(conn, "7")
    # pfSense row has no id → op backfills the requested uuid
    assert out["uuid"] == "7" and out["enabled"] is False


@pytest.mark.unit
def test_rule_detail_reports_error_with_uuid_on_failure():
    conn = _Conn({}, raise_exc=RuntimeError("boom"))
    out = rules.rule_detail(conn, "r9")
    assert "error" in out and out["uuid"] == "r9"


@pytest.mark.unit
def test_rule_states_top_limit_and_fields():
    conn = _Conn({
        _p(OPNSENSE, "rule_states"): {"rows": [
            {"interface": "wan", "proto": "tcp", "src": "1.1.1.1", "dst": "2.2.2.2",
             "state": "ESTABLISHED", "age": "10"},
            {"interface": "lan", "proto": "udp", "src": "3.3.3.3", "dst": "4.4.4.4"},
        ]}
    })
    out = rules.rule_states(conn, top=1)
    assert out["total"] == 2 and len(out["states"]) == 1
    assert out["states"][0]["source"] == "1.1.1.1"


@pytest.mark.unit
def test_rule_stats_error_path():
    conn = _Conn({}, raise_exc=ValueError("bad"))
    assert "error" in rules.rule_stats(conn)


# ── NAT: outbound + 1:1 + error ──────────────────────────────────────────────


@pytest.mark.unit
def test_outbound_nat_normalizes_translation():
    conn = _Conn({
        _p(OPNSENSE, "nat_outbound"): {"rows": [
            {"uuid": "o1", "enabled": "1", "interface": "wan",
             "source_net": "10.0.0.0/24", "target": "1.2.3.4", "description": "hide"},
        ]}
    })
    out = nat.outbound_nat(conn)
    assert out["total"] == 1
    m = out["outboundNat"][0]
    assert m["translation"] == "1.2.3.4" and m["source"] == "10.0.0.0/24"


@pytest.mark.unit
def test_one_to_one_nat_normalizes_external_internal():
    conn = _Conn({
        _p(OPNSENSE, "nat_one_to_one"): {"rows": [
            {"uuid": "b1", "disabled": False, "interface": "wan",
             "external": "5.5.5.5", "internal": "10.0.0.9"},
        ]}
    })
    out = nat.one_to_one_nat(conn)
    m = out["oneToOneNat"][0]
    assert m["external"] == "5.5.5.5" and m["internal"] == "10.0.0.9" and m["enabled"] is True


@pytest.mark.unit
def test_nat_reads_error_path():
    conn = _Conn({}, raise_exc=RuntimeError("x"))
    assert "error" in nat.port_forwards(conn)
    assert "error" in nat.outbound_nat(conn)
    assert "error" in nat.one_to_one_nat(conn)


# ── VPN: OpenVPN + IPsec + error ─────────────────────────────────────────────


@pytest.mark.unit
def test_openvpn_sessions_normalizes():
    conn = _Conn({
        _p(OPNSENSE, "openvpn"): {"rows": [
            {"common_name": "laptop", "real_address": "9.9.9.9:1194",
             "virtual_address": "10.8.0.2", "bytes_received": 100, "bytes_sent": 200},
        ]}
    })
    out = vpn.openvpn_sessions(conn)
    assert out["total"] == 1
    s0 = out["sessions"][0]
    assert s0["commonName"] == "laptop" and s0["bytesSent"] == 200


@pytest.mark.unit
def test_ipsec_sas_normalizes_installed_flag():
    conn = _Conn({
        _p(OPNSENSE, "ipsec"): {"rows": [
            {"name": "site-b", "local-host": "1.1.1.1", "remote-host": "2.2.2.2",
             "state": "ESTABLISHED", "installed": "1", "bytes-in": 10, "bytes-out": 20},
        ]}
    })
    out = vpn.ipsec_sas(conn)
    sa = out["securityAssociations"][0]
    assert sa["installed"] is True and sa["remoteAddress"] == "2.2.2.2"


@pytest.mark.unit
def test_vpn_reads_error_path():
    conn = _Conn({}, raise_exc=RuntimeError("down"))
    assert "error" in vpn.wireguard_status(conn)
    assert "error" in vpn.openvpn_sessions(conn)
    assert "error" in vpn.ipsec_sas(conn)


# ── DHCP: static mappings + error ────────────────────────────────────────────


@pytest.mark.unit
def test_dhcp_static_mappings_normalizes():
    conn = _Conn({
        _p(OPNSENSE, "dhcp_static"): {"rows": [
            {"mac": "aa:bb", "ipaddr": "10.0.0.50", "hostname": "printer",
             "descr": "front office"},
        ]}
    })
    out = dhcp.static_mappings(conn)
    assert out["total"] == 1
    assert out["staticMappings"][0]["ip"] == "10.0.0.50"


@pytest.mark.unit
def test_dhcp_reads_error_path():
    conn = _Conn({}, raise_exc=RuntimeError("x"))
    assert "error" in dhcp.leases(conn)
    assert "error" in dhcp.static_mappings(conn)


# ── diag: states_table + pull_log + errors ───────────────────────────────────


@pytest.mark.unit
def test_states_table_top_limit_and_bytes():
    conn = _Conn({
        _p(OPNSENSE, "states"): {"rows": [
            {"interface": "wan", "proto": "tcp", "src": "1.1.1.1", "dst": "2.2.2.2",
             "state": "ESTABLISHED", "bytes": 500, "packets": 5},
            {"interface": "lan", "proto": "udp", "src": "3.3.3.3", "dst": "4.4.4.4"},
        ]}
    })
    out = diag.states_table(conn, top=1)
    assert out["total"] == 2 and len(out["states"]) == 1
    assert out["states"][0]["bytes"] == 500


@pytest.mark.unit
def test_pull_log_normalizes_and_limits():
    conn = _Conn({
        _p(OPNSENSE, "firewall_log"): {"rows": [
            {"action": "Block", "src": "9.9.9.9", "dstport": "22"},
            {"action": "pass", "src": "10.0.0.1", "dstport": "443"},
            {"action": "block", "src": "8.8.8.8", "dstport": "23"},
        ]}
    })
    rows = diag.pull_log(conn, limit=2)
    assert len(rows) == 2
    # action is lower-cased during normalisation
    assert rows[0]["action"] == "block"


@pytest.mark.unit
def test_firewall_log_no_action_returns_all():
    conn = _Conn({
        _p(OPNSENSE, "firewall_log"): {"rows": [
            {"action": "block", "src": "9.9.9.9", "dstport": "22"},
            {"action": "pass", "src": "10.0.0.1", "dstport": "443"},
        ]}
    })
    out = diag.firewall_log(conn)
    assert out["returned"] == 2 and out["action"] == "all"
    assert out["truncated"] is False and out["limit"] == 200


@pytest.mark.unit
def test_diag_error_paths():
    conn = _Conn({}, raise_exc=RuntimeError("x"))
    assert "error" in diag.states_table(conn)
    assert "error" in diag.top_talkers(conn)
    # firewall_log wraps non-ValueError as {"error": ...}
    assert "error" in diag.firewall_log(conn)


# ── system: firmware + health + gateway error ────────────────────────────────


@pytest.mark.unit
def test_firmware_status_opnsense_fields():
    conn = _Conn({
        _p(OPNSENSE, "firmware"): {
            "product_version": "24.7", "product_name": "OPNsense", "status": "1",
        }
    })
    out = system.firmware_status(conn)
    assert out["version"] == "24.7" and out["updatesAvailable"] is True


@pytest.mark.unit
def test_firmware_status_pfsense_unwraps_data():
    conn = _Conn(
        {_p(PFSENSE, "firmware"): {"data": {"version": "2.7.2", "product": "pfSense"}}},
        platform=PFSENSE,
    )
    out = system.firmware_status(conn)
    assert out["version"] == "2.7.2" and out["product"] == "pfSense"


@pytest.mark.unit
def test_firmware_status_opnsense_reads_nested_product():
    """Regression (live-found on real OPNsense 26.7, 2026-08-01): OPNsense nests
    the version under ``product`` (product_version / product_id), NOT at the top
    level — reading the top level returned version=null on every real firewall."""
    conn = _Conn(
        {_p(OPNSENSE, "firmware"): {
            "status": "none",
            "product": {"product_version": "26.7", "product_id": "opnsense",
                        "CORE_VERSION": "26.7"},
        }},
        platform=OPNSENSE,
    )
    out = system.firmware_status(conn)
    assert out["version"] == "26.7"
    assert out["product"] == "opnsense"  # product_id, not the product dict


@pytest.mark.unit
def test_rule_evaluation_count_is_int_not_float():
    """Regression (bug class #2, live-observed on OPNsense 2026-08-01): a rule's
    evaluation counter must render as int, not float (0.0) — a float count is
    semantically wrong and equality assertions do not catch it."""
    row = rules._norm_rule({"uuid": "u", "enabled": "1", "evaluations": 202.0})
    assert row["evaluations"] == 202
    assert isinstance(row["evaluations"], int)


@pytest.mark.unit
def test_health_status_fields():
    conn = _Conn({
        _p(OPNSENSE, "system_info"): {
            "hostname": "fw", "uptime": "10 days", "cpu": 12, "memory": 40,
        }
    })
    out = system.health_status(conn)
    assert out["hostname"] == "fw" and out["cpuPercent"] == 12 and out["memPercent"] == 40


@pytest.mark.unit
def test_system_reads_error_paths():
    conn = _Conn({}, raise_exc=RuntimeError("x"))
    assert "error" in system.firmware_status(conn)
    assert "error" in system.health_status(conn)
    assert "error" in system.gateway_status(conn)
    assert "error" in system.interface_status(conn)


# ── aliases: list error + entries pfsense address-list + error ───────────────


@pytest.mark.unit
def test_list_aliases_error_path():
    conn = _Conn({}, raise_exc=RuntimeError("x"))
    assert "error" in aliases.list_aliases(conn)


@pytest.mark.unit
def test_alias_entries_pfsense_address_list_shape():
    conn = _Conn(
        {_p(PFSENSE, "alias_entries", name="bogons"): {
            "data": {"name": "bogons", "address": ["1.2.3.4", "5.6.7.8"]}
        }},
        platform=PFSENSE,
    )
    out = aliases.alias_entries(conn, "bogons")
    assert out["total"] == 2 and "5.6.7.8" in out["entries"]


@pytest.mark.unit
def test_alias_entries_string_content_splits():
    conn = _Conn({
        _p(OPNSENSE, "alias_entries", name="nets"): {"content": "10.0.0.0/8 172.16.0.0/12"}
    })
    out = aliases.alias_entries(conn, "nets")
    assert out["total"] == 2


@pytest.mark.unit
def test_alias_entries_error_carries_name():
    conn = _Conn({}, raise_exc=RuntimeError("x"))
    out = aliases.alias_entries(conn, "bl")
    assert "error" in out and out["alias"] == "bl"


@pytest.mark.unit
def test_list_aliases_counts_list_content():
    conn = _Conn({
        _p(OPNSENSE, "aliases_search"): {"rows": [
            {"uuid": "a1", "name": "hosts", "type": "host",
             "content": ["10.0.0.1", "10.0.0.2", ""]},
        ]}
    })
    out = aliases.list_aliases(conn)
    # empty member is not counted
    assert out["aliases"][0]["entries"] == 2


# ── overview: partial-degrade with errors list ───────────────────────────────


@pytest.mark.unit
def test_firewall_overview_collects_errors_when_subcalls_fail():
    conn = _Conn({}, raise_exc=RuntimeError("unreachable"))
    out = overview.firewall_overview(conn)
    assert out["platform"] == "opnsense"
    # every sub-read failed → each contributes an error line, counts degrade to 0
    assert len(out["errors"]) == 4
    assert out["ruleCount"] is None and out["gatewaysTotal"] == 0
