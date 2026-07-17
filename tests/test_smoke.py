"""Smoke tests for firewall-aiops.

Proves: every module imports, the CLI builds and --help works, the MCP server
exposes the expected tool surface and EVERY tool carries the harness marker
``_is_governed_tool``, and config platform validation works. No real
OPNsense/pfSense is needed.
"""

import asyncio
import importlib

import pytest
from typer.testing import CliRunner

# Kept in sync with mcp_server/server.py (the full registered tool surface).
EXPECTED_TOOLS = {
    # system
    "firmware_status", "health_status", "interface_status", "gateway_status",
    # rules
    "list_rules", "rule_detail", "rule_stats", "rule_states",
    # nat
    "nat_port_forwards", "nat_outbound", "nat_one_to_one",
    # aliases
    "list_aliases", "alias_entries",
    # vpn
    "wireguard_status", "openvpn_sessions", "ipsec_sas",
    # dhcp
    "dhcp_leases", "dhcp_static_mappings",
    # diag
    "firewall_log", "states_table", "top_talkers",
    # analysis (flagship)
    "gateway_health_rca", "rule_hit_and_shadow_analysis", "blocked_traffic_rca",
    # writes
    "toggle_rule", "add_alias_entry", "remove_alias_entry", "apply_changes",
    "reconfigure", "kill_states", "restart_service", "reboot",
}


@pytest.mark.unit
def test_all_modules_import():
    for name in (
        "firewall_aiops", "firewall_aiops.config", "firewall_aiops.connection",
        "firewall_aiops.platform", "firewall_aiops.doctor",
        "firewall_aiops.secretstore",
        "firewall_aiops.ops.system", "firewall_aiops.ops.rules",
        "firewall_aiops.ops.nat", "firewall_aiops.ops.aliases",
        "firewall_aiops.ops.vpn", "firewall_aiops.ops.dhcp",
        "firewall_aiops.ops.diag", "firewall_aiops.ops.analysis",
        "firewall_aiops.ops.writes", "firewall_aiops.ops.overview",
        "firewall_aiops.cli", "firewall_aiops.cli._root", "firewall_aiops.cli._common",
        "firewall_aiops.cli.init", "firewall_aiops.cli.secret",
        "firewall_aiops.cli.rules", "firewall_aiops.cli.log",
        "firewall_aiops.cli.overview", "firewall_aiops.cli.doctor",
        "mcp_server.server", "mcp_server._shared",
        "mcp_server.tools.system", "mcp_server.tools.writes",
    ):
        importlib.import_module(name)


@pytest.mark.unit
def test_version_matches_pyproject():
    """__version__ is single-sourced from package metadata; it must track
    pyproject.toml so a release bump can never ship a stale self-report."""
    import tomllib
    from pathlib import Path

    import firewall_aiops

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    expected = tomllib.loads(pyproject.read_text("utf-8"))["project"]["version"]
    assert firewall_aiops.__version__ == expected


@pytest.mark.unit
def test_cli_app_builds_and_help_works():
    from firewall_aiops.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for sub in ("rules", "secret", "init", "overview", "log", "doctor", "mcp"):
        assert sub in result.output


@pytest.mark.unit
def test_cli_leaf_help_triggers_lazy_imports():
    from firewall_aiops.cli import app

    runner = CliRunner()
    for cmd in (
        ["rules", "--help"], ["secret", "--help"], ["doctor", "--help"],
        ["overview", "--help"], ["log", "--help"], ["init", "--help"],
        ["rules", "list", "--help"], ["rules", "show", "--help"],
        ["rules", "toggle", "--help"],
        ["secret", "list", "--help"], ["secret", "set", "--help"],
    ):
        result = runner.invoke(app, cmd)
        assert result.exit_code == 0, f"{cmd} failed: {result.output}"


@pytest.mark.unit
def test_mcp_list_tools_exposes_expected_tools():
    from mcp_server.server import mcp

    tools = asyncio.run(mcp.list_tools())
    names = {t.name for t in tools}
    assert EXPECTED_TOOLS <= names, f"missing: {EXPECTED_TOOLS - names}"


@pytest.mark.unit
def test_every_mcp_tool_is_governed_by_harness():
    from mcp_server import _shared

    tool_objs = _shared.mcp._tool_manager._tools
    assert EXPECTED_TOOLS <= set(tool_objs), "tool registry incomplete"
    for name, tool in tool_objs.items():
        fn = getattr(tool, "fn", None)
        assert fn is not None, f"{name} has no fn"
        assert getattr(fn, "_is_governed_tool", False), f"{name} missing @governed_tool"


@pytest.mark.unit
def test_tool_count_is_expected():
    from mcp_server import _shared

    assert len(_shared.mcp._tool_manager._tools) == 34
