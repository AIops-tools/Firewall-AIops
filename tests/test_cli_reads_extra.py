"""CLI read commands (overview / log / rules list+show) and the undo list path.

The connection layer is faked at ``cli._common.get_connection`` so the commands
render real op output without a live firewall; error translation is checked too.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from firewall_aiops.config import TargetConfig
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


@pytest.fixture
def patched_conn(monkeypatch):
    """Return a factory that installs a fake connection for the CLI commands.

    Each command module imports ``get_connection`` into its own namespace, so we
    patch the name where it is used, not only on ``_common``.
    """
    from firewall_aiops.cli import log, overview, rules

    def install(responses):
        conn = _Conn(responses)
        fake = lambda target, config_path=None: (conn, None)  # noqa: E731
        for mod in (overview, log, rules):
            monkeypatch.setattr(mod, "get_connection", fake)
        return conn

    return install


@pytest.mark.unit
def test_cli_overview_renders_summary(patched_conn):
    from firewall_aiops.cli import app

    patched_conn({
        _p("firmware"): {"product_version": "24.7"},
        _p("gateways"): {"rows": [{"name": "WAN", "status": "none"}]},
        _p("interfaces"): {"wan": {"status": "up"}},
        _p("rules_search"): {"rows": [{"uuid": "r1", "enabled": "1"}]},
    })
    r = CliRunner().invoke(app, ["overview"])
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    assert data["version"] == "24.7" and data["ruleCount"] == 1


@pytest.mark.unit
def test_cli_log_action_filter(patched_conn):
    from firewall_aiops.cli import app

    patched_conn({
        _p("firewall_log"): {"rows": [
            {"action": "block", "src": "9.9.9.9", "dstport": "22"},
            {"action": "pass", "src": "10.0.0.1", "dstport": "443"},
        ]}
    })
    r = CliRunner().invoke(app, ["log", "--action", "block"])
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    assert data["total"] == 1 and data["action"] == "block"


@pytest.mark.unit
def test_cli_rules_list_and_show(patched_conn):
    from firewall_aiops.cli import app

    patched_conn({
        _p("rules_search"): {"rows": [
            {"uuid": "r1", "enabled": "1", "action": "pass", "interface": "wan"},
        ]},
        _p("rule_get", uuid="r1"): {"rule": {"uuid": "r1", "enabled": "1", "action": "pass"}},
    })
    r = CliRunner().invoke(app, ["rules", "list"])
    assert r.exit_code == 0 and json.loads(r.output)["total"] == 1

    r = CliRunner().invoke(app, ["rules", "show", "r1"])
    assert r.exit_code == 0 and json.loads(r.output)["uuid"] == "r1"


@pytest.mark.unit
def test_cli_error_translation_one_liner(monkeypatch):
    """A FirewallApiError from the op surfaces as one red line + exit 1, not a
    traceback (cli_errors path)."""
    from firewall_aiops.cli import app, overview
    from firewall_aiops.connection import FirewallApiError

    def boom(target, config_path=None):
        raise FirewallApiError("auth failed (401)")

    monkeypatch.setattr(overview, "get_connection", boom)
    r = CliRunner().invoke(app, ["overview"])
    assert r.exit_code == 1
    assert "Error:" in r.output and "auth failed" in r.output


@pytest.mark.unit
def test_cli_undo_list_renders(monkeypatch):
    from firewall_aiops.cli import app
    from mcp_server.tools import undo as gov

    monkeypatch.setattr(gov, "undo_list", lambda limit=50, target=None: {"total": 0, "undos": []})
    r = CliRunner().invoke(app, ["undo", "list"])
    assert r.exit_code == 0 and json.loads(r.output)["total"] == 0


@pytest.mark.unit
def test_cli_no_args_shows_help():
    from firewall_aiops.cli import app

    r = CliRunner().invoke(app, [])
    # no_args_is_help → usage text, non-zero exit
    assert "Usage" in r.output or "Governed AI-ops" in r.output
