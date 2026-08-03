"""Undo EXECUTOR — undo_apply dispatches a recorded inverse through its governed
tool, on a real undo.db in an isolated home. Closes the loop from "undo recorded"
to "undo actually executed".

Portable across the line: the dispatched inverse is a synthetic governed tool
registered on the real MCP instance, so this file is identical everywhere except
the package import path.
"""

from __future__ import annotations

import sqlite3

import pytest

import firewall_aiops.governance.audit as audit_mod
import firewall_aiops.governance.policy as policy_mod
import firewall_aiops.governance.undo as undo_mod
from firewall_aiops.governance import governed_tool
from mcp_server._shared import mcp
from mcp_server.tools import undo as gov

_CALLS: list[dict] = []
_TARGETS: list = []


@governed_tool(risk_level="low")
def _undo_probe(value: str = "", target=None) -> dict:
    """Synthetic inverse target used only by the undo-executor tests."""
    _CALLS.append({"value": value})
    _TARGETS.append(target)
    return {"ok": True, "value": value}


@pytest.fixture
def gov_home(tmp_path, monkeypatch):
    _CALLS.clear()
    _TARGETS.clear()
    # Register the probe only for the duration of these tests so it never
    # pollutes the real tool registry (which exact-count smoke tests assert on).
    mcp.add_tool(_undo_probe, name="_undo_probe")
    monkeypatch.setenv("FIREWALL_AIOPS_HOME", str(tmp_path))
    monkeypatch.setenv("FIREWALL_AUDIT_APPROVED_BY", "pytest")
    audit_mod.reset_engine()
    policy_mod.reset_policy_engine()
    undo_mod.reset_undo_store()
    yield tmp_path
    mcp._tool_manager._tools.pop("_undo_probe", None)
    audit_mod.reset_engine()
    policy_mod.reset_policy_engine()
    undo_mod.reset_undo_store()


def _record(undo_tool="_undo_probe", params=None):
    descriptor = {"tool": undo_tool, "params": params if params is not None else {"value": "v1"}}
    return undo_mod.get_undo_store().record(
        skill="probe", tool="orig_op", undo_descriptor=descriptor,
    )


@pytest.mark.unit
def test_undo_list_returns_recorded_tokens(gov_home):
    uid = _record()
    out = gov.undo_list()
    assert out["count"] == 1
    assert out["undos"][0]["undoId"] == uid
    assert out["undos"][0]["inverseTool"] == "_undo_probe"


@pytest.mark.unit
def test_undo_apply_dispatches_inverse_and_marks_applied(gov_home):
    uid = _record(params={"value": "restore-me"})
    result = gov.undo_apply(undo_id=uid)
    assert result["applied"] is True
    assert result["inverseTool"] == "_undo_probe"
    # the inverse governed tool actually ran with the recorded params
    assert _CALLS == [{"value": "restore-me"}]
    # the token is consumed (single-use)
    assert undo_mod.get_undo_store().get(uid)["status"] == "applied"
    assert uid not in {u["undoId"] for u in gov.undo_list()["undos"]}


@pytest.mark.unit
def test_undo_apply_replays_against_the_target_the_write_ran_on(gov_home):
    """A replay must go to the host the original write went to.

    Without this the inverse ran against whatever target the caller named — in
    practice the config's first entry — so on a multi-target config it hit the
    wrong host. It only looked harmless because the resource usually does not
    exist there; two hosts holding the same name and the inverse succeeds on the
    wrong one, silently. Caught live on 2026-08-03 in container-host-aiops: a
    stop recorded against a Podman target replayed against a Portainer target.
    """
    uid = undo_mod.get_undo_store().record(
        skill="probe",
        tool="orig_op",
        undo_descriptor={"tool": "_undo_probe", "params": {"value": "v1"}},
        orig_params={"value": "v1", "target": "second-host"},
    )
    result = gov.undo_apply(undo_id=uid)
    assert result["applied"] is True
    assert _TARGETS == ["second-host"]


@pytest.mark.unit
def test_undo_apply_prefers_an_explicit_caller_target(gov_home):
    """An explicitly named target still wins — the fallback is only a default."""
    uid = undo_mod.get_undo_store().record(
        skill="probe",
        tool="orig_op",
        undo_descriptor={"tool": "_undo_probe", "params": {"value": "v1"}},
        orig_params={"value": "v1", "target": "second-host"},
    )
    gov.undo_apply(undo_id=uid, target="chosen-host")
    assert _TARGETS == ["chosen-host"]


@pytest.mark.unit
def test_undo_apply_survives_unreadable_orig_params(gov_home):
    """Corrupt orig_params must not break the replay — just lose the fallback."""
    uid = _record(params={"value": "v1"})
    with sqlite3.connect(gov_home / "undo.db") as db:
        db.execute("UPDATE undo_log SET orig_params = ? WHERE undo_id = ?",
                   ("{not json", uid))
    assert gov.undo_apply(undo_id=uid)["applied"] is True
    assert _TARGETS == [None]


@pytest.mark.unit
def test_undo_apply_dry_run_previews_without_running(gov_home):
    uid = _record()
    out = gov.undo_apply(undo_id=uid, dry_run=True)
    assert out["dryRun"] is True
    assert out["wouldApply"]["tool"] == "_undo_probe"
    assert _CALLS == []
    assert undo_mod.get_undo_store().get(uid)["status"] == "recorded"


@pytest.mark.unit
def test_undo_apply_is_single_use(gov_home):
    uid = _record()
    gov.undo_apply(undo_id=uid)
    second = gov.undo_apply(undo_id=uid)
    assert "already 'applied'" in second["error"]


@pytest.mark.unit
def test_undo_apply_unknown_id_errors(gov_home):
    out = gov.undo_apply(undo_id="deadbeef")
    assert "Unknown undo id" in out["error"]


@pytest.mark.unit
def test_undo_apply_unregistered_inverse_errors(gov_home):
    uid = _record(undo_tool="no_such_tool_xyz")
    out = gov.undo_apply(undo_id=uid)
    assert "not registered" in out["error"]
    assert undo_mod.get_undo_store().get(uid)["status"] == "recorded"


@pytest.mark.unit
def test_cli_undo_apply_dry_run_renders(gov_home):
    """The `undo apply --dry-run` CLI path must render without error — guards
    against dry_run_print signature drift across tools (api_call vs detail)."""
    from typer.testing import CliRunner

    from firewall_aiops.cli import app

    uid = _record()
    result = CliRunner().invoke(app, ["undo", "apply", uid, "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "DRY-RUN" in result.output
    # effectVerified rides in the banner: False would mean the original write
    # lost its response, so the change being reversed is probable, not confirmed.
    assert "effectVerified = True" in result.output
    assert _CALLS == []
    assert undo_mod.get_undo_store().get(uid)["status"] == "recorded"


@pytest.mark.unit
def test_cli_undo_apply_dry_run_of_an_unapplicable_token_is_refused(gov_home):
    """A preview whose answer is "this cannot be applied" must refuse, not preview.

    An unknown id, a spent token and an unregistered inverse all come back from
    the governed twin as ``{"error": ...}``. The CLI used to read straight past
    that into ``preview["wouldApply"]``, print ``inverse: ?`` under a green
    DRY-RUN banner and exit 0 — telling the operator (and any ``&&`` chain) that
    an inapplicable undo was ready to go.
    """
    from typer.testing import CliRunner

    from firewall_aiops.cli import app

    spent = _record()
    gov.undo_apply(undo_id=spent)
    unregistered = _record(undo_tool="no_such_tool_xyz")

    for undo_id, expected in (
        ("deadbeef", "Unknown undo id"),
        (spent, "already 'applied'"),
        (unregistered, "not registered"),
    ):
        result = CliRunner().invoke(app, ["undo", "apply", undo_id, "--dry-run"])
        assert result.exit_code == 1, result.output
        assert "DRY-RUN" not in result.output
        assert expected in result.output


@pytest.mark.unit
def test_undo_apply_audits_both_wrapper_and_inverse(gov_home):
    uid = _record()
    gov.undo_apply(undo_id=uid)
    conn = sqlite3.connect(gov_home / "audit.db")
    try:
        tools = [r[0] for r in conn.execute("SELECT tool FROM audit_log ORDER BY id")]
    finally:
        conn.close()
    assert "undo_apply" in tools
    assert "_undo_probe" in tools


@pytest.mark.unit
def test_resolve_tool_loads_full_registry_under_cli_only_import():
    """Regression (live-found 2026-07-31): CLI ``undo apply`` runs in a process
    that imports only ``mcp_server.tools.undo`` — every write tool is imported
    lazily inside its own CLI command, so the inverse was "not registered" and
    CLI-initiated undo failed for every write tool. ``_resolve_tool`` must force
    a full server load on a miss.

    Reproduced in a FRESH interpreter, because this pytest process has already
    imported the whole server, which would mask the bug.
    """
    import subprocess
    import sys
    import textwrap

    script = textwrap.dedent(
        """
        from mcp_server._shared import mcp
        import mcp_server.tools.undo as u
        before = set(mcp._tool_manager._tools)
        # A miss must trigger the full-registry load, not just return None.
        u._resolve_tool("__definitely_not_a_tool__")
        after = set(mcp._tool_manager._tools)
        new = after - before
        assert new, "fallback loaded no additional tools"
        sample = sorted(new)[0]
        assert u._resolve_tool(sample) is not None, sample
        print("OK", len(before), len(after))
        """
    )
    r = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("OK"), r.stdout
