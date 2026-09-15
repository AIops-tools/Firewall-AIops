"""Every CLI command that reaches the engine is audited.

MCP tools write their audit row through ``@governed_tool``. CLI commands that called
the ops layer directly wrote none: on 2026-09-15 a read command of every tool in the
line, run in a scratch home, left no audit.db while the harness itself worked. Each
such command is now wrapped in ``audited`` (``cli/_common.py``); commands that call an
MCP tool are audited by that tool. This pins the helper's behaviour and that no
engine command escapes it.
"""

from __future__ import annotations

import ast
import inspect
import sqlite3
import textwrap

import pytest
import typer
from typer.main import get_command

from firewall_aiops.cli import app
from firewall_aiops.cli._common import audited

pytestmark = pytest.mark.unit

#: Local-only commands: they never reach the engine (``undo`` goes through MCP tools).
EXEMPT = {"init", "doctor", "secret", "mcp", "undo"}


def _leaves() -> list[tuple[list[str], object]]:
    found: list[tuple[list[str], object]] = []

    def walk(cmd, path):
        if hasattr(cmd, "list_commands"):
            for name, sub in cmd.commands.items():
                walk(sub, path + [name])
        else:
            found.append((path, cmd))

    walk(get_command(app), [])
    return found


def _chain(fn):
    seen = []
    while fn is not None and fn not in seen:
        seen.append(fn)
        fn = getattr(fn, "__wrapped__", None)
    return seen


def _calls_an_mcp_tool(fn) -> bool:
    source = inspect.getsource(fn)
    if "mcp_server" in source:
        return True
    names = set()
    for node in ast.parse(open(inspect.getsourcefile(fn)).read()).body:
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("mcp_server"):
            names |= {a.asname or a.name for a in node.names}
    used = {n.id for n in ast.walk(ast.parse(textwrap.dedent(source))) if isinstance(n, ast.Name)}
    return bool(names & used)


def test_every_engine_command_is_audited():
    commands = [(path, cmd) for path, cmd in _leaves() if path and path[0] not in EXEMPT]
    assert commands, "no commands found: the walker is broken, not the CLI clean"
    missing = [
        " ".join(path) for path, cmd in commands
        if not any(getattr(f, "_is_audited_cli", False) for f in _chain(cmd.callback))
        and not _calls_an_mcp_tool(inspect.unwrap(cmd.callback))
    ]
    assert not missing, f"CLI commands that leave no audit row: {missing}"


@pytest.fixture
def home(tmp_path, monkeypatch):
    import firewall_aiops.governance.audit as audit_mod
    import firewall_aiops.governance.budget as budget_mod

    monkeypatch.setenv("FIREWALL_AIOPS_HOME", str(tmp_path))
    audit_mod.reset_engine()
    budget_mod.reset_budget()
    yield tmp_path
    audit_mod.reset_engine()
    budget_mod.reset_budget()


def _rows(home) -> list[tuple[str, str]]:
    con = sqlite3.connect(home / "audit.db")
    try:
        return con.execute("SELECT tool, status FROM audit_log ORDER BY id").fetchall()
    finally:
        con.close()


def test_audited_records_success_exit_codes_and_exceptions(home):
    @audited
    def cmd_ok(target=None):
        return None

    @audited
    def cmd_exit_zero(target=None):
        raise typer.Exit()

    @audited
    def cmd_exit_one(target=None):
        raise typer.Exit(1)

    @audited
    def cmd_raises(target=None):
        raise RuntimeError("engine unreachable")

    cmd_ok()
    with pytest.raises(typer.Exit) as zero:
        cmd_exit_zero()
    assert zero.value.exit_code == 0
    with pytest.raises(typer.Exit) as one:
        cmd_exit_one()
    assert one.value.exit_code == 1
    with pytest.raises(RuntimeError, match="engine unreachable"):
        cmd_raises()
    assert _rows(home) == [("cmd_ok", "ok"), ("cmd_exit_zero", "ok"),
                           ("cmd_exit_one", "error"), ("cmd_raises", "error")]


def test_audited_keeps_the_command_signature_for_typer():
    def cmd(limit: int = 5, target: str | None = None) -> None:
        return None

    assert list(inspect.signature(audited(cmd)).parameters) == ["limit", "target"]
