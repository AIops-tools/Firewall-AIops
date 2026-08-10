"""The CLI must never report a failed governed write as a success.

Two regressions are pinned here.

**The behaviour** — ``checked()`` aborts non-zero on an error payload and on an
undetermined outcome. Governed twins are wrapped in ``@tool_errors``, which
flattens every exception into ``{"error": ...}`` and *returns* it, so a
command that prints its result unconditionally exits 0 for an operation that
was refused or failed.

**The invariant** — every CLI call into a governed write twin routes its result
through that helper. This is the part that matters over time: the defect was
fixed repo-by-repo several times and kept coming back, because nothing stopped
a *new* command from printing a governed result bare. A structural assertion
does. It was introduced after an audit found the preview path guarded and the
real write path unguarded in 18 of the 24 tools at once — the preview was
stricter than the write it previews.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
import typer

from firewall_aiops.cli._common import checked

CLI_DIR = pathlib.Path(__file__).resolve().parents[1] / "firewall_aiops" / "cli"
TOOLS_DIR = pathlib.Path(__file__).resolve().parents[1] / "mcp_server" / "tools"

#: Helpers that end the command non-zero when the payload reports a failure.
CHECKERS = ['checked', 'dry_run_preview']


@pytest.mark.unit
def test_checked_aborts_on_error_payload():
    with pytest.raises(typer.Exit) as exc:
        checked({"error": "refused: that would lock this tool out"})
    assert exc.value.exit_code == 1


@pytest.mark.unit
def test_checked_passes_a_successful_payload_through():
    payload = {"action": "did_a_thing", "ok": True}
    assert checked(payload) == payload


def _callee(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _write_tool_names() -> set[str]:
    names: set[str] = set()
    for path in TOOLS_DIR.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and "[WRITE]" in (ast.get_docstring(node) or ""):
                names.add(node.name)
    return names


def _aborts_on_failure(fn: ast.FunctionDef) -> bool:
    """Does this function raise ``typer.Exit`` off a failure key in the payload?

    Several commands guard with a locally named helper (``_require_ok``,
    ``_emit``, ...) rather than the shared one. Those are correct guards, so the
    invariant recognises the *shape* instead of a list of blessed names.
    """
    raises_exit = any(
        isinstance(n, ast.Call) and _callee(n.func) == "Exit" for n in ast.walk(fn)
    )
    reads_failure_key = any(
        isinstance(n, ast.Constant) and n.value in ("error", "outcomeUnknown")
        for n in ast.walk(fn)
    )
    return raises_exit and reads_failure_key


def _checker_names() -> set[str]:
    """CHECKERS, every local guard, and any wrapper delegating to one of them."""
    funcs: dict[str, list[ast.FunctionDef]] = {}
    for path in CLI_DIR.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.FunctionDef):
                funcs.setdefault(node.name, []).append(node)
    found = set(CHECKERS) | {
        name for name, defs in funcs.items() if any(_aborts_on_failure(f) for f in defs)
    }
    changed = True
    while changed:
        changed = False
        for name, defs in funcs.items():
            if name in found:
                continue
            for fn in defs:
                if any(isinstance(n, ast.Call) and _callee(n.func) in found for n in ast.walk(fn)):
                    found.add(name)
                    changed = True
                    break
    return found


@pytest.mark.unit
def test_every_cli_governed_write_result_is_checked():
    tools = _write_tool_names()
    assert tools, "no [WRITE] tools parsed — the invariant would vacuously pass"
    checkers = _checker_names()
    unchecked: list[str] = []

    for path in sorted(CLI_DIR.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            parents: dict[ast.AST, ast.AST] = {}
            for node in ast.walk(func):
                for child in ast.iter_child_nodes(node):
                    parents[child] = node
            guarded = {
                arg.id
                for node in ast.walk(func)
                if isinstance(node, ast.Call) and _callee(node.func) in checkers
                for arg in list(node.args) + [kw.value for kw in node.keywords]
                if isinstance(arg, ast.Name)
            }
            for node in ast.walk(func):
                if not (isinstance(node, ast.Call) and _callee(node.func) in tools):
                    continue
                parent = parents.get(node)
                if isinstance(parent, (ast.keyword, ast.Starred)):
                    parent = parents.get(parent)
                if isinstance(parent, ast.Call) and _callee(parent.func) in checkers:
                    continue
                if isinstance(parent, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id in guarded for t in parent.targets
                ):
                    continue
                unchecked.append(f"{path.name}:{node.lineno}:{_callee(node.func)}")

    assert not unchecked, (
        "these CLI call sites print a governed write's result without routing it "
        f"through {sorted(checkers)}, so a refusal exits 0: {unchecked}"
    )

@pytest.mark.unit
def test_undetermined_outcome_beats_error_and_is_not_a_plain_failure():
    """A lost response carries BOTH keys — it must exit 2, not 1.

    ``@tool_errors`` flattens the exception into ``{"error": ...}`` and, when
    the failure is one where the write may still have landed, also sets
    ``outcomeUnknown``. The harness deliberately judges unknown *before* error
    when writing the audit row, for the reason its own note gives: the change
    may have taken effect, so a blind retry could apply it twice. The CLI has to
    agree, or the audit says "may have taken effect" while the exit status tells
    a script it did not happen.
    """
    with pytest.raises(typer.Exit) as exc:
        checked({
            "error": "connection reset while awaiting the response",
            "outcomeUnknown": True,
            "note": "may have taken effect",
        })
    assert exc.value.exit_code == 2
