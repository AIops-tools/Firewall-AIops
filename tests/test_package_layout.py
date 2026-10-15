"""The wheel ships exactly one top-level package, and nothing imports a shared one.

Every AIops tool used to install a top-level ``mcp_server`` package beside its
own. Two tools in one environment then merged into a single ``mcp_server``:
one tool's ``-mcp`` entry point started the other tool's server, and its CLI
``undo`` wrote audit rows into the other tool's home. The server now lives at
``<pkg>.mcp_server``. This file is identical across the AIops line.
"""

import ast
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))
WHEEL_PACKAGES = PYPROJECT["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]
PKG = WHEEL_PACKAGES[0]


def test_wheel_ships_only_the_tool_package():
    assert WHEEL_PACKAGES == [PKG]
    assert PKG != "mcp_server"


def test_no_top_level_mcp_server_directory():
    assert not (ROOT / "mcp_server").exists()
    assert (ROOT / PKG / "mcp_server" / "server.py").is_file()


def test_mcp_entry_point_starts_this_tools_server():
    entries = [v for k, v in PYPROJECT["project"]["scripts"].items() if k.endswith("-mcp")]
    assert entries == [f"{PKG}.mcp_server.server:main"]


def _imported_modules(path: Path) -> list[str]:
    names: list[str] = []
    for node in ast.walk(ast.parse(path.read_text("utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.append(node.module)
        elif isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
    return names


def test_nothing_imports_a_top_level_mcp_server():
    files = [p for d in (ROOT / PKG, ROOT / "tests") for p in d.rglob("*.py")]
    assert files, "no source files found"
    offenders = sorted(
        f"{p.relative_to(ROOT)}: {name}"
        for p in files
        if "__pycache__" not in p.parts
        for name in _imported_modules(p)
        if name == "mcp_server" or name.startswith("mcp_server.")
    )
    assert not offenders, offenders


def test_server_module_resolves_inside_the_package():
    import importlib

    server = importlib.import_module(f"{PKG}.mcp_server.server")
    assert Path(server.__file__).resolve().is_relative_to((ROOT / PKG).resolve())
