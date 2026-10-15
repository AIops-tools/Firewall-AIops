"""Invariants for the MCP annotations derived from ``risk_level``.

Asserted on ``list_tools()`` — the payload a client actually receives — not on
the internal registry, so a regression in how annotations reach the wire fails
here too. This file is identical across the AIops line.
"""

import asyncio
import importlib
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp.server import MCPServer


def _server_package() -> str:
    """``<pkg>.mcp_server``, found on disk so this file needs no per-tool name."""
    root = Path(__file__).resolve().parents[1]
    found = sorted(p.parent.parent.name for p in root.glob("*/mcp_server/server.py"))
    assert len(found) == 1, f"expected exactly one <pkg>/mcp_server/server.py, found {found}"
    return f"{found[0]}.mcp_server"


SERVER_PACKAGE = _server_package()
server = importlib.import_module(f"{SERVER_PACKAGE}.server")
_annotations = importlib.import_module(f"{SERVER_PACKAGE}._annotations")
RISK_META_KEY = _annotations.RISK_META_KEY
annotations_for = _annotations.annotations_for
apply_risk_annotations = _annotations.apply_risk_annotations


@pytest.fixture(scope="module")
def listed():
    return asyncio.run(server.mcp.list_tools())


@pytest.fixture(scope="module")
def registry():
    return server.mcp._tool_manager._tools


def test_every_tool_is_annotated(listed):
    assert listed, "no tools listed"
    missing = [t.name for t in listed if t.annotations is None or not t.meta]
    assert not missing, f"tools advertised without annotations: {missing}"


def test_meta_carries_the_declared_risk_level(listed, registry):
    wrong = [t.name for t in listed if t.meta.get(RISK_META_KEY) != registry[t.name].fn._risk_level]
    assert not wrong, f"_meta risk level differs from @governed_tool: {wrong}"


def test_read_only_hint_true_exactly_for_low_risk(listed):
    wrong = [
        t.name for t in listed if t.annotations.read_only_hint != (t.meta[RISK_META_KEY] == "low")
    ]
    assert not wrong, f"readOnlyHint disagrees with risk_level: {wrong}"


def test_no_write_claims_to_be_non_destructive(listed):
    # medium holds deletes and hard power-offs; the tier cannot prove safety.
    wrong = [
        t.name
        for t in listed
        if not t.annotations.read_only_hint and t.annotations.destructive_hint is not True
    ]
    assert not wrong, f"writes advertised as non-destructive: {wrong}"


def test_idempotent_hint_only_echoes_an_explicit_declaration(listed, registry):
    wrong = [
        t.name
        for t in listed
        if t.annotations.idempotent_hint and not registry[t.name].fn._idempotent
    ]
    assert not wrong, f"idempotentHint inferred without a declaration: {wrong}"


def test_open_world_hint_is_never_narrowed(listed):
    assert all(t.annotations.open_world_hint in (None, True) for t in listed)


@pytest.mark.parametrize("level", ["low", "medium", "high", "critical"])
def test_mapping_per_level(level):
    hints = annotations_for(level, idempotent=False)
    if level == "low":
        assert hints.read_only_hint is True
        assert hints.destructive_hint is None
    else:
        assert hints.read_only_hint is False
        assert hints.destructive_hint is True
        assert hints.idempotent_hint is False


def test_declared_idempotent_write_is_echoed():
    assert annotations_for("medium", idempotent=True).idempotent_hint is True


def test_unknown_risk_level_is_rejected():
    with pytest.raises(ValueError, match="unknown risk_level"):
        annotations_for("Low", idempotent=False)


def test_ungoverned_tool_fails_fast():
    fake_tool = SimpleNamespace(fn=lambda: None, meta=None)
    fake = SimpleNamespace(_tool_manager=SimpleNamespace(_tools={"rogue": fake_tool}))
    with pytest.raises(RuntimeError, match="rogue"):
        apply_risk_annotations(fake)


def test_meta_key_is_the_published_contract():
    # Clients match on this literal; it must be a valid, non-reserved _meta key.
    assert RISK_META_KEY == "io.github.AIops-tools/riskLevel"
    prefix, name = RISK_META_KEY.split("/")
    label = re.compile(r"^[A-Za-z]([A-Za-z0-9-]*[A-Za-z0-9])?$")
    labels = prefix.split(".")
    assert all(label.match(part) for part in labels)
    assert not {"mcp", "modelcontextprotocol"} & {part.lower() for part in labels}
    assert re.match(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$", name)


def test_existing_meta_survives_on_a_real_tool():
    fresh = MCPServer("annotations-test")

    def probe() -> str:
        return "ok"

    probe._risk_level = "medium"
    probe._idempotent = True
    fresh.tool(meta={"x": 1})(probe)
    apply_risk_annotations(fresh)

    (listed_tool,) = asyncio.run(fresh.list_tools())
    assert listed_tool.meta == {"x": 1, RISK_META_KEY: "medium"}
    assert listed_tool.annotations.destructive_hint is True
    assert listed_tool.annotations.idempotent_hint is True
    assert fresh._tool_manager._tools["probe"].fn is probe
