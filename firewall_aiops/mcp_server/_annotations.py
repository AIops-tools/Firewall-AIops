"""Derive MCP tool annotations from the governance risk level.

Every tool already declares ``risk_level`` on ``@governed_tool``; this module
publishes it to MCP clients as the standard ``ToolAnnotations`` hints plus the
exact level under ``_meta``, so a client can gate approval without reading our
docstrings.

Only the safe direction is ever asserted:

- ``low`` → ``readOnlyHint: true``. Backed by the smoke-test invariant that
  ``risk_level == "low"`` exactly when the docstring says ``[READ]``.
- anything else → ``readOnlyHint: false, destructiveHint: true``. The
  ``medium`` tier is NOT non-destructive — it holds deletes, hard power-offs,
  state kills and stat resets — so claiming ``destructiveHint: false`` from the
  tier would tell a client it may skip approval for a delete. Over-warning
  costs a confirmation prompt; under-warning costs data.
- ``idempotentHint`` only echoes an explicit ``@governed_tool(idempotent=True)``
  declaration; it is never inferred.
- ``openWorldHint`` is left unset (spec default ``true``): every tool talks to
  an external system.

This file is identical across the AIops line; keep it that way.
"""

from typing import Any

from mcp.types import ToolAnnotations

RISK_META_KEY = "io.github.AIops-tools/riskLevel"
RISK_LEVELS = frozenset({"low", "medium", "high", "critical"})


def annotations_for(risk_level: str, idempotent: bool) -> ToolAnnotations:
    """Return the MCP hints that a tool of ``risk_level`` may honestly claim."""
    if risk_level not in RISK_LEVELS:
        raise ValueError(
            f"unknown risk_level {risk_level!r}; expected one of {sorted(RISK_LEVELS)}"
        )
    if risk_level == "low":
        return ToolAnnotations(read_only_hint=True)
    return ToolAnnotations(
        read_only_hint=False,
        destructive_hint=True,
        idempotent_hint=idempotent,
    )


def apply_risk_annotations(server: Any) -> None:
    """Replace every registered tool with a copy carrying its risk annotations.

    Fails fast on a tool without ``@governed_tool`` metadata: an unannotated
    tool would be advertised with the spec defaults, i.e. as a destructive
    write with no stated risk level — wrong for a read, silent for a write.
    """
    tools = server._tool_manager._tools  # same private registry undo.py relies on
    for name, tool in list(tools.items()):
        risk_level = getattr(tool.fn, "_risk_level", None)
        if risk_level is None:
            raise RuntimeError(f"tool {name!r} has no @governed_tool risk_level")
        idempotent = bool(getattr(tool.fn, "_idempotent", False))
        tools[name] = tool.model_copy(
            update={
                "annotations": annotations_for(risk_level, idempotent),
                "meta": {**(tool.meta or {}), RISK_META_KEY: risk_level},
            }
        )
