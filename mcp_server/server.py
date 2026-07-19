"""MCP server wrapping firewall-aiops operations (stdio transport).

Thin adapter layer: each ``@mcp.tool()`` function (in ``mcp_server/tools/``)
delegates to the ``firewall_aiops`` ops package and is wrapped with the
firewall-aiops ``@governed_tool`` harness (audit / budget / undo / risk-tier).

Standalone, self-governed firewall operations over OPNsense and
pfSense: system/rules/nat/aliases/vpn/dhcp/diagnostics reads, three flagship
analyses, and governed writes (rule toggle, alias entries, apply/reconfigure,
kill-states, service restart, reboot).

Source: https://github.com/AIops-tools/Firewall-AIops
License: MIT
"""

import logging

from firewall_aiops.governance import READ_ONLY_ENV, is_read_only
from mcp_server._shared import _safe_error, mcp, tool_errors

# Importing the tool modules registers every @mcp.tool() onto the shared
# `mcp` instance. Order does not matter; each module is self-contained.
from mcp_server.tools import (  # noqa: F401 — side effects
    aliases,
    analysis,
    dhcp,
    diag,
    nat,
    rules,
    system,
    undo,
    vpn,
    writes,
)

__all__ = ["mcp", "main", "_safe_error", "tool_errors", "apply_read_only"]

logger = logging.getLogger(__name__)


def apply_read_only() -> list[str]:
    """Unregister every write tool when read-only mode is on.

    The ``@governed_tool`` harness already refuses writes in this mode, so this
    is a second layer — and the one that matters for smaller local models:
    a tool absent from ``list_tools()`` cannot be hallucinated into a call,
    whereas a tool that exists but refuses invites retry loops. It also gives a
    compliance reviewer something checkable — the write tools are simply not
    exposed.

    ``risk_level == "low"`` is the read/write discriminator; a smoke test
    asserts it stays in agreement with each tool's ``[READ]``/``[WRITE]``
    docstring tag so the two can never drift apart silently.

    Returns the names that were removed (empty when not in read-only mode).
    """
    if not is_read_only():
        return []
    registry = mcp._tool_manager._tools
    dropped = [
        name
        for name, tool in registry.items()
        if getattr(getattr(tool, "fn", None), "_risk_level", "low") != "low"
    ]
    for name in dropped:
        del registry[name]
    if dropped:
        logger.info(
            "%s is set — read-only mode: %d write tool(s) not exposed",
            READ_ONLY_ENV, len(dropped),
        )
    return dropped


def main() -> None:
    """Run the MCP server over stdio."""
    logging.basicConfig(level=logging.INFO)
    apply_read_only()
    mcp.run(transport="stdio")
