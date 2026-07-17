"""MCP server wrapping firewall-aiops operations (stdio transport).

Thin adapter layer: each ``@mcp.tool()`` function (in ``mcp_server/tools/``)
delegates to the ``firewall_aiops`` ops package and is wrapped with the
firewall-aiops ``@governed_tool`` harness (audit / budget / undo / risk-tier).

Standalone, self-governed firewall operations (preview) over OPNsense and
pfSense: system/rules/nat/aliases/vpn/dhcp/diagnostics reads, three flagship
analyses, and governed writes (rule toggle, alias entries, apply/reconfigure,
kill-states, service restart, reboot).

Source: https://github.com/AIops-tools/Firewall-AIops
License: MIT
"""

import logging

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

__all__ = ["mcp", "main", "_safe_error", "tool_errors"]


def main() -> None:
    """Run the MCP server over stdio."""
    logging.basicConfig(level=logging.INFO)
    mcp.run(transport="stdio")
