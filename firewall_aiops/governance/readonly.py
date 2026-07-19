"""Read-only mode — a hard switch that removes every write capability.

Set ``FIREWALL_READ_ONLY=1`` (or ``true``/``yes``/``on``) and this tool can only
read. Enforcement is deliberately two-layered:

  1. :func:`~firewall_aiops.governance.decorators.governed_tool` refuses any
     non-``low`` risk call. This covers **every** caller — MCP, the CLI, and
     in-process use — so the switch cannot be sidestepped by changing entry point.
  2. The MCP server *unregisters* write tools, so they never appear in
     ``list_tools()`` at all.

The second layer is what matters for smaller local models. A tool that is absent
cannot be hallucinated into a call; a tool that exists but refuses invites retry
loops and "I'll describe the call instead" behaviour. It is also stronger
evidence for a compliance reviewer: "the write tools are not exposed" beats
"the write tools promise to refuse".

Why an environment variable rather than config: an MCP client launches the
server as a subprocess and can set env directly, with no file to mount or path
to agree on. It is also the form an operator can apply per-invocation.
"""

from __future__ import annotations

import os

#: Environment variable that turns read-only mode on.
READ_ONLY_ENV = "FIREWALL_READ_ONLY"

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def is_read_only() -> bool:
    """True when the operator has put this tool into read-only mode.

    Read fresh from the environment on every call rather than cached at import
    time, so a test (or an embedding process) can flip it without reloading the
    module.
    """
    return os.environ.get(READ_ONLY_ENV, "").strip().lower() in _TRUTHY


def read_only_denial(tool_name: str) -> str:
    """The operator-facing reason a write was refused in read-only mode."""
    return (
        f"'{tool_name}' is a write operation, and this tool is running in "
        f"read-only mode because {READ_ONLY_ENV} is set. Unset {READ_ONLY_ENV} "
        f"to allow writes; no change was made."
    )
