"""Undo executor — list recorded inverse descriptors and APPLY them.

Every governed write records a replayable inverse descriptor (tool + params) to
``undo.db``. This module closes the loop: ``undo_apply`` looks up a recorded
descriptor and dispatches it to the named governed tool, so the inverse runs on
the SAME governance path as any other call (audited, budget-checked, and — if
the inverse itself is destructive — re-gated by its own risk tier / approver
requirement). ``undo_apply`` is itself governed; the real risk is enforced by
the inner tool it calls.

Note: recorded ``undo_params`` are the redacted safe-params captured at record
time, so an inverse that would need a secret value cannot be replayed here — by
design, inverses in this line key off ids/names, not credentials.
"""

import json
from typing import Any, Optional

from firewall_aiops.governance import governed_tool
from firewall_aiops.governance.undo import get_undo_store
from mcp_server._shared import mcp, tool_errors


def _resolve_tool(name: str) -> Any:
    """Return the governed callable registered under ``name`` (or None)."""
    tool = mcp._tool_manager._tools.get(name)
    return getattr(tool, "fn", None) if tool else None


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def undo_list(limit: int = 50, target: Optional[str] = None) -> dict:
    """[READ] List recorded, not-yet-applied undo tokens (most recent first).

    Each entry names the original tool, the inverse tool that ``undo_apply``
    would run, and a human note. Use the ``undoId`` with ``undo_apply``.

    Returns {"undos": [...], "returned": N, "limit": L, "truncated": bool}.
    ``truncated`` is *measured* (one extra row is fetched), not guessed from a
    length coincidence: when it is true there are MORE tokens than shown, so
    re-run with a higher ``limit`` rather than reporting the list as complete.

    Each entry carries ``effectVerified``. False means the original write lost
    its response, so the change it reverses is PROBABLE, not confirmed — check
    the live state before applying, and do not report the result as a restore
    of a state that may never have been reached.

    Args:
        limit: Max rows to return (default 50, capped at 500).
        target: Unused (undo state is host-local); accepted for CLI uniformity.
    """
    requested = max(1, min(limit, 500))
    raw = get_undo_store().list(status="recorded", limit=requested + 1)
    truncated = len(raw) > requested
    rows = raw[:requested]
    return {
        "count": len(rows),
        "returned": len(rows),
        "limit": requested,
        "truncated": truncated,
        "undos": [
            {
                "undoId": r["undo_id"],
                "ts": r["ts"],
                "originalTool": r["tool"],
                "inverseTool": r["undo_tool"],
                "note": r.get("note", ""),
                "effectVerified": bool(r.get("effect_verified", 1)),
            }
            for r in rows
        ],
    }


@mcp.tool()
@governed_tool(risk_level="medium")
@tool_errors("dict")
def undo_apply(undo_id: str, dry_run: bool = False, target: Optional[str] = None) -> dict:
    """[WRITE][risk=medium] Apply a recorded undo by dispatching its inverse tool.

    The inverse runs through its own governed tool, so its real risk tier and
    any approver requirement are enforced there. Pass dry_run=True to preview
    the inverse call without executing it. A token can only be applied once.

    Args:
        undo_id: The undoId from undo_list (or an ``_undo_id`` in a write result).
        dry_run: If True, preview the inverse tool + params without running it.
        target: Passed through to the inverse tool when it accepts a target.
    """
    store = get_undo_store()
    rec = store.get(undo_id)
    if not rec:
        raise ValueError(f"Unknown undo id '{undo_id}'. Run undo_list to see available tokens.")
    if rec["status"] != "recorded":
        raise ValueError(
            f"Undo '{undo_id}' is already '{rec['status']}' — a token can only be applied once."
        )

    inverse_tool = rec["undo_tool"]
    try:
        params = json.loads(rec["undo_params"]) if rec["undo_params"] else {}
    except (ValueError, TypeError):
        params = {}
    if not isinstance(params, dict):
        params = {}

    fn = _resolve_tool(inverse_tool)
    if fn is None:
        raise ValueError(
            f"Inverse tool '{inverse_tool}' is not registered on this server; cannot apply."
        )

    effect_verified = bool(rec.get("effect_verified", 1))
    if dry_run:
        return {
            "dryRun": True,
            "undoId": undo_id,
            "effectVerified": effect_verified,
            "wouldApply": {"tool": inverse_tool, "params": params},
        }

    call_params = dict(params)
    if target is not None and "target" not in call_params:
        call_params["target"] = target
    result = fn(**call_params)

    # Only mark applied when the inverse did not itself return an error dict.
    if not (isinstance(result, dict) and result.get("error")):
        store.mark(undo_id, "applied")
        applied = True
    else:
        applied = False

    return {
        "undoId": undo_id,
        "applied": applied,
        "effectVerified": effect_verified,
        "inverseTool": inverse_tool,
        "result": result,
        "note": (
            ""
            if effect_verified
            else "The original write lost its response, so it was never confirmed "
            "to have taken effect. This inverse ran regardless; report the "
            "CURRENT server state, not a restore that may have had nothing "
            "to restore."
        ),
    }
