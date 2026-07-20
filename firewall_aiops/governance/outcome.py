"""Tell "the write did not happen" apart from "we cannot tell whether it happened".

A governed write that loses its response is not a failed write. The request may
already have landed; the only thing that certainly failed is our knowledge of
the outcome. The harness used to collapse both into ``status='error'`` with no
undo token — and it did so precisely where the operation was most dangerous,
because the two coincide:

    a write whose target is the very thing serving this tool's API
    → the change takes effect
    → the response never comes back, because what would have sent it is gone
    → sanitized to {"error": ...} → audited as a FAILURE → no inverse recorded

The audit trail then reports that the destructive call failed while the change
is live and unrecorded. For a line whose product is "governed and reversible",
a row that confidently states the wrong outcome is worse than a missing one.

Two primitives fix that:

``mark_unknown`` / ``is_unknown``
    The MCP layer's ``tool_errors`` classifies the exception it caught. Only
    errors that leave the request's fate genuinely undetermined (a read
    timeout, a half-closed socket, a protocol error mid-response) are marked.
    A connect error or a pool timeout means the request never left, and an HTTP
    status error means the server answered — both are ordinary failures and are
    NOT marked. The distinction is per-tool knowledge, so each tool's
    ``mcp_server/_shared.py`` owns the exception tuple; this module only carries
    the marker.

``capture_prior_state`` / ``take_prior_state``
    An undo callable receives ``(params, result)``. When the write raises, the
    before-state that was read moments earlier dies with the exception and no
    inverse can be computed. A write that wants its undo to survive a lost
    response stashes the before-state *before* issuing the mutating request::

        before = conn.get(...)
        capture_prior_state({"running": before["running"]})
        conn.post(...)                      # may never return

    The harness then records the inverse even on the unknown path, flagged
    ``effect_verified=False`` so nobody mistakes it for a confirmed change.
    Opt-in by design: fabricating a descriptor from an empty result would
    produce a *wrong* inverse, which is worse than none.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any

# Public result field. Explicit rather than inferred: a caller must never have
# to guess from the error text whether the operation may have taken effect.
UNKNOWN_FIELD = "outcomeUnknown"

_UNKNOWN_NOTE = (
    "The request was sent but no usable response came back, so this operation "
    "MAY have taken effect on the server. Verify the current state before "
    "retrying — a blind retry could apply it twice."
)

# Set by a write immediately before it issues its mutating request; consumed by
# the harness. A ContextVar (not a module global) so concurrent calls and async
# tools never read each other's state.
_prior_state: ContextVar[dict[str, Any] | None] = ContextVar(
    "governed_prior_state", default=None
)


def mark_unknown(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a NEW error payload flagged as having an undetermined outcome."""
    marked = dict(payload)
    marked[UNKNOWN_FIELD] = True
    marked["note"] = _UNKNOWN_NOTE
    return marked


def is_unknown(result: Any) -> bool:
    """True when ``result`` is an error payload whose effect is undetermined."""
    return isinstance(result, dict) and result.get(UNKNOWN_FIELD) is True


def capture_prior_state(state: dict[str, Any]) -> None:
    """Stash before-state so the inverse survives a lost response.

    Call this AFTER reading the before-state and BEFORE issuing the mutating
    request. Overwrites any previously captured state for this call.
    """
    _prior_state.set(dict(state))


def take_prior_state() -> dict[str, Any] | None:
    """Consume the captured before-state (harness-internal).

    Consuming rather than peeking keeps one call's state from leaking into the
    next on a reused thread or task.
    """
    state = _prior_state.get()
    _prior_state.set(None)
    return state


def clear_prior_state() -> None:
    """Drop any captured state. Called at the start of every governed call."""
    _prior_state.set(None)
