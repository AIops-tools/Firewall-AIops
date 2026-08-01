"""Shared helpers for the firewall ops modules.

OPNsense and pfSense return the same firewall concepts under different JSON
field names (e.g. a rule's enabled state is OPNsense ``enabled`` ``"1"/"0"`` vs
pfSense ``disabled`` boolean). The ops modules stay platform-neutral by asking
the platform for paths/rows (see :mod:`firewall_aiops.platform`) and by reading
fields through :func:`pick` / :func:`pick_bool`, which try a list of candidate
keys. All firewall text reaches the caller only after ``sanitize()`` via ``s``.
"""

from __future__ import annotations

from typing import Any

from firewall_aiops.governance import opt_str, sanitize


def as_obj(data: Any) -> dict:
    """Return ``data`` as a dict (empty dict if it isn't one)."""
    return data if isinstance(data, dict) else {}


def s(value: Any, limit: int = 256) -> str:
    """Sanitize an arbitrary value to a bounded, injection-safe string."""
    return sanitize(str(value if value is not None else ""), limit)


def opt(value: Any, limit: int = 256) -> str | None:
    """Sanitize an *optional* field, preserving the difference between absent and empty.

    Companion to :func:`s`, which folds ``None`` into ``""``. Firewall rows are
    read through :func:`pick`, which returns ``None`` when none of the candidate
    keys were present — that is a different fact from the field being present
    and blank, and collapsing the two hides it from the caller. Use this for
    anything read via :func:`pick`; keep :func:`s` for values that always exist
    (an exception message, a caller-supplied UUID).
    """
    return opt_str(value, limit)


def pick(row: dict, *keys: str, default: Any = None) -> Any:
    """Return the first present, non-None value among ``keys`` (else ``default``)."""
    for key in keys:
        if key in row and row[key] is not None:
            return row[key]
    return default


_TRUE = {"1", "true", "yes", "on", "enabled", "up", "active"}
_FALSE = {"0", "false", "no", "off", "disabled", "down", "", "none"}


def to_bool(value: Any) -> bool:
    """Coerce a firewall truthy/falsy cell (``"1"``, ``true``, ``"yes"``) to bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return bool(text)


def rule_enabled(row: dict) -> bool:
    """Read a rule's effective enabled state across both platforms.

    OPNsense exposes ``enabled`` (``"1"``/``"0"``); pfSense exposes ``disabled``
    (a boolean/flag). ``enabled`` wins when present, otherwise the inverse of
    ``disabled`` is used.
    """
    if "enabled" in row and row["enabled"] is not None:
        return to_bool(row["enabled"])
    if "disabled" in row and row["disabled"] is not None:
        return not to_bool(row["disabled"])
    return True


def num(value: Any) -> float:
    """Coerce a numeric cell to float; 0.0 when absent/non-numeric.

    Use only for genuine fractions/ratios/percentages. For counts, byte totals
    and whole-second durations use :func:`as_int` — a count rendered as ``0.0``
    is semantically wrong and equality assertions won't catch it (bug class #2).
    """
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def as_int(value: Any) -> int:
    """Coerce a count/byte value to int; 0 when absent/non-numeric.

    Companion to :func:`num` for integral quantities (rule evaluations, packet
    and byte counters) so they never render as ``202.0``.
    """
    if isinstance(value, bool):
        return 0
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0
