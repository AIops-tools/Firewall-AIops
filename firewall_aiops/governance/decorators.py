"""The ``@governed_tool`` decorator — mandatory wrapper for all container-host MCP tool functions.

Responsibilities:
  1. Pre-check: tag the risk tier for audit + run the runaway/budget safety guard
     (no authorization — the skill does not decide read vs write)
  2. Execute: run the actual tool function
  3. Post-log: write audit record to ``~/.firewall-aiops/audit.db``
  4. Metadata: attach risk_level, idempotent, timeout, sensitive_params

Usage::

    from firewall_aiops.governance import governed_tool

    @governed_tool(risk_level="high", sensitive_params=["password"])
    def delete_segment(name: str, env: str) -> dict:
        ...

Registration enforcement::

    # In your MCP server startup
    for tool in tools:
        assert getattr(tool, "_is_governed_tool", False), f"{tool.__name__} missing @governed_tool"
"""

from __future__ import annotations

import inspect
import logging
import os
import re
import time
import traceback
from functools import wraps
from typing import Any

from firewall_aiops.governance.audit import detect_agent, get_engine
from firewall_aiops.governance.budget import BudgetExceeded, get_budget
from firewall_aiops.governance.outcome import (
    clear_prior_state,
    is_unknown,
    take_prior_state,
)
from firewall_aiops.governance.patterns import PatternMatch, get_pattern_engine
from firewall_aiops.governance.policy import get_policy_engine
from firewall_aiops.governance.sanitize import sanitize

_log = logging.getLogger("firewall-aiops.decorators")


class PolicyDenied(Exception):
    """Retained for backward compatibility with callers that catch it.

    The skill no longer makes authorization decisions — read-only mode, deny
    rules and the approver gate were all removed — so nothing raises this any
    more. It stays defined and caught so existing ``except PolicyDenied`` sites
    keep compiling; the live stop path is :class:`BudgetExceeded` (runaway).
    """


def governed_tool(
    fn: Any = None,
    *,
    risk_level: str = "low",
    idempotent: bool = False,
    timeout_seconds: int = 300,
    sensitive_params: list[str] | None = None,
    undo: Any = None,
) -> Any:
    """Decorator for all container-host MCP tool functions.

    Can be used with or without arguments::

        @governed_tool
        def list_segments(...): ...

        @governed_tool(risk_level="critical", sensitive_params=["password"])
        def delete_vm(...): ...

    Args:
        risk_level: One of 'low', 'medium', 'high', 'critical'.
        idempotent: Whether the operation can be safely retried on failure.
        timeout_seconds: Maximum execution time before warning — exceeding it
            logs a warning (no hard cancellation).
        sensitive_params: Parameter names to redact in audit logs.
        undo: Optional callable ``(params, result) -> dict | None`` returning an
            inverse descriptor ``{"tool", "params", "skill"?, "note"?}``. On a
            successful call the inverse is recorded to ~/.firewall-aiops/undo.db and the
            result dict gains an ``_undo_id``. Return None for "no safe inverse".
            Recording only — execution is an external orchestrator's job.
    """
    _sensitive = set(sensitive_params or [])

    def decorator(func: Any) -> Any:
        # Cache the signature at decoration time so positional args can be
        # mapped to parameter names on every call (audit + env scoping).
        signature = inspect.signature(func)

        if inspect.iscoroutinefunction(func):
            # ── Async tools get an async wrapper with identical audit /
            # policy / circuit-breaker semantics (a sync wrapper would return
            # an un-awaited coroutine and audit it as "ok").
            @wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                state = _CallState(
                    func, args, kwargs, signature, _sensitive, risk_level,
                    timeout_seconds, undo,
                )
                try:
                    _pre_check(state)
                    return _annotate_result(state, await func(*args, **kwargs))
                except (PolicyDenied, BudgetExceeded):
                    raise
                except Exception as exc:
                    _capture_error(state, exc)
                    raise
                finally:
                    _finalize(state)
        else:
            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                state = _CallState(
                    func, args, kwargs, signature, _sensitive, risk_level,
                    timeout_seconds, undo,
                )
                try:
                    _pre_check(state)
                    return _annotate_result(state, func(*args, **kwargs))
                except (PolicyDenied, BudgetExceeded):
                    raise
                except Exception as exc:
                    _capture_error(state, exc)
                    raise
                finally:
                    _finalize(state)

        # ── Attach metadata for harness / introspection ───────────
        wrapper._is_governed_tool = True
        wrapper._risk_level = risk_level
        wrapper._idempotent = idempotent
        wrapper._timeout_seconds = timeout_seconds
        wrapper._sensitive_params = list(_sensitive)
        return wrapper

    # Support @governed_tool and @governed_tool(...)
    if fn is not None:
        return decorator(fn)
    return decorator


# ── Internal helpers ──────────────────────────────────────────────────


class _CallState:
    """Per-call context shared by the sync and async wrapper bodies.

    Built once per invocation; the helper functions (`_pre_check`,
    `_annotate_result`, `_capture_error`, `_finalize`) read and mutate it so
    both wrappers keep identical audit / policy / circuit-breaker semantics.
    """

    __slots__ = (
        "skill", "tool_name", "agent", "start", "status", "result",
        "pattern_match", "audit",
        "safe_params", "env", "risk_level", "timeout_seconds",
        "rationale", "approved_by", "risk_tier", "undo", "dry_run",
    )

    def __init__(
        self,
        func: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        signature: inspect.Signature,
        sensitive: set[str],
        risk_level: str,
        timeout_seconds: int,
        undo: Any = None,
    ) -> None:
        # A previous call on this thread/task may have captured before-state
        # that its own wrapper never consumed (it raised past _annotate_result).
        # Start clean so one call's prior state can never be recorded as another's.
        clear_prior_state()
        self.undo = undo
        self.skill = _infer_skill(func)
        self.tool_name = func.__name__
        self.agent = detect_agent()
        self.start = time.time()
        self.status = "ok"
        self.result: Any = None
        self.pattern_match: PatternMatch | None = None
        self.risk_level = risk_level
        self.timeout_seconds = timeout_seconds
        self.audit = get_engine()

        # Map positional args to parameter names so they appear in the audit
        # log and participate in env scoping (previously only kwargs did).
        params = _bind_params(signature, args, kwargs)
        self.safe_params = _redact(params, sensitive)
        # Previews are governed like any other call — audited, budget-counted —
        # but they change nothing, so undo recording must not apply to them.
        self.dry_run = bool(params.get("dry_run", False))
        env = params.get("target", params.get("env", ""))
        self.env = str(env) if env else ""

        # Optional accountability context for the audit trail (SOC2 / 等保: who
        # authorized this, and why). Read from env so an operator or pilot can
        # annotate the trail without changing any tool signature. Purely
        # recorded — never required, never enforced. risk_tier is filled by the
        # pre-check as a descriptive label for the row.
        self.rationale = os.environ.get("FIREWALL_AUDIT_RATIONALE", "")
        self.approved_by = os.environ.get("FIREWALL_AUDIT_APPROVED_BY", "")
        self.risk_tier = ""


def _bind_params(
    signature: inspect.Signature, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Build a full name→value param dict from positional + keyword args.

    Falls back to kwargs-only if binding fails (the actual call will raise
    the matching TypeError; audit should not mask it with its own).
    """
    try:
        bound = signature.bind_partial(*args, **kwargs)
        # Apply declared defaults so env scoping and risk-tier matching see the
        # effective target/tags even when the caller relied on a default value
        # (bind_partial alone only captures explicitly-passed arguments).
        bound.apply_defaults()
    except TypeError:
        return dict(kwargs)
    params: dict[str, Any] = {}
    for name, value in bound.arguments.items():
        kind = signature.parameters[name].kind
        if kind == inspect.Parameter.VAR_KEYWORD:
            params.update(value)
        elif kind == inspect.Parameter.VAR_POSITIONAL:
            params[name] = list(value)
        else:
            params[name] = value
    return params


def _pre_check(state: _CallState) -> None:
    """Risk-tier tagging + runaway guard + auto-remediation pattern consult.

    Deliberately does NO authorization. Whether a read or a write is permitted
    is the agent's decision or the connecting account's permissions, not the
    skill's — read-only mode, deny rules and the approver gate were all removed.
    What happens here: the operation's risk tier is recorded for the audit
    trail, the runaway/budget guard (a safety stop, not an authz gate) is
    applied, and the pattern engine is consulted. A broken pattern file must
    never take down a tool, so that consult is fail-open.
    """
    # Descriptive label for the audit row (e.g. a high-risk delete). Gates nothing.
    state.risk_tier = get_policy_engine().tier_for(state.risk_level)

    # Runaway / budget guard — a safety backstop for a stuck loop, not an
    # authorization decision. A trip raises BudgetExceeded (a hard stop); mark
    # it on state so _finalize audits the stopped call.
    try:
        get_budget().check_and_record(state.tool_name, state.safe_params)
    except BudgetExceeded as exc:
        state.status = "budget_exceeded"
        state.result = {"error": exc.reason, "rule": exc.rule}
        raise

    try:
        state.pattern_match = get_pattern_engine().match(
            skill=state.skill, tool=state.tool_name, target=state.env
        )
    except Exception:  # noqa: BLE001 — fail-open by design
        state.pattern_match = None


def _annotate_result(state: _CallState, result: Any) -> Any:
    """Record the result, surface pattern context, and record an undo token.

    Runs on the path where the tool returned a value — which includes the
    failures ``tool_errors`` sanitized into an ``{"error": ...}`` dict. Those
    are not all alike: one whose response was merely lost may well have taken
    effect, so :func:`_record_undo` treats it separately rather than assuming
    nothing happened.
    """
    state.result = result
    if (
        state.pattern_match
        and state.pattern_match.armed
        and isinstance(result, dict)
    ):
        result.setdefault("_pattern_id", state.pattern_match.pattern.pattern_id)
        result.setdefault("_pattern_armed", True)
    _record_undo(state, result)
    return result


def _record_undo(state: _CallState, result: Any) -> None:
    """Compute and persist the inverse descriptor for a write.

    Two paths:

    * **Confirmed** — the tool returned normally, so ``result`` carries the
      before-state its undo callable needs. Recorded ``effect_verified=True``.
    * **Undetermined** — the response was lost (see
      :mod:`firewall_aiops.governance.outcome`). The change may be live,
      so an inverse still matters, but ``result`` is only an error payload. An
      inverse is recorded ONLY when the write explicitly stashed its
      before-state via ``capture_prior_state``; synthesizing one from an empty
      result would produce a *wrong* inverse, which is worse than none.

    Best-effort throughout: a broken undo callable or store must never fail the
    call. Attaches ``_undo_id`` to dict results so the caller can reference it.
    """
    if state.undo is None:
        return
    if state.dry_run:
        # A preview changed nothing, so there is nothing to invert — and the
        # descriptor it would produce is actively dangerous. An undo callable
        # reads the before-state out of the result, and a preview has none, so
        # permissive defaults (``(result.get("priorState") or {}).get("running",
        # True)``) fill the gap with a guess. That yielded a REAL, applicable
        # start_container token for a stop that never happened.
        return

    verified = True
    undo_input = result
    if is_unknown(result):
        prior = take_prior_state()
        if prior is None:
            _log.warning(
                "%s.%s outcome undetermined and no prior state captured — "
                "no inverse recorded; the change may be live and unrecorded",
                state.skill, state.tool_name,
            )
            return
        verified = False
        undo_input = {"priorState": prior, "outcomeUnknown": True}
    elif isinstance(result, dict) and result.get("error"):
        return  # definite failure — no change happened, so no inverse to record

    try:
        descriptor = state.undo(state.safe_params, undo_input)
    except Exception:  # noqa: BLE001 — undo computation must not fail the call
        _log.warning("undo callable for %s.%s raised", state.skill, state.tool_name,
                     exc_info=True)
        return
    if not descriptor:
        return
    try:
        from firewall_aiops.governance.undo import get_undo_store

        undo_id = get_undo_store().record(
            skill=state.skill,
            tool=state.tool_name,
            undo_descriptor=descriptor,
            orig_params=state.safe_params,
            effect_verified=verified,
        )
        if undo_id and isinstance(result, dict):
            result.setdefault("_undo_id", undo_id)
    except Exception:  # noqa: BLE001 — recording is best-effort
        _log.warning("failed to record undo for %s.%s", state.skill, state.tool_name,
                     exc_info=True)


def _capture_error(state: _CallState, exc: Exception) -> None:
    """Record a failed call. Exception text and tracebacks can carry
    connection strings, credentials, internal paths — sanitize before
    persisting to the audit row."""
    state.status = "error"
    state.result = {
        "error": sanitize(_redact_secrets_text(str(exc)), 500),
        "traceback": sanitize(
            _redact_secrets_text(traceback.format_exc()[-500:]), 500
        ),
    }


def _finalize(state: _CallState) -> None:
    """Audit + circuit-breaker bookkeeping. Runs in the wrapper's finally."""
    # A sanitized failure (@tool_errors converts exceptions into {"error": ...}
    # dicts BEFORE this harness sees them) must not be audited as success —
    # compliance exception reports are built from this status. 'unknown' is a
    # distinct verdict, not a softer 'error': the request may have taken effect,
    # so the row must not assert a failure the tool cannot actually vouch for.
    if state.status == "ok" and isinstance(state.result, dict) and state.result.get("error"):
        state.status = "unknown" if is_unknown(state.result) else "error"

    duration = int((time.time() - state.start) * 1000)

    # Accumulate wall-time toward the cumulative time budget (best-effort).
    try:
        get_budget().add_duration(time.time() - state.start)
    except Exception:  # noqa: BLE001 — bookkeeping must never fail the call
        pass

    # timeout_seconds is advisory: exceeding it logs a warning, no hard
    # cancellation (cancelling mid-flight container-host calls is worse).
    if state.timeout_seconds and duration > state.timeout_seconds * 1000:
        _log.warning(
            "%s.%s took %dms — exceeded timeout_seconds=%d (advisory, not cancelled)",
            state.skill, state.tool_name, duration, state.timeout_seconds,
        )

    final_status = state.status

    # Update circuit-breaker state for armed patterns
    if state.pattern_match and state.pattern_match.armed:
        try:
            get_pattern_engine().report_outcome(
                pattern_id=state.pattern_match.pattern.pattern_id,
                target=state.env,
                success=(state.status == "ok"),
            )
        except Exception:  # noqa: BLE001 — never let bookkeeping fail the call
            pass

    pattern_id = state.pattern_match.pattern.pattern_id if state.pattern_match else ""
    pattern_armed = bool(state.pattern_match and state.pattern_match.armed)

    state.audit.log(
        skill=state.skill,
        tool=state.tool_name,
        params=state.safe_params,
        result=_with_pattern_context(state.result, pattern_id, pattern_armed),
        status=final_status,
        duration_ms=duration,
        agent=state.agent,
        user="",
        risk_level=state.risk_level,
        rationale=state.rationale,
        approved_by=state.approved_by,
        risk_tier=state.risk_tier,
    )


def _infer_skill(func: Any) -> str:
    """Infer the skill name from the function's module path.

    ``firewall_aiops.ops.jobs`` → ``firewall-aiops``
    ``mcp_server.server`` → ``firewall-aiops`` (the only consumer here).
    """
    module = getattr(func, "__module__", "") or ""
    if module.startswith("firewall_aiops") or module.startswith("mcp_server"):
        return "firewall-aiops"
    return "unknown"


def _redact(params: dict[str, Any], sensitive: set[str]) -> dict[str, Any]:
    """Return a copy of params with sensitive values replaced by '***'.

    Recurses into nested dicts AND lists/tuples so credentials buried inside
    collections (e.g. ``{"targets": [{"password": "x"}]}``) are redacted too.
    """
    if not sensitive:
        return params
    result: dict[str, Any] = {}
    for k, v in params.items():
        if k in sensitive:
            result[k] = "***"
        else:
            result[k] = _redact_value(v, sensitive)
    return result


def _redact_value(value: Any, sensitive: set[str]) -> Any:
    """Recursively redact sensitive keys inside dicts, lists, and tuples."""
    if isinstance(value, dict):
        return _redact(value, sensitive)
    if isinstance(value, (list, tuple)):
        return type(value)(_redact_value(item, sensitive) for item in value)
    return value


# Matches ``key=value`` / ``key: value`` / ``key"="value`` for common secret
# keys in free-form exception text. Value runs until whitespace, quote, comma,
# or '@' (to keep host:port that often follows a credential in DSNs).
_SECRET_TEXT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|authorization|bearer)"
    r"(\s*[=:]\s*|\s+)"
    r"['\"]?[^\s'\",@]+",
)


def _redact_secrets_text(text: str) -> str:
    """Redact ``password=...`` / ``token: ...`` style secrets in free-form text."""
    return _SECRET_TEXT_RE.sub(r"\1\2***", text)


def _with_pattern_context(result: Any, pattern_id: str, armed: bool) -> Any:
    """Attach pattern metadata to an audit row's result field.

    Only mutates dict results; non-dict results (errors, primitives) are
    returned unchanged so the audit log preserves them faithfully.
    """
    if not pattern_id:
        return result
    if isinstance(result, dict):
        annotated = dict(result)
        annotated.setdefault("_pattern_id", pattern_id)
        annotated.setdefault("_pattern_armed", armed)
        return annotated
    return result
