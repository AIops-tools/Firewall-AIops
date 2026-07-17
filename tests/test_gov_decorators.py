"""Governance harness — @governed_tool decorator coverage.

Portable across the whole tool line: references ONLY
``firewall_aiops.governance.*`` and binds state to an isolated home via
``FIREWALL_AIOPS_HOME``. Every governed function under test is SYNTHETIC and
defined inline — no real ops / cli / connection / mcp_server tool is imported.

Exercises the async wrapper (audit parity with sync), the error-capture path
with secret redaction, BudgetExceeded + PolicyDenied propagation, positional /
var-arg binding, sensitive-param redaction (nested), undo recording + failure
tolerance, pattern arming + circuit-breaker bookkeeping, the timeout advisory,
and the sanitized-error → status=error rule.

Because these functions live in the test module, ``_infer_skill`` classifies
them as skill ``"unknown"`` — patterns under test therefore target that skill,
which keeps the file identical across every tool.
"""

from __future__ import annotations

import asyncio
import sqlite3
import types

import pytest

import firewall_aiops.governance.audit as audit_mod
import firewall_aiops.governance.budget as budget_mod
import firewall_aiops.governance.decorators as dec_mod
import firewall_aiops.governance.patterns as patterns_mod
import firewall_aiops.governance.policy as policy_mod
import firewall_aiops.governance.undo as undo_mod
from firewall_aiops.governance import PolicyDenied, governed_tool
from firewall_aiops.governance.budget import BudgetExceeded


def _reset() -> None:
    audit_mod.reset_engine()
    policy_mod.reset_policy_engine()
    undo_mod.reset_undo_store()
    budget_mod.reset_budget()
    patterns_mod.reset_pattern_engine()


@pytest.fixture
def dec_home(tmp_path, monkeypatch):
    monkeypatch.setenv("FIREWALL_AIOPS_HOME", str(tmp_path))
    monkeypatch.setenv("FIREWALL_AUDIT_APPROVED_BY", "pytest")
    monkeypatch.delenv("FIREWALL_POLICY_DISABLED", raising=False)
    monkeypatch.delenv("FIREWALL_MAX_TOOL_CALLS", raising=False)
    monkeypatch.delenv("FIREWALL_MAX_TOOL_SECONDS", raising=False)
    _reset()
    yield tmp_path
    _reset()


def _audit_rows(home):
    conn = sqlite3.connect(home / "audit.db")
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id")]
    finally:
        conn.close()


_ARMABLE_PATTERN = """\
schema_version: 1
pattern_id: {pid}
classification:
  risk: low
  reversible: true
  repeatable: true
action:
  skill: unknown
  tool: {tool}
approval:
  status: approved
  signed_by: dba-alice
"""


def _install_pattern(home, tool, pid="pat1"):
    d = home / "auto-remediation-patterns"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{pid}.yaml").write_text(_ARMABLE_PATTERN.format(pid=pid, tool=tool), "utf-8")


# ── Sync happy path + bare decorator ───────────────────────────────────


@pytest.mark.unit
def test_bare_decorator_without_parens(dec_home):
    @governed_tool
    def _bare_op(value: str = "x") -> dict:
        return {"ok": True}

    assert _bare_op._is_governed_tool is True
    assert _bare_op(value="a")["ok"] is True
    rows = _audit_rows(dec_home)
    assert rows[-1]["tool"] == "_bare_op"
    assert rows[-1]["status"] == "ok"


@pytest.mark.unit
def test_positional_args_bound_into_params(dec_home):
    @governed_tool(risk_level="low")
    def _pos_op(name: str, target: str = "") -> dict:
        return {"ok": True}

    _pos_op("idx1", "prod-db")  # both positional
    row = _audit_rows(dec_home)[-1]
    import json

    params = json.loads(row["params"])
    assert params["name"] == "idx1"
    assert params["target"] == "prod-db"


@pytest.mark.unit
def test_var_keyword_and_var_positional_binding(dec_home):
    @governed_tool
    def _vk_op(name: str, *extra: str, **rest: str) -> dict:
        return {"ok": True}

    _vk_op("n", "e1", "e2", foo="bar")
    import json

    params = json.loads(_audit_rows(dec_home)[-1]["params"])
    assert params["name"] == "n"
    assert params["extra"] == ["e1", "e2"]
    assert params["foo"] == "bar"


@pytest.mark.unit
def test_bind_fallback_on_binding_error(dec_home):
    @governed_tool
    def _one(x: str) -> dict:
        return {"ok": True}

    # Passing x both positionally and by keyword makes signature.bind_partial
    # raise, exercising the kwargs-only fallback; the real call raises TypeError.
    with pytest.raises(TypeError):
        _one("a", x="b")
    # The call was still audited (as an error).
    assert _audit_rows(dec_home)[-1]["tool"] == "_one"
    assert _audit_rows(dec_home)[-1]["status"] == "error"


# ── Async wrapper parity ───────────────────────────────────────────────


@pytest.mark.unit
def test_async_wrapper_audits_like_sync(dec_home):
    @governed_tool(
        risk_level="low",
        undo=lambda p, r: {"tool": "inverse", "params": {"n": p["name"]}},
    )
    async def _async_op(name: str, target: str = "") -> dict:
        await asyncio.sleep(0)
        return {"status": "done"}

    result = asyncio.run(_async_op(name="w1", target="db"))
    assert result["status"] == "done"
    assert result.get("_undo_id")  # undo recorded on the async success path

    rows = _audit_rows(dec_home)
    assert rows[-1]["tool"] == "_async_op"
    assert rows[-1]["status"] == "ok"

    undo_conn = sqlite3.connect(dec_home / "undo.db")
    try:
        n = undo_conn.execute("SELECT COUNT(*) FROM undo_log").fetchone()[0]
    finally:
        undo_conn.close()
    assert n == 1


@pytest.mark.unit
def test_async_wrapper_error_path(dec_home):
    @governed_tool
    async def _async_boom(target: str = "") -> dict:
        raise RuntimeError("async failure")

    with pytest.raises(RuntimeError):
        asyncio.run(_async_boom(target="db"))
    row = _audit_rows(dec_home)[-1]
    assert row["tool"] == "_async_boom"
    assert row["status"] == "error"


# ── Error capture + secret redaction ───────────────────────────────────


@pytest.mark.unit
def test_error_capture_redacts_secrets(dec_home):
    @governed_tool
    def _leaky(target: str = "") -> dict:
        raise ValueError("connect failed password=hunter2 host=db")

    with pytest.raises(ValueError):
        _leaky(target="db")
    row = _audit_rows(dec_home)[-1]
    assert row["status"] == "error"
    import json

    result = json.loads(row["result"])
    assert "hunter2" not in result["error"]
    assert "password" in result["error"]
    assert "***" in result["error"]
    assert "traceback" in result


@pytest.mark.unit
def test_sanitized_error_result_marked_error(dec_home):
    @governed_tool(undo=lambda p, r: {"tool": "inverse", "params": {}})
    def _soft_fail(target: str = "") -> dict:
        return {"error": "upstream sanitized this"}

    result = _soft_fail(target="db")
    assert "_undo_id" not in result  # no undo for a no-op failure
    row = _audit_rows(dec_home)[-1]
    assert row["status"] == "error"


# ── Budget + policy denial propagation ─────────────────────────────────


@pytest.mark.unit
def test_budget_exceeded_propagates_and_audits(dec_home, monkeypatch):
    monkeypatch.setenv("FIREWALL_MAX_TOOL_CALLS", "0")

    @governed_tool
    def _budgeted(target: str = "") -> dict:
        return {"ok": True}

    with pytest.raises(BudgetExceeded):
        _budgeted(target="db")
    row = _audit_rows(dec_home)[-1]
    assert row["status"] == "budget_exceeded"


@pytest.mark.unit
def test_policy_denied_propagates_and_audits(dec_home):
    (dec_home / "rules.yaml").write_text(
        "deny:\n  - name: block_drops\n    operations: ['_drop_*']\n", "utf-8"
    )
    _reset()

    @governed_tool
    def _drop_thing(target: str = "") -> dict:
        return {"ok": True}

    with pytest.raises(PolicyDenied):
        _drop_thing(target="db")
    row = _audit_rows(dec_home)[-1]
    assert row["status"] == "denied"
    assert row["tool"] == "_drop_thing"


# ── Sensitive param redaction (nested) ─────────────────────────────────


@pytest.mark.unit
def test_sensitive_params_redacted_nested(dec_home):
    @governed_tool(sensitive_params=["password"])
    def _connect_op(password: str = "", targets: list | None = None, target: str = "") -> dict:
        return {"ok": True}

    _connect_op(
        password="topsecret",
        targets=[{"password": "nested-secret", "host": "h1"}],
        target="db",
    )
    import json

    params = json.loads(_audit_rows(dec_home)[-1]["params"])
    assert params["password"] == "***"
    assert params["targets"][0]["password"] == "***"
    assert params["targets"][0]["host"] == "h1"


# ── Undo tolerance ─────────────────────────────────────────────────────


@pytest.mark.unit
def test_undo_callable_raising_does_not_fail_call(dec_home):
    def _bad_undo(p, r):
        raise ValueError("undo blew up")

    @governed_tool(undo=_bad_undo)
    def _op(target: str = "") -> dict:
        return {"ok": True}

    result = _op(target="db")
    assert result["ok"] is True
    assert "_undo_id" not in result
    assert _audit_rows(dec_home)[-1]["status"] == "ok"


@pytest.mark.unit
def test_undo_store_failure_does_not_fail_call(dec_home, monkeypatch):
    class _BadStore:
        def record(self, *_a, **_k):
            raise RuntimeError("store down")

    monkeypatch.setattr(undo_mod, "get_undo_store", lambda: _BadStore())

    @governed_tool(undo=lambda p, r: {"tool": "inverse", "params": {}})
    def _op(target: str = "") -> dict:
        return {"ok": True}

    result = _op(target="db")
    assert result["ok"] is True
    assert "_undo_id" not in result


# ── Pattern arming + circuit-breaker bookkeeping ───────────────────────


@pytest.mark.unit
def test_armed_pattern_annotates_result_and_reports_outcome(dec_home):
    _install_pattern(dec_home, tool="_armed_op")
    _reset()

    @governed_tool
    def _armed_op(target: str = "") -> dict:
        return {"status": "ok"}

    result = _armed_op(target="db1")
    assert result["_pattern_armed"] is True
    assert result["_pattern_id"] == "pat1"

    # _finalize reported a success outcome → failure counter stays 0.
    eng = patterns_mod.get_pattern_engine()
    assert eng._counters[("pat1", "db1")].consecutive_failures == 0

    row = _audit_rows(dec_home)[-1]
    import json

    assert json.loads(row["result"])["_pattern_id"] == "pat1"


@pytest.mark.unit
def test_armed_pattern_failure_increments_breaker(dec_home):
    _install_pattern(dec_home, tool="_armed_boom")
    _reset()

    @governed_tool
    def _armed_boom(target: str = "") -> dict:
        raise RuntimeError("kaboom")

    with pytest.raises(RuntimeError):
        _armed_boom(target="db1")
    eng = patterns_mod.get_pattern_engine()
    assert eng._counters[("pat1", "db1")].consecutive_failures == 1


@pytest.mark.unit
def test_pattern_context_on_non_dict_result(dec_home):
    _install_pattern(dec_home, tool="_armed_list")
    _reset()

    @governed_tool
    def _armed_list(target: str = "") -> list:
        return ["a", "b"]

    result = _armed_list(target="db1")
    # Non-dict result is returned unchanged (no pattern keys can attach).
    assert result == ["a", "b"]
    # But the pattern still matched and was recorded to the audit trail.
    row = _audit_rows(dec_home)[-1]
    assert row["tool"] == "_armed_list"
    assert row["status"] == "ok"


@pytest.mark.unit
def test_pattern_engine_failure_is_fail_open(dec_home, monkeypatch):
    class _Raiser:
        def match(self, **_k):
            raise RuntimeError("pattern engine broken")

    monkeypatch.setattr(dec_mod, "get_pattern_engine", lambda: _Raiser())

    @governed_tool
    def _op(target: str = "") -> dict:
        return {"ok": True}

    # A broken pattern engine must not block the call.
    assert _op(target="db")["ok"] is True
    assert _audit_rows(dec_home)[-1]["status"] == "ok"


# ── Timeout advisory + duration bookkeeping tolerance ──────────────────


@pytest.mark.unit
def test_timeout_advisory_warns(dec_home, caplog):
    # Fake the module clock so the measured duration exceeds timeout_seconds
    # without an actual slow call. Order of time.time() calls: start, finalize
    # duration, finalize add_duration.
    seq = iter([0.0, 5.0, 5.0])
    monkeypatch_time = types.SimpleNamespace(time=lambda: next(seq))
    orig = dec_mod.time
    dec_mod.time = monkeypatch_time
    try:

        @governed_tool(timeout_seconds=1)
        def _slow(target: str = "") -> dict:
            return {"ok": True}

        with caplog.at_level("WARNING"):
            _slow(target="db")
    finally:
        dec_mod.time = orig

    assert any("exceeded timeout_seconds" in r.message for r in caplog.records)
    assert _audit_rows(dec_home)[-1]["duration_ms"] == 5000


@pytest.mark.unit
def test_add_duration_failure_does_not_fail_call(dec_home, monkeypatch):
    class _BadBudget:
        def check_and_record(self, *_a, **_k):
            return None

        def add_duration(self, *_a, **_k):
            raise RuntimeError("bookkeeping down")

    monkeypatch.setattr(dec_mod, "get_budget", lambda: _BadBudget())

    @governed_tool
    def _op(target: str = "") -> dict:
        return {"ok": True}

    assert _op(target="db")["ok"] is True
    assert _audit_rows(dec_home)[-1]["status"] == "ok"


# ── policy_disabled bypass status suffix ───────────────────────────────


@pytest.mark.unit
def test_policy_disabled_marks_status_bypassed(dec_home, monkeypatch):
    monkeypatch.setenv("FIREWALL_POLICY_DISABLED", "1")
    _reset()

    @governed_tool(risk_level="high")
    def _op(target: str = "") -> dict:
        return {"ok": True}

    _op(target="db")
    assert _audit_rows(dec_home)[-1]["status"] == "ok_bypassed"
