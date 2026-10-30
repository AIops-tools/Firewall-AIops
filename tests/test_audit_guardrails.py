"""Durable write intent, private audit payloads, and safe telemetry."""

from __future__ import annotations

import asyncio
import importlib
import json
import logging
import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PKG = next(p.name for p in ROOT.iterdir() if (p / "governance/audit.py").is_file())
PREFIX = PKG.upper()
HOME_ENV = f"{PREFIX}{'' if PKG.endswith('_aiops') else '_AIOPS'}_HOME"
audit = importlib.import_module(f"{PKG}.governance.audit")
budget = importlib.import_module(f"{PKG}.governance.budget")
decorators = importlib.import_module(f"{PKG}.governance.decorators")
patterns = importlib.import_module(f"{PKG}.governance.patterns")
policy = importlib.import_module(f"{PKG}.governance.policy")
undo = importlib.import_module(f"{PKG}.governance.undo")


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv(HOME_ENV, str(tmp_path))
    monkeypatch.delenv(f"{PREFIX}_MAX_TOOL_CALLS", raising=False)
    monkeypatch.setenv("AIOPS_WORKFLOW_ID", "workflow-123")
    for module, reset_name in (
        (audit, "reset_engine"),
        (budget, "reset_budget"),
        (patterns, "reset_pattern_engine"),
        (policy, "reset_policy_engine"),
        (undo, "reset_undo_store"),
    ):
        getattr(module, reset_name)()
    yield tmp_path
    for module, reset_name in (
        (audit, "reset_engine"),
        (budget, "reset_budget"),
        (patterns, "reset_pattern_engine"),
        (policy, "reset_policy_engine"),
        (undo, "reset_undo_store"),
    ):
        getattr(module, reset_name)()


def _rows(home):
    with sqlite3.connect(home / "audit.db") as db:
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute("SELECT * FROM audit_log ORDER BY id")]


def test_write_intent_precedes_effect_and_result_is_minimized(home):
    @decorators.governed_tool(risk_level="high")
    def write() -> dict:
        row = _rows(home)[-1]
        assert row["status"] == "pending"
        assert row["workflow_id"] == "workflow-123"
        return {"secret": {"password": "sentinel-secret"}, "truncated": True, "returned": 3}

    assert write()["secret"]["password"] == "sentinel-secret"
    rows = _rows(home)
    assert len(rows) == 1
    assert rows[0]["status"] == "ok"
    assert json.loads(rows[0]["result"]) == {
        "kind": "object", "truncated": True, "returned": 3,
    }
    assert "sentinel-secret" not in rows[0]["result"]


def test_audit_outage_prevents_upstream_write(home, monkeypatch):
    engine = audit.get_engine()
    monkeypatch.setattr(
        engine, "_connect", lambda: (_ for _ in ()).throw(sqlite3.OperationalError("disk full"))
    )
    effects = []

    @decorators.governed_tool(risk_level="medium")
    def write() -> dict:
        effects.append("called")
        return {"ok": True}

    with pytest.raises(audit.AuditUnavailable, match="not started"):
        write()
    assert effects == []
    assert engine.health()["writeBlocked"] is True
    assert engine.health()["available"] is False
    assert engine.health()["auditWriteFailures"] >= 1


def test_async_write_and_preview_have_correct_intents(home):
    @decorators.governed_tool(risk_level="medium")
    async def write(dry_run: bool = False) -> dict:
        if dry_run:
            assert _rows(home) == []
        else:
            assert _rows(home)[-1]["status"] == "pending"
        return {"ok": True}

    assert asyncio.run(write(dry_run=True))["ok"] is True
    assert _rows(home)[-1]["status"] == "ok"
    assert asyncio.run(write())["ok"] is True
    assert [row["status"] for row in _rows(home)] == ["ok", "ok"]


def test_finalization_failure_leaves_recoverable_unknown(home, monkeypatch):
    engine = audit.get_engine()
    original_connect = engine._connect

    @decorators.governed_tool(risk_level="high")
    def write() -> dict:
        assert _rows(home)[-1]["status"] == "pending"
        monkeypatch.setattr(
            engine, "_connect", lambda: (_ for _ in ()).throw(sqlite3.OperationalError("disk full"))
        )
        return {"ok": True}

    with pytest.raises(audit.AuditUnavailable, match="may have completed"):
        write()
    monkeypatch.setattr(engine, "_connect", original_connect)
    assert _rows(home)[-1]["status"] == "pending"
    assert engine.health()["writeBlocked"] is True
    restarted = audit.AuditEngine(home / "audit.db")
    assert restarted.health()["pendingWrites"] == 1
    assert _rows(home)[-1]["status"] == "pending"
    assert restarted.reconcile_pending(_rows(home)[-1]["id"]) is True
    assert _rows(home)[-1]["status"] == "unknown"


def test_rotation_waits_for_pending_write(home, monkeypatch):
    engine = audit.get_engine()
    intent = engine.begin_write(skill="unknown", tool="write", risk_level="high")
    monkeypatch.setattr(audit, "_MAX_DB_SIZE_BYTES", 1)
    engine.log(skill="unknown", tool="read", risk_level="low")
    assert list(home.glob("audit.*.db")) == []
    assert _rows(home)[0]["status"] == "pending"
    engine.finish_write(intent, result={"ok": True}, status="ok", duration_ms=1)
    engine.log(skill="unknown", tool="read2", risk_level="low")
    archives = list(home.glob("audit.*.db"))
    assert len(archives) == 1
    with sqlite3.connect(archives[0]) as db:
        assert db.execute("SELECT status FROM audit_log WHERE id = ?", (intent,)).fetchone() == (
            "ok",
        )


def test_failed_wal_checkpoint_never_rotates_committed_rows(home, monkeypatch):
    engine = audit.get_engine()
    engine.log(skill="unknown", tool="first")
    original_connect = engine._connect

    class CheckpointFailure:
        def __init__(self, conn):
            self.conn = conn

        def execute(self, sql, *args):
            if sql.startswith("PRAGMA wal_checkpoint"):
                raise sqlite3.OperationalError("checkpoint failed")
            return self.conn.execute(sql, *args)

        def close(self):
            self.conn.close()

        def __getattr__(self, name):
            return getattr(self.conn, name)

    monkeypatch.setattr(engine, "_connect", lambda: CheckpointFailure(original_connect()))
    monkeypatch.setattr(audit, "_MAX_DB_SIZE_BYTES", 1)
    engine.log(skill="unknown", tool="second")
    assert list(home.glob("audit.*.db")) == []
    assert [row["tool"] for row in _rows(home)] == ["first", "second"]


def test_telemetry_has_correlation_and_no_business_payload(home, monkeypatch, caplog):
    monkeypatch.setenv("AIOPS_TELEMETRY", "1")

    @decorators.governed_tool(risk_level="low")
    def read() -> dict:
        return {"secret": "sentinel-secret", "truncated": False}

    with caplog.at_level(logging.INFO):
        read()
    event = next(r.message for r in caplog.records if r.message.startswith("AIOPS_TELEMETRY "))
    payload = json.loads(event.removeprefix("AIOPS_TELEMETRY "))
    assert payload["workflowId"] == "workflow-123"
    assert payload["status"] == "ok"
    assert payload["auditPersisted"] is True
    assert payload["truncated"] is False
    assert "sentinel-secret" not in event


def test_telemetry_does_not_copy_untrusted_truncation_value(home, monkeypatch, caplog):
    monkeypatch.setenv("AIOPS_TELEMETRY", "1")
    monkeypatch.setenv("AIOPS_WORKFLOW_ID", "secret with spaces")

    @decorators.governed_tool(risk_level="low")
    def read() -> dict:
        return {"truncated": "sentinel-secret"}

    with caplog.at_level(logging.INFO):
        read()
    event = next(r.message for r in caplog.records if r.message.startswith("AIOPS_TELEMETRY "))
    payload = json.loads(event.removeprefix("AIOPS_TELEMETRY "))
    assert payload["workflowId"] == ""
    assert payload["truncated"] is None
    assert "sentinel-secret" not in event
