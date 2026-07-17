"""Governance harness — audit engine coverage.

Portable across the whole tool line: references ONLY
``firewall_aiops.governance.audit`` and binds state to an isolated home via
``FIREWALL_AIOPS_HOME``. No ops / cli / connection / mcp_server imports.

Exercises row writes with every column, query filters, stats aggregation,
size-based rotation + archive cleanup, permission hardening, in-place column
migration, agent detection, the _safe_json fallback, and the singleton.
"""

from __future__ import annotations

import sqlite3
import stat
import sys

import pytest

import firewall_aiops.governance.audit as audit_mod
from firewall_aiops.governance.audit import (
    AuditEngine,
    _current_user,
    _safe_json,
    detect_agent,
    get_engine,
    reset_engine,
)


@pytest.fixture
def audit_home(tmp_path, monkeypatch):
    monkeypatch.setenv("FIREWALL_AIOPS_HOME", str(tmp_path))
    reset_engine()
    yield tmp_path
    reset_engine()


def _rows(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id")]
    finally:
        conn.close()


# ── log() writes ───────────────────────────────────────────────────────


@pytest.mark.unit
def test_log_writes_row_with_all_columns(audit_home):
    eng = AuditEngine(audit_home / "audit.db")
    eng.log(
        skill="firewall-aiops",
        tool="drop_index",
        params={"name": "idx1"},
        result={"status": "dropped"},
        status="ok",
        duration_ms=42,
        agent="claude",
        workflow_id="wf-1",
        risk_level="high",
        rationale="cleanup",
        approved_by="dba-alice",
        risk_tier="dual",
    )
    rows = _rows(audit_home / "audit.db")
    assert len(rows) == 1
    row = rows[0]
    assert row["skill"] == "firewall-aiops"
    assert row["tool"] == "drop_index"
    assert row["status"] == "ok"
    assert row["duration_ms"] == 42
    assert row["agent"] == "claude"
    assert row["workflow_id"] == "wf-1"
    assert row["risk_level"] == "high"
    assert row["rationale"] == "cleanup"
    assert row["approved_by"] == "dba-alice"
    assert row["risk_tier"] == "dual"
    assert '"name": "idx1"' in row["params"]
    assert row["user"]  # defaulted to current user


@pytest.mark.unit
def test_log_noop_when_engine_not_ok(audit_home):
    # Parent is a file → mkdir fails → engine not ok → log is a silent no-op.
    blocker = audit_home / "blocker"
    blocker.write_text("x", "utf-8")
    eng = AuditEngine(blocker / "audit.db")
    assert eng._ok is False
    eng.log(skill="s", tool="t")  # must not raise


@pytest.mark.unit
def test_log_swallows_write_errors(audit_home, monkeypatch):
    eng = AuditEngine(audit_home / "audit.db")

    def _boom(*_a, **_k):
        raise sqlite3.OperationalError("disk gone")

    monkeypatch.setattr(eng, "_connect", _boom)
    eng.log(skill="s", tool="t")  # swallowed, no raise


# ── query() ────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_query_filters(audit_home):
    eng = AuditEngine(audit_home / "audit.db")
    eng.log(skill="firewall-aiops", tool="a", status="ok", workflow_id="w1")
    eng.log(skill="firewall-aiops", tool="b", status="error", workflow_id="w2")
    eng.log(skill="other", tool="a", status="ok", workflow_id="w1")

    assert len(eng.query()) == 3
    assert len(eng.query(skill="firewall-aiops")) == 2
    assert len(eng.query(tool="a")) == 2
    assert len(eng.query(status="error")) == 1
    assert len(eng.query(workflow_id="w1")) == 2
    assert len(eng.query(limit=1)) == 1
    # since filter in the future → nothing.
    assert eng.query(since="2999-01-01T00:00:00+00:00") == []
    # DESC ordering by id.
    assert eng.query()[0]["skill"] == "other"


# ── stats() ────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_stats_aggregation(audit_home):
    eng = AuditEngine(audit_home / "audit.db")
    eng.log(skill="firewall-aiops", tool="a", status="ok")
    eng.log(skill="firewall-aiops", tool="b", status="error")
    eng.log(skill="other", tool="c", status="ok")

    stats = eng.stats(days=7)
    assert stats["total"] == 3
    assert stats["days"] == 7
    assert stats["by_status"] == {"ok": 2, "error": 1}
    assert stats["by_skill"] == {"firewall-aiops": 2, "other": 1}


# ── Rotation + archive cleanup ─────────────────────────────────────────


@pytest.mark.unit
def test_rotation_archives_when_over_size(audit_home, monkeypatch):
    db = audit_home / "audit.db"
    eng = AuditEngine(db)
    eng.log(skill="s", tool="first")
    # Force the next log() to see the DB as oversized.
    monkeypatch.setattr(audit_mod, "_MAX_DB_SIZE_BYTES", 1)
    eng.log(skill="s", tool="second")

    archives = list(audit_home.glob("audit.*.db"))
    assert len(archives) == 1, archives
    # Fresh DB holds only the post-rotation row.
    tools = [r["tool"] for r in _rows(db)]
    assert tools == ["second"]
    # The archive retains the pre-rotation row.
    assert [r["tool"] for r in _rows(archives[0])] == ["first"]


@pytest.mark.unit
def test_cleanup_archives_keeps_recent_n(audit_home, monkeypatch):
    db = audit_home / "audit.db"
    eng = AuditEngine(db)
    monkeypatch.setattr(audit_mod, "_MAX_ARCHIVES", 2)
    # Fabricate 4 archive files with increasing mtimes.
    import os

    made = []
    for i in range(4):
        p = audit_home / f"audit.2026010{i}-000000.db"
        p.write_text("x", "utf-8")
        os.utime(p, (1000 + i, 1000 + i))
        made.append(p)
    eng._cleanup_archives()
    remaining = sorted(audit_home.glob("audit.*.db"))
    # Only the two most recent survive.
    assert remaining == sorted(made[2:])


# ── Migration of legacy DBs ────────────────────────────────────────────


@pytest.mark.unit
def test_migrate_adds_missing_columns(audit_home):
    db = audit_home / "audit.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "ts TEXT NOT NULL, skill TEXT NOT NULL, tool TEXT NOT NULL, "
        "params TEXT DEFAULT '{}', result TEXT DEFAULT '{}', status TEXT DEFAULT 'ok', "
        "duration_ms INTEGER DEFAULT 0, agent TEXT DEFAULT 'unknown', "
        "workflow_id TEXT DEFAULT '', user TEXT DEFAULT 'unknown', "
        "risk_level TEXT DEFAULT 'low')"
    )
    conn.commit()
    conn.close()

    AuditEngine(db)  # triggers _migrate
    cols = {r[1] for r in sqlite3.connect(db).execute("PRAGMA table_info(audit_log)")}
    assert {"rationale", "approved_by", "risk_tier"} <= cols


# ── Permission hardening ───────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission model")
def test_permissions_hardened(audit_home):
    db = audit_home / "audit.db"
    eng = AuditEngine(db)
    eng.log(skill="s", tool="t")
    dir_mode = stat.S_IMODE(db.parent.stat().st_mode)
    db_mode = stat.S_IMODE(db.stat().st_mode)
    assert dir_mode == 0o700
    assert db_mode == 0o600


# ── Module helpers ─────────────────────────────────────────────────────


@pytest.mark.unit
def test_safe_json_variants():
    assert _safe_json(None) == "{}"
    assert _safe_json({"a": 1}) == '{"a": 1}'
    # Circular reference → json.dumps raises even with default=str → _raw fallback.
    circular: list = []
    circular.append(circular)
    out = _safe_json(circular)
    assert "_raw" in out


@pytest.mark.unit
def test_current_user_fallback(monkeypatch):
    import getpass

    monkeypatch.setattr(getpass, "getuser", lambda: (_ for _ in ()).throw(OSError()))
    assert _current_user() == "unknown"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ("CLAUDE_SESSION_ID", "claude"),
        ("CLAUDE_CODE", "claude"),
        ("CODEX_SESSION", "codex"),
        ("OLLAMA_HOST", "local"),
        ("DEERFLOW_SESSION", "deerflow"),
    ],
)
def test_detect_agent_markers(monkeypatch, env, expected):
    for marker in (
        "CLAUDE_SESSION_ID",
        "CLAUDE_CODE",
        "CODEX_SESSION",
        "OLLAMA_HOST",
        "DEERFLOW_SESSION",
    ):
        monkeypatch.delenv(marker, raising=False)
    monkeypatch.setenv(env, "1")
    assert detect_agent() == expected


@pytest.mark.unit
def test_detect_agent_unknown(monkeypatch):
    for marker in (
        "CLAUDE_SESSION_ID",
        "CLAUDE_CODE",
        "CODEX_SESSION",
        "OLLAMA_HOST",
        "DEERFLOW_SESSION",
    ):
        monkeypatch.delenv(marker, raising=False)
    assert detect_agent() == "unknown"


# ── Singleton ──────────────────────────────────────────────────────────


@pytest.mark.unit
def test_singleton_identity_and_rebind_warning(audit_home, tmp_path):
    first = get_engine(audit_home / "audit.db")
    other = tmp_path / "elsewhere" / "audit.db"
    assert get_engine(other) is first  # rebind ignored
    reset_engine()
    assert get_engine(other) is not first
