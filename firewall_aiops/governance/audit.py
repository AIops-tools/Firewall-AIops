"""Unified audit logging engine — all Monitoring skills write to a single SQLite database.

Replaces 7 per-skill JSON Lines audit loggers with one shared ``~/.firewall-aiops/audit.db``.
Framework-agnostic: works with Claude, Codex, local agents, or any MCP client.
"""

from __future__ import annotations

import getpass
import json
import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from firewall_aiops.governance.paths import ops_path

try:
    import fcntl
except ImportError:  # Windows has no fcntl; the in-process lock still applies.
    fcntl = None

_log = logging.getLogger("firewall-aiops.audit")

# Back-compat override hook. When None (default) the path resolves via
# ops_path("audit.db") (honoring FIREWALL_AIOPS_HOME). Downstream code/tests may set this
# to a fixed Path to redirect the default DB — kept so the FIREWALL_AIOPS_HOME refactor
# does not break callers that monkeypatch `_DEFAULT_DB`.
_DEFAULT_DB: Path | None = None

_MAX_DB_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB
_MAX_ARCHIVES = 5
_BUSY_TIMEOUT_MS = 5000
_rotation_thread_lock = threading.RLock()


@contextmanager
def _rotation_guard(path: Path):
    """Serialize rotation and intent insertion across local processes."""
    with _rotation_thread_lock:
        fd = os.open(path.with_name("audit.lock"), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


class AuditUnavailable(RuntimeError):
    """A write was stopped because its durable audit intent could not be recorded."""

_CREATE_TABLE = """\
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    skill       TEXT    NOT NULL,
    tool        TEXT    NOT NULL,
    params      TEXT    NOT NULL DEFAULT '{}',
    result      TEXT    NOT NULL DEFAULT '{}',
    status      TEXT    NOT NULL DEFAULT 'ok',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    agent       TEXT    NOT NULL DEFAULT 'unknown',
    workflow_id TEXT    NOT NULL DEFAULT '',
    user        TEXT    NOT NULL DEFAULT 'unknown',
    risk_level  TEXT    NOT NULL DEFAULT 'low',
    rationale   TEXT    NOT NULL DEFAULT '',
    approved_by TEXT    NOT NULL DEFAULT '',
    risk_tier   TEXT    NOT NULL DEFAULT ''
)
"""

# Columns added after the original schema shipped. Each is applied with an
# idempotent ALTER TABLE so pre-existing audit.db files migrate in place (a
# fresh DB already has them via _CREATE_TABLE). Accountability fields per the
# SOC2 / 等保 "who authorized this, and why" requirement.
_MIGRATIONS = (
    ("rationale", "TEXT NOT NULL DEFAULT ''"),
    ("approved_by", "TEXT NOT NULL DEFAULT ''"),
    ("risk_tier", "TEXT NOT NULL DEFAULT ''"),
)

_INSERT = """\
INSERT INTO audit_log (ts, skill, tool, params, result, status, duration_ms, agent, workflow_id, user, risk_level, rationale, approved_by, risk_tier)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class AuditEngine:
    """Append-only audit logger backed by SQLite with WAL mode.

    Thread-safe for concurrent writes from multiple skill processes.
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        if db_path:
            self._path = Path(db_path).expanduser()
        else:
            self._path = _DEFAULT_DB or ops_path("audit.db")
        self._ok = False
        self._write_blocked = False
        self._write_failures = 0
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self._init_db()
            self._harden_permissions()
            self._ok = True
        except Exception:
            _log.warning("Cannot initialize audit DB at %s", self._path, exc_info=True)

    def _init_db(self) -> None:
        conn = self._connect()
        conn.execute(_CREATE_TABLE)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        self._migrate(conn)
        conn.commit()
        conn.close()

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Add columns introduced after the original schema, in place.

        Idempotent: only adds a column the table is missing, so existing
        audit.db files gain rationale/approved_by/risk_tier without losing rows.
        """
        existing = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)")}
        for name, decl in _MIGRATIONS:
            if name not in existing:
                conn.execute(f"ALTER TABLE audit_log ADD COLUMN {name} {decl}")  # nosec B608

    def _harden_permissions(self) -> None:
        """Restrict the audit dir to 0700 and DB files (incl. WAL/SHM) to 0600.

        ``mkdir(mode=...)`` is masked by umask, so set permissions explicitly.
        Best-effort: never raises (audit must not break the tool call)."""
        try:
            os.chmod(self._path.parent, 0o700)
        except OSError:
            pass
        for suffix in ("", "-wal", "-shm"):
            candidate = self._path.with_name(self._path.name + suffix)
            try:
                if candidate.exists():
                    os.chmod(candidate, 0o600)
            except OSError:
                pass

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path), timeout=_BUSY_TIMEOUT_MS / 1000)
        conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def log(
        self,
        *,
        skill: str,
        tool: str,
        params: dict[str, Any] | None = None,
        result: Any = None,
        status: str = "ok",
        duration_ms: int = 0,
        agent: str = "unknown",
        workflow_id: str = "",
        user: str = "",
        risk_level: str = "low",
        rationale: str = "",
        approved_by: str = "",
        risk_tier: str = "",
        strict: bool = False,
    ) -> int | None:
        """Append a row. Strict mode refuses writes if the intent cannot persist.

        rationale / approved_by / risk_tier carry the accountability trail:
        *why* a change was made, *who* signed off, and the *approval tier* the
        policy engine assigned (none/confirm/dual/review).
        """
        if not self._ok:
            if strict:
                self._write_blocked = True
                self._write_failures += 1
                raise AuditUnavailable("Audit storage is unavailable; write was not started")
            self._write_failures += 1
            return None
        try:
            with _rotation_guard(self._path):
                self._maybe_rotate()
                conn = self._connect()
                try:
                    cursor = conn.execute(
                        _INSERT,
                        (
                            datetime.now(tz=UTC).isoformat(),
                            skill,
                            tool,
                            _safe_json(params),
                            _safe_json(_summarize_result(result)),
                            status,
                            duration_ms,
                            agent,
                            workflow_id,
                            user or _current_user(),
                            risk_level,
                            rationale,
                            approved_by,
                            risk_tier,
                        ),
                    )
                    conn.commit()
                    audit_id = cursor.lastrowid
                finally:
                    conn.close()
            _log.debug("[AUDIT] %s.%s -> %s (%dms)", skill, tool, status, duration_ms)
            return audit_id
        except Exception:
            self._write_failures += 1
            _log.warning("Failed to write audit log", exc_info=True)
            if strict:
                self._write_blocked = True
                raise AuditUnavailable("Audit storage is unavailable; write was not started") from None
            return None

    def begin_write(self, **metadata: Any) -> int:
        """Commit a durable intent before the caller sends an upstream write."""
        if self._write_blocked:
            raise AuditUnavailable("Audit storage failed; further writes are blocked")
        audit_id = self.log(status="pending", strict=True, **metadata)
        assert audit_id is not None
        return audit_id

    def finish_write(self, audit_id: int, *, result: Any, status: str, duration_ms: int) -> None:
        """Resolve a write intent; on failure leave a recoverable pending row."""
        try:
            conn = self._connect()
            try:
                cursor = conn.execute(
                    "UPDATE audit_log SET result = ?, status = ?, duration_ms = ? "
                    "WHERE id = ? AND status = 'pending'",
                    (_safe_json(_summarize_result(result)), status, duration_ms, audit_id),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError(f"audit intent {audit_id} is missing")
                conn.commit()
            finally:
                conn.close()
        except Exception:
            self._write_blocked = True
            self._write_failures += 1
            _log.warning("Failed to finalize audit intent %s", audit_id, exc_info=True)
            raise AuditUnavailable(
                f"Audit intent {audit_id} remains pending; operation may have completed"
            ) from None

    def reconcile_pending(self, audit_id: int) -> bool:
        """Mark an orphaned intent unknown after an operator checks the process.

        Never run this automatically: another process may still be executing
        the write. The row remains visible until explicitly reconciled.
        """
        conn = self._connect()
        try:
            cursor = conn.execute(
                "UPDATE audit_log SET status = 'unknown', result = ? "
                "WHERE id = ? AND status = 'pending'",
                (_safe_json({"auditInterrupted": True}), audit_id),
            )
            conn.commit()
            return cursor.rowcount == 1
        finally:
            conn.close()

    def health(self) -> dict[str, Any]:
        """Safe local health counters for operators and telemetry exporters."""
        pending: int | None = None
        if self._ok:
            try:
                conn = self._connect()
                try:
                    pending = conn.execute(
                        "SELECT COUNT(*) FROM audit_log WHERE status = 'pending'"
                    ).fetchone()[0]
                finally:
                    conn.close()
            except Exception:
                pass
        return {
            "available": self._ok and pending is not None and not self._write_blocked,
            "writeBlocked": self._write_blocked,
            "auditWriteFailures": self._write_failures,
            "pendingWrites": pending,
        }

    # ── Rotation ──────────────────────────────────────────────────────

    def _maybe_rotate(self) -> None:
        """Archive the DB if it exceeds size limit."""
        try:
            if not self._path.exists():
                return
            if self._path.stat().st_size < _MAX_DB_SIZE_BYTES:
                return
            pending_conn = self._connect()
            try:
                if pending_conn.execute(
                    "SELECT 1 FROM audit_log WHERE status = 'pending' LIMIT 1"
                ).fetchone():
                    return
            finally:
                pending_conn.close()
            archive_name = self._path.with_suffix(
                f".{datetime.now(tz=UTC).strftime('%Y%m%d-%H%M%S')}.db"
            )
            # Checkpoint the WAL into the main file before renaming, otherwise
            # un-checkpointed rows in audit.db-wal are silently lost (the
            # sidecars belong to the OLD path and never follow the archive).
            conn = self._connect()
            try:
                checkpoint = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                if checkpoint is None or checkpoint[0]:
                    raise RuntimeError(f"WAL checkpoint incomplete: {checkpoint}")
            finally:
                conn.close()
            self._path.rename(archive_name)
            # Drop now-stale sidecars (empty after a successful checkpoint).
            for suffix in ("-wal", "-shm"):
                sidecar = self._path.with_name(self._path.name + suffix)
                try:
                    sidecar.unlink(missing_ok=True)
                except OSError:
                    pass
            self._init_db()
            self._harden_permissions()
            self._cleanup_archives()
            _log.info("Audit DB rotated → %s", archive_name.name)
        except Exception:
            _log.warning("Audit DB rotation failed", exc_info=True)

    def _cleanup_archives(self) -> None:
        """Keep only the most recent N archive files."""
        archives = sorted(
            self._path.parent.glob("audit.*.db"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for old in archives[_MAX_ARCHIVES:]:
            old.unlink(missing_ok=True)

    # ── Query helpers (used by CLI) ───────────────────────────────────

    def query(
        self,
        *,
        skill: str | None = None,
        tool: str | None = None,
        status: str | None = None,
        workflow_id: str | None = None,
        since: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Query audit records with optional filters."""
        clauses: list[str] = []
        values: list[Any] = []

        if skill:
            clauses.append("skill = ?")
            values.append(skill)
        if tool:
            clauses.append("tool = ?")
            values.append(tool)
        if status:
            clauses.append("status = ?")
            values.append(status)
        if workflow_id:
            clauses.append("workflow_id = ?")
            values.append(workflow_id)
        if since:
            clauses.append("ts >= ?")
            values.append(since)

        # ``clauses`` are hardcoded "col = ?" fragments; every user value is a
        # bound parameter in ``values``. No user input is interpolated here.
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM audit_log {where} ORDER BY id DESC LIMIT ?"  # nosec B608
        values.append(limit)

        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(sql, values).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def stats(self, days: int = 7) -> dict[str, Any]:
        """Aggregate statistics over the last N days."""
        since = (datetime.now(tz=UTC) - timedelta(days=days)).isoformat()
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row

            total = conn.execute(
                "SELECT COUNT(*) as c FROM audit_log WHERE ts >= ?", (since,)
            ).fetchone()["c"]

            by_status = {
                r["status"]: r["c"]
                for r in conn.execute(
                    "SELECT status, COUNT(*) as c FROM audit_log WHERE ts >= ? GROUP BY status",
                    (since,),
                ).fetchall()
            }

            by_skill = {
                r["skill"]: r["c"]
                for r in conn.execute(
                    "SELECT skill, COUNT(*) as c FROM audit_log WHERE ts >= ? GROUP BY skill",
                    (since,),
                ).fetchall()
            }

            return {"total": total, "by_status": by_status, "by_skill": by_skill, "days": days}
        finally:
            conn.close()


# ── Module-level helpers ──────────────────────────────────────────────

def _current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def _safe_json(obj: Any) -> str:
    """Serialize to JSON, falling back to str() for non-serializable objects."""
    if obj is None:
        return "{}"
    try:
        return json.dumps(obj, ensure_ascii=False, default=str)
    except Exception:
        return json.dumps({"_raw": str(obj)})


def _summarize_result(result: Any) -> dict[str, Any]:
    """Persist only outcome metadata; never copy a tool's business payload."""
    if isinstance(result, dict):
        summary: dict[str, Any] = {"kind": "object"}
        if result.get("error"):
            summary["error"] = True
        if result.get("outcomeUnknown") is True:
            summary["outcomeUnknown"] = True
        if result.get("_undo_id"):
            summary["undoRecorded"] = True
        if result.get("_pattern_id"):
            summary["patternMatched"] = True
        for key in ("truncated", "returned", "limit"):
            value = result.get(key)
            if type(value) in (bool, int):
                summary[key] = value
        return summary
    if isinstance(result, (list, tuple)):
        return {"kind": "list", "count": len(result)}
    return {"kind": type(result).__name__}


def detect_agent() -> str:
    """Infer the calling AI agent from environment variables."""
    if os.environ.get("CLAUDE_SESSION_ID") or os.environ.get("CLAUDE_CODE"):
        return "claude"
    # Note: OPENAI_API_KEY is deliberately NOT used as a codex marker — it is
    # commonly set in shells for unrelated tooling and misattributes the agent.
    if os.environ.get("CODEX_SESSION"):
        return "codex"
    if os.environ.get("OLLAMA_HOST"):
        return "local"
    if os.environ.get("DEERFLOW_SESSION"):
        return "deerflow"
    return "unknown"


# Singleton — shared across all skills in the same process
_engine: AuditEngine | None = None
_engine_lock = threading.Lock()


def get_engine(db_path: Path | str | None = None) -> AuditEngine:
    """Return the global AuditEngine singleton (lazy, lock-guarded).

    A ``db_path`` differing from the one the singleton was created with is
    ignored with a warning — call :func:`reset_engine` first to rebind.
    """
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = AuditEngine(db_path)
                return _engine
    if db_path is not None:
        requested = Path(db_path).expanduser()
        if requested != _engine._path:
            _log.warning(
                "get_engine(%s) ignored — singleton already initialized at %s; "
                "call reset_engine() first to rebind.",
                requested, _engine._path,
            )
    return _engine


def reset_engine() -> None:
    """Reset the singleton. Mirrors patterns.reset_pattern_engine()."""
    global _engine
    with _engine_lock:
        _engine = None
