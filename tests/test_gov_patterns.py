"""Governance harness — L5 auto-remediation pattern engine coverage.

Portable across the whole tool line: references ONLY
``firewall_aiops.governance.patterns`` and binds state to an isolated home via
``FIREWALL_AIOPS_HOME``. No ops / cli / connection / mcp_server imports.

Exercises pattern loading + signature validation, the armable preconditions,
skill/tool/target matching, rate limiting, the circuit breaker's state
transitions, hot-reload, fail-open on malformed input, and the singleton.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest

import firewall_aiops.governance.patterns as patterns_mod
from firewall_aiops.governance.patterns import (
    PatternEngine,
    get_pattern_engine,
    reset_pattern_engine,
)

# ── YAML fixtures ──────────────────────────────────────────────────────

_ARMABLE = """\
schema_version: 1
pattern_id: {pid}
classification:
  risk: low
  reversible: true
  repeatable: true
action:
  skill: {skill}
  tool: {tool}
approval:
  status: approved
  signed_by: dba-alice
rate_limit:
  max_per_hour: {per_hour}
  max_per_day: {per_day}
circuit_breaker:
  consecutive_validation_failures: {threshold}
  disable_seconds: {disable}
{extra}
"""


def _write_pattern(
    directory,
    *,
    pid="p1",
    skill="firewall-aiops",
    tool="reindex_table",
    per_hour=0,
    per_day=0,
    threshold=3,
    disable=3600,
    extra="",
    filename=None,
):
    directory.mkdir(parents=True, exist_ok=True)
    text = _ARMABLE.format(
        pid=pid,
        skill=skill,
        tool=tool,
        per_hour=per_hour,
        per_day=per_day,
        threshold=threshold,
        disable=disable,
        extra=extra,
    )
    path = directory / (filename or f"{pid}.yaml")
    path.write_text(text, "utf-8")
    return path


@pytest.fixture
def patterns_dir(tmp_path):
    return tmp_path / "auto-remediation-patterns"


@pytest.fixture(autouse=True)
def _reset_singleton():
    reset_pattern_engine()
    yield
    reset_pattern_engine()


# ── Loading + validation ───────────────────────────────────────────────


@pytest.mark.unit
def test_load_armable_pattern(patterns_dir):
    _write_pattern(patterns_dir)
    eng = PatternEngine(patterns_dir)
    loaded = eng.loaded_patterns()
    assert len(loaded) == 1
    pat = loaded[0]
    assert pat.pattern_id == "p1"
    assert pat.risk == "low"
    assert pat.is_armable is True
    assert pat.is_expired is False


@pytest.mark.unit
def test_missing_dir_yields_no_patterns(patterns_dir):
    eng = PatternEngine(patterns_dir)  # dir never created
    assert eng.loaded_patterns() == []


@pytest.mark.unit
def test_empty_file_is_skipped(patterns_dir):
    patterns_dir.mkdir(parents=True)
    (patterns_dir / "empty.yaml").write_text("", "utf-8")
    eng = PatternEngine(patterns_dir)
    assert eng.loaded_patterns() == []


@pytest.mark.unit
def test_malformed_file_fails_open_and_good_files_still_load(patterns_dir):
    _write_pattern(patterns_dir, pid="good", tool="reindex_table")
    patterns_dir.mkdir(parents=True, exist_ok=True)
    (patterns_dir / "broken.yaml").write_text("{{ not: valid: yaml ::::", "utf-8")
    eng = PatternEngine(patterns_dir)
    ids = {p.pattern_id for p in eng.loaded_patterns()}
    assert ids == {"good"}


@pytest.mark.unit
def test_missing_required_key_skipped(patterns_dir):
    patterns_dir.mkdir(parents=True)
    # No 'action' key at all.
    (patterns_dir / "p.yaml").write_text(
        "schema_version: 1\npattern_id: x\nclassification:\n"
        "  risk: low\n  reversible: true\n  repeatable: true\n",
        "utf-8",
    )
    assert PatternEngine(patterns_dir).loaded_patterns() == []


@pytest.mark.unit
def test_wrong_schema_version_skipped(patterns_dir):
    _write_pattern(patterns_dir, pid="v2")
    (patterns_dir / "v2.yaml").write_text(
        (patterns_dir / "v2.yaml").read_text().replace("schema_version: 1", "schema_version: 2"),
        "utf-8",
    )
    assert PatternEngine(patterns_dir).loaded_patterns() == []


@pytest.mark.unit
def test_missing_classification_key_skipped(patterns_dir):
    patterns_dir.mkdir(parents=True)
    (patterns_dir / "p.yaml").write_text(
        "schema_version: 1\npattern_id: x\nclassification:\n  risk: low\n"
        "action:\n  skill: s\n  tool: t\n",
        "utf-8",
    )
    assert PatternEngine(patterns_dir).loaded_patterns() == []


@pytest.mark.unit
def test_missing_action_skill_or_tool_skipped(patterns_dir):
    patterns_dir.mkdir(parents=True)
    (patterns_dir / "p.yaml").write_text(
        "schema_version: 1\npattern_id: x\nclassification:\n"
        "  risk: low\n  reversible: true\n  repeatable: true\n"
        "action:\n  skill: s\n",  # no tool
        "utf-8",
    )
    assert PatternEngine(patterns_dir).loaded_patterns() == []


@pytest.mark.unit
def test_duplicate_pattern_id_keeps_first(patterns_dir):
    _write_pattern(patterns_dir, pid="dup", tool="a", filename="aaa.yaml")
    _write_pattern(patterns_dir, pid="dup", tool="b", filename="zzz.yaml")
    eng = PatternEngine(patterns_dir)
    loaded = eng.loaded_patterns()
    assert len(loaded) == 1
    # sorted glob → aaa.yaml wins
    assert loaded[0].tool == "a"


# ── Armable preconditions ──────────────────────────────────────────────


@pytest.mark.unit
def test_unsigned_pattern_not_armable(patterns_dir):
    _write_pattern(patterns_dir, extra="")  # base has signed_by + approved
    # Overwrite approval to unsigned.
    path = patterns_dir / "p1.yaml"
    path.write_text(
        path.read_text().replace("signed_by: dba-alice", "signed_by: ''"), "utf-8"
    )
    pat = PatternEngine(patterns_dir).loaded_patterns()[0]
    assert pat.risk == "unsigned"
    assert pat.is_armable is False


@pytest.mark.unit
def test_rejected_status_not_armable(patterns_dir):
    _write_pattern(patterns_dir)
    path = patterns_dir / "p1.yaml"
    path.write_text(
        path.read_text().replace("status: approved", "status: rejected"), "utf-8"
    )
    pat = PatternEngine(patterns_dir).loaded_patterns()[0]
    assert pat.risk == "unsigned"
    assert pat.is_armable is False


@pytest.mark.unit
def test_expired_pattern_not_armable(patterns_dir):
    past = (datetime.now(tz=UTC) - timedelta(days=1)).isoformat()
    _write_pattern(patterns_dir, extra=f"expires_at: '{past}'")
    pat = PatternEngine(patterns_dir).loaded_patterns()[0]
    assert pat.is_expired is True
    assert pat.is_armable is False


@pytest.mark.unit
def test_future_expiry_still_armable(patterns_dir):
    future = (datetime.now(tz=UTC) + timedelta(days=1)).isoformat()
    _write_pattern(patterns_dir, extra=f"expires_at: '{future}'")
    pat = PatternEngine(patterns_dir).loaded_patterns()[0]
    assert pat.is_expired is False
    assert pat.is_armable is True


@pytest.mark.unit
def test_malformed_expiry_treated_as_expired(patterns_dir):
    _write_pattern(patterns_dir, extra="expires_at: 'not-a-real-date'")
    pat = PatternEngine(patterns_dir).loaded_patterns()[0]
    assert pat.is_expired is True
    assert pat.is_armable is False


@pytest.mark.unit
def test_non_low_risk_not_armable(patterns_dir):
    _write_pattern(patterns_dir)
    path = patterns_dir / "p1.yaml"
    path.write_text(path.read_text().replace("risk: low", "risk: high"), "utf-8")
    pat = PatternEngine(patterns_dir).loaded_patterns()[0]
    assert pat.is_armable is False


# ── Matching ───────────────────────────────────────────────────────────


@pytest.mark.unit
def test_match_armed(patterns_dir):
    _write_pattern(patterns_dir, skill="firewall-aiops", tool="reindex_table")
    eng = PatternEngine(patterns_dir)
    m = eng.match(skill="firewall-aiops", tool="reindex_table", target="db1")
    assert m is not None
    assert m.armed is True
    assert m.pattern.pattern_id == "p1"


@pytest.mark.unit
def test_match_none_when_no_action_matches(patterns_dir):
    _write_pattern(patterns_dir, tool="reindex_table")
    eng = PatternEngine(patterns_dir)
    assert eng.match(skill="firewall-aiops", tool="other", target="db1") is None


@pytest.mark.unit
def test_match_not_armable_returns_unarmed_with_reason(patterns_dir):
    _write_pattern(patterns_dir, tool="reindex_table")
    path = patterns_dir / "p1.yaml"
    path.write_text(path.read_text().replace("status: approved", "status: rejected"), "utf-8")
    eng = PatternEngine(patterns_dir)
    m = eng.match(skill="firewall-aiops", tool="reindex_table", target="db1")
    assert m is not None
    assert m.armed is False
    assert "not armable" in m.reason


@pytest.mark.unit
def test_rate_limit_hourly_cap(patterns_dir):
    _write_pattern(patterns_dir, tool="reindex_table", per_hour=2)
    eng = PatternEngine(patterns_dir)
    assert eng.match("firewall-aiops", "reindex_table", "db1").armed is True
    assert eng.match("firewall-aiops", "reindex_table", "db1").armed is True
    third = eng.match("firewall-aiops", "reindex_table", "db1")
    assert third.armed is False
    assert "hourly cap" in third.reason
    # A different target has its own budget.
    assert eng.match("firewall-aiops", "reindex_table", "db2").armed is True


@pytest.mark.unit
def test_rate_limit_daily_cap(patterns_dir):
    _write_pattern(patterns_dir, tool="reindex_table", per_hour=0, per_day=1)
    eng = PatternEngine(patterns_dir)
    assert eng.match("firewall-aiops", "reindex_table", "db1").armed is True
    second = eng.match("firewall-aiops", "reindex_table", "db1")
    assert second.armed is False
    assert "daily cap" in second.reason


# ── Circuit breaker ────────────────────────────────────────────────────


@pytest.mark.unit
def test_circuit_breaker_trips_after_threshold_failures(patterns_dir):
    _write_pattern(patterns_dir, tool="reindex_table", threshold=3, disable=3600)
    eng = PatternEngine(patterns_dir)
    for _ in range(3):
        eng.report_outcome("p1", "db1", success=False)
    key = ("p1", "db1")
    ctr = eng._counters[key]
    assert ctr.consecutive_failures == 3
    assert ctr.disabled_until > time.time()
    # Now match is circuit-broken.
    m = eng.match("firewall-aiops", "reindex_table", "db1")
    assert m.armed is False
    assert "circuit-broken" in m.reason


@pytest.mark.unit
def test_circuit_breaker_success_resets_failures(patterns_dir):
    _write_pattern(patterns_dir, tool="reindex_table", threshold=3)
    eng = PatternEngine(patterns_dir)
    eng.report_outcome("p1", "db1", success=False)
    eng.report_outcome("p1", "db1", success=False)
    assert eng._counters[("p1", "db1")].consecutive_failures == 2
    eng.report_outcome("p1", "db1", success=True)
    assert eng._counters[("p1", "db1")].consecutive_failures == 0
    # Not tripped — still armable.
    assert eng.match("firewall-aiops", "reindex_table", "db1").armed is True


@pytest.mark.unit
def test_report_outcome_unknown_pattern_uses_defaults(patterns_dir):
    _write_pattern(patterns_dir)
    eng = PatternEngine(patterns_dir)
    # Unknown pattern id → default threshold 3.
    for _ in range(3):
        eng.report_outcome("no-such", "db1", success=False)
    assert eng._counters[("no-such", "db1")].disabled_until > time.time()


# ── Hot reload + helpers ───────────────────────────────────────────────


@pytest.mark.unit
def test_hot_reload_on_new_file(patterns_dir):
    _write_pattern(patterns_dir, pid="p1", tool="reindex_table")
    eng = PatternEngine(patterns_dir)
    assert eng.match("firewall-aiops", "reindex_table", "db1") is not None
    # Add a second pattern file — match() triggers _maybe_reload.
    _write_pattern(patterns_dir, pid="p2", tool="vacuum_table", filename="p2.yaml")
    m = eng.match("firewall-aiops", "vacuum_table", "db1")
    assert m is not None
    assert m.pattern.pattern_id == "p2"


@pytest.mark.unit
def test_hot_reload_on_mtime_change(patterns_dir):
    _write_pattern(patterns_dir, pid="p1", tool="reindex_table")
    eng = PatternEngine(patterns_dir)
    assert eng.match("firewall-aiops", "reindex_table", "db1") is not None
    # Rewrite the same file with a different tool + bump mtime.
    _write_pattern(patterns_dir, pid="p1", tool="analyze_table")
    path = patterns_dir / "p1.yaml"
    future = path.stat().st_mtime + 1000
    import os

    os.utime(path, (future, future))
    assert eng.match("firewall-aiops", "analyze_table", "db1") is not None


@pytest.mark.unit
def test_hot_reload_on_dir_deletion(patterns_dir):
    _write_pattern(patterns_dir, tool="reindex_table")
    eng = PatternEngine(patterns_dir)
    assert eng.loaded_patterns()
    # Delete the directory then trigger a reload check.
    import shutil

    shutil.rmtree(patterns_dir)
    assert eng.match("firewall-aiops", "reindex_table", "db1") is None
    assert eng.loaded_patterns() == []


@pytest.mark.unit
def test_reset_state_clears_counters(patterns_dir):
    _write_pattern(patterns_dir, tool="reindex_table", per_hour=1)
    eng = PatternEngine(patterns_dir)
    eng.match("firewall-aiops", "reindex_table", "db1")
    assert eng._counters
    eng.reset_state()
    assert eng._counters == {}


@pytest.mark.unit
def test_singleton_identity_and_reset(patterns_dir, monkeypatch, tmp_path):
    monkeypatch.setenv("FIREWALL_AIOPS_HOME", str(tmp_path))
    _write_pattern(tmp_path / "auto-remediation-patterns", tool="reindex_table")
    first = get_pattern_engine()
    assert get_pattern_engine() is first
    reset_pattern_engine()
    assert get_pattern_engine() is not first


@pytest.mark.unit
def test_engine_honors_home_env(monkeypatch, tmp_path):
    monkeypatch.setenv("FIREWALL_AIOPS_HOME", str(tmp_path))
    _write_pattern(tmp_path / "auto-remediation-patterns", tool="reindex_table")
    reset_pattern_engine()
    eng = patterns_mod.get_pattern_engine()
    assert eng.match("firewall-aiops", "reindex_table", "db1").armed is True
