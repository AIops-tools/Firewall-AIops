"""Governance harness — policy engine coverage.

Portable across the whole tool line: references ONLY
``firewall_aiops.governance.policy`` and binds state to an isolated home via
``FIREWALL_AIOPS_HOME``. No ops / cli / connection / mcp_server imports.

Exercises deny-rule matching, operation globs, environment / min-risk scoping,
maintenance windows (in/out/wrap-midnight/malformed → fail-closed), graduated
risk tiers (highest-tier-wins + tag / min-risk matching), tag extraction,
POLICY_DISABLED bypass, hot-reload, and the secure-by-default approver gate.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

import firewall_aiops.governance.policy as policy_mod
from firewall_aiops.governance.policy import (
    PolicyEngine,
    _extract_tags,
    get_policy_engine,
    reset_policy_engine,
    risk_requires_confirmation,
)


@pytest.fixture
def rules_path(tmp_path):
    return tmp_path / "rules.yaml"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("FIREWALL_POLICY_DISABLED", raising=False)
    reset_policy_engine()
    yield
    reset_policy_engine()


def _hhmm(minute: int) -> str:
    minute %= 1440
    return f"{minute // 60:02d}:{minute % 60:02d}"


def _now_minutes() -> int:
    now = datetime.now(tz=UTC)
    return now.hour * 60 + now.minute


# ── risk_requires_confirmation ─────────────────────────────────────────


@pytest.mark.unit
def test_risk_requires_confirmation_levels():
    assert risk_requires_confirmation("critical") is True
    assert risk_requires_confirmation("high") is True
    assert risk_requires_confirmation("medium") is False
    assert risk_requires_confirmation("low") is False


# ── No rules / bypass ──────────────────────────────────────────────────


@pytest.mark.unit
def test_no_rules_file_allows(rules_path):
    eng = PolicyEngine(rules_path)  # file does not exist
    res = eng.check_allowed("drop_index", risk_level="high")
    assert res.allowed is True
    assert res.rule == "no_rules"


@pytest.mark.unit
def test_policy_disabled_bypasses_check(rules_path, monkeypatch):
    rules_path.write_text("deny:\n  - name: block_all\n    operations: ['*']\n", "utf-8")
    monkeypatch.setenv("FIREWALL_POLICY_DISABLED", "1")
    eng = PolicyEngine(rules_path)
    res = eng.check_allowed("drop_index", params={"password": "x"})
    assert res.allowed is True
    assert res.rule == "policy_disabled"


@pytest.mark.unit
def test_policy_disabled_tier_is_none(rules_path, monkeypatch):
    monkeypatch.setenv("FIREWALL_POLICY_DISABLED", "1")
    eng = PolicyEngine(rules_path)
    tier = eng.required_approval_tier("drop_index", risk_level="critical")
    assert tier.tier == "none"
    assert tier.rule == "policy_disabled"


# ── Deny rules ─────────────────────────────────────────────────────────


@pytest.mark.unit
def test_deny_rule_operation_glob(rules_path):
    rules_path.write_text(
        "deny:\n  - name: no_drops\n    operations: ['drop_*']\n"
        "    reason: destructive\n",
        "utf-8",
    )
    eng = PolicyEngine(rules_path)
    denied = eng.check_allowed("drop_index")
    assert denied.allowed is False
    assert denied.rule == "no_drops"
    assert denied.reason == "destructive"
    # A non-matching op passes.
    assert eng.check_allowed("create_index").allowed is True


@pytest.mark.unit
def test_deny_rule_star_matches_all(rules_path):
    rules_path.write_text("deny:\n  - name: block\n    operations: ['*']\n", "utf-8")
    eng = PolicyEngine(rules_path)
    assert eng.check_allowed("anything_at_all").allowed is False


@pytest.mark.unit
def test_deny_operations_absent_matches_all(rules_path):
    # No 'operations' key → rule applies to every operation.
    rules_path.write_text("deny:\n  - name: env_block\n    environments: ['prod']\n", "utf-8")
    eng = PolicyEngine(rules_path)
    assert eng.check_allowed("any_op", env="prod").allowed is False
    # Different env → not denied.
    assert eng.check_allowed("any_op", env="dev").allowed is True


@pytest.mark.unit
def test_deny_operations_empty_matches_nothing(rules_path):
    rules_path.write_text("deny:\n  - name: noop\n    operations: []\n", "utf-8")
    eng = PolicyEngine(rules_path)
    assert eng.check_allowed("drop_index").allowed is True


@pytest.mark.unit
def test_deny_rule_min_risk_level(rules_path):
    rules_path.write_text(
        "deny:\n  - name: high_only\n    min_risk_level: high\n", "utf-8"
    )
    eng = PolicyEngine(rules_path)
    assert eng.check_allowed("op", risk_level="low").allowed is True
    assert eng.check_allowed("op", risk_level="medium").allowed is True
    assert eng.check_allowed("op", risk_level="high").allowed is False
    assert eng.check_allowed("op", risk_level="critical").allowed is False


@pytest.mark.unit
def test_deny_rule_unnamed_default_reason(rules_path):
    rules_path.write_text("deny:\n  - operations: ['drop_*']\n", "utf-8")
    eng = PolicyEngine(rules_path)
    res = eng.check_allowed("drop_index")
    assert res.allowed is False
    assert "unnamed" in res.reason


# ── Maintenance window ─────────────────────────────────────────────────


@pytest.mark.unit
def test_maintenance_window_in_window_allows_high_risk(rules_path):
    rules_path.write_text(
        'maintenance_window:\n  start: "00:00"\n  end: "23:59"\n', "utf-8"
    )
    eng = PolicyEngine(rules_path)
    assert eng.check_allowed("op", risk_level="high").allowed is True


@pytest.mark.unit
def test_maintenance_window_out_of_window_denies_high_risk(rules_path):
    cur = _now_minutes()
    if cur < 1420:
        start, end = _hhmm(cur + 10), _hhmm(cur + 15)
    else:
        start, end = _hhmm(cur - 20), _hhmm(cur - 10)
    rules_path.write_text(
        f'maintenance_window:\n  start: "{start}"\n  end: "{end}"\n', "utf-8"
    )
    eng = PolicyEngine(rules_path)
    res = eng.check_allowed("op", risk_level="high")
    assert res.allowed is False
    assert res.rule == "maintenance_window"


@pytest.mark.unit
def test_maintenance_window_ignored_for_low_risk(rules_path):
    cur = _now_minutes()
    start, end = _hhmm(cur + 10), _hhmm(cur + 15)
    rules_path.write_text(
        f'maintenance_window:\n  start: "{start}"\n  end: "{end}"\n', "utf-8"
    )
    eng = PolicyEngine(rules_path)
    # Low risk is not subject to the window at all.
    assert eng.check_allowed("op", risk_level="low").allowed is True


@pytest.mark.unit
def test_maintenance_window_malformed_fails_closed(rules_path):
    rules_path.write_text(
        'maintenance_window:\n  start: "not-a-time"\n  end: "06:00"\n', "utf-8"
    )
    eng = PolicyEngine(rules_path)
    res = eng.check_allowed("op", risk_level="high")
    assert res.allowed is False
    assert res.rule == "maintenance_window_malformed"


@pytest.mark.unit
def test_in_maintenance_window_full_day_true():
    assert PolicyEngine._in_maintenance_window({"start": "00:00", "end": "23:59"}) is True


@pytest.mark.unit
def test_in_maintenance_window_wrap_always_true():
    # start > end (wrap) where every minute qualifies.
    assert PolicyEngine._in_maintenance_window({"start": "23:59", "end": "23:58"}) is True


@pytest.mark.unit
def test_in_maintenance_window_wrap_false():
    cur = _now_minutes()
    if cur < 5:
        cur = 5
    if cur > 1434:
        cur = 1434
    # Wrap window (start > end) that excludes 'now'.
    window = {"start": _hhmm(cur + 5), "end": _hhmm(cur - 5)}
    assert PolicyEngine._in_maintenance_window(window) is False


# ── change_limits (reserved / warn-only) ───────────────────────────────


@pytest.mark.unit
def test_change_limits_configured_are_not_enforced(rules_path):
    rules_path.write_text("change_limits:\n  max_cpu_pct: 10\n", "utf-8")
    eng = PolicyEngine(rules_path)
    # Limits are warn-only: the call is still allowed.
    res = eng.check_allowed("op", params={"cpu": 99})
    assert res.allowed is True


# ── Risk tiers (graduated autonomy) ────────────────────────────────────


@pytest.mark.unit
def test_default_high_risk_requires_dual_with_no_rules(rules_path):
    eng = PolicyEngine(rules_path)  # no file
    tier = eng.required_approval_tier("drop_index", risk_level="high")
    assert tier.tier == "dual"
    assert tier.rule == "default_high_risk"


@pytest.mark.unit
def test_default_low_risk_no_tier_with_no_rules(rules_path):
    eng = PolicyEngine(rules_path)
    tier = eng.required_approval_tier("read_op", risk_level="low")
    assert tier.tier == "none"
    assert tier.rule == "no_tiers"


@pytest.mark.unit
def test_operator_rules_without_tiers_is_none(rules_path):
    # An explicit operator file (even without risk_tiers) stands down the gate.
    rules_path.write_text("deny: []\n", "utf-8")
    eng = PolicyEngine(rules_path)
    tier = eng.required_approval_tier("drop_index", risk_level="high")
    assert tier.tier == "none"
    assert tier.rule == "no_tiers"


@pytest.mark.unit
def test_risk_tier_operation_and_min_risk_match(rules_path):
    rules_path.write_text(
        "risk_tiers:\n"
        "  - name: drops_need_dual\n    operations: ['drop_*']\n"
        "    min_risk_level: high\n    tier: dual\n",
        "utf-8",
    )
    eng = PolicyEngine(rules_path)
    hit = eng.required_approval_tier("drop_index", risk_level="high")
    assert hit.tier == "dual"
    assert hit.rule == "drops_need_dual"
    # min_risk not met → no match.
    miss = eng.required_approval_tier("drop_index", risk_level="low")
    assert miss.tier == "none"
    # operation glob miss.
    assert eng.required_approval_tier("create_index", risk_level="high").tier == "none"


@pytest.mark.unit
def test_risk_tier_highest_wins(rules_path):
    rules_path.write_text(
        "risk_tiers:\n"
        "  - name: loose\n    operations: ['drop_*']\n    tier: confirm\n"
        "  - name: strict\n    operations: ['drop_*']\n    tier: review\n",
        "utf-8",
    )
    eng = PolicyEngine(rules_path)
    tier = eng.required_approval_tier("drop_index", risk_level="high")
    assert tier.tier == "review"
    assert tier.rule == "strict"


@pytest.mark.unit
def test_risk_tier_invalid_tier_skipped(rules_path):
    rules_path.write_text(
        "risk_tiers:\n  - name: bogus\n    operations: ['*']\n    tier: nonsense\n",
        "utf-8",
    )
    eng = PolicyEngine(rules_path)
    assert eng.required_approval_tier("op", risk_level="high").tier == "none"


@pytest.mark.unit
def test_risk_tier_environment_scoping(rules_path):
    rules_path.write_text(
        "risk_tiers:\n"
        "  - name: prod_only\n    environments: ['prod']\n    tier: dual\n",
        "utf-8",
    )
    eng = PolicyEngine(rules_path)
    assert eng.required_approval_tier("op", env="prod", risk_level="low").tier == "dual"
    # Env mismatch and empty env both fail to match an env-scoped rule.
    assert eng.required_approval_tier("op", env="dev", risk_level="low").tier == "none"
    assert eng.required_approval_tier("op", env="", risk_level="low").tier == "none"


@pytest.mark.unit
def test_risk_tier_tag_matching(rules_path):
    rules_path.write_text(
        "risk_tiers:\n"
        "  - name: pci\n    tags: ['pci']\n    tier: review\n",
        "utf-8",
    )
    eng = PolicyEngine(rules_path)
    hit = eng.required_approval_tier("op", risk_level="low", params={"tags": ["pci", "prod"]})
    assert hit.tier == "review"
    miss = eng.required_approval_tier("op", risk_level="low", params={"tags": ["dev"]})
    assert miss.tier == "none"


# ── Tag extraction ─────────────────────────────────────────────────────


@pytest.mark.unit
def test_extract_tags_all_key_shapes():
    assert _extract_tags(None) == set()
    assert _extract_tags({}) == set()
    assert _extract_tags({"tag": "prod"}) == {"prod"}
    assert _extract_tags({"folder": "staging"}) == {"staging"}
    assert _extract_tags({"tags": ["a", "b"]}) == {"a", "b"}
    assert _extract_tags({"resource_tag": ("x", "y")}) == {"x", "y"}
    merged = _extract_tags({"environment": "prod", "tags": ["pci"]})
    assert merged == {"prod", "pci"}


# ── Hot reload ─────────────────────────────────────────────────────────


@pytest.mark.unit
def test_hot_reload_on_mtime_change(rules_path):
    rules_path.write_text("deny:\n  - name: block\n    operations: ['drop_*']\n", "utf-8")
    eng = PolicyEngine(rules_path)
    assert eng.check_allowed("drop_index").allowed is False
    # Relax the rule and bump mtime.
    rules_path.write_text("deny: []\n", "utf-8")
    future = rules_path.stat().st_mtime + 1000
    os.utime(rules_path, (future, future))
    assert eng.check_allowed("drop_index").allowed is True


@pytest.mark.unit
def test_hot_reload_on_file_deletion(rules_path):
    rules_path.write_text("deny:\n  - name: block\n    operations: ['*']\n", "utf-8")
    eng = PolicyEngine(rules_path)
    assert eng.check_allowed("op").allowed is False
    rules_path.unlink()
    # Deletion clears rules → falls back to no_rules allow.
    res = eng.check_allowed("op")
    assert res.allowed is True
    assert res.rule == "no_rules"


@pytest.mark.unit
def test_malformed_rules_file_loads_empty(rules_path):
    rules_path.write_text("{{ not valid yaml ::::", "utf-8")
    eng = PolicyEngine(rules_path)
    # Parse failure → empty rules → allow (no deny rules).
    assert eng.check_allowed("op").allowed is True


# ── Singleton ──────────────────────────────────────────────────────────


@pytest.mark.unit
def test_singleton_identity_and_rebind_warning(rules_path, tmp_path):
    first = get_policy_engine(rules_path)
    other = tmp_path / "other.yaml"
    # A different path is ignored (warned) — same instance returned.
    assert get_policy_engine(other) is first
    reset_policy_engine()
    assert get_policy_engine(other) is not first


@pytest.mark.unit
def test_singleton_honors_home_env(monkeypatch, tmp_path):
    monkeypatch.setenv("FIREWALL_AIOPS_HOME", str(tmp_path))
    (tmp_path / "rules.yaml").write_text(
        "deny:\n  - name: block\n    operations: ['*']\n", "utf-8"
    )
    reset_policy_engine()
    eng = policy_mod.get_policy_engine()
    assert eng.check_allowed("op").allowed is False
