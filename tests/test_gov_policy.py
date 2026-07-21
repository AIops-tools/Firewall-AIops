"""The policy module is now a risk-tier classifier, not an authorization layer.

Read-only mode, deny rules and the approver gate were all removed: whether a
read or a write is permitted is the agent's decision or the connecting account's
permissions, not the skill's. All that remains is a stateless map from a tool's
declared risk_level to a descriptive tier name carried into the audit row. These
tests pin that it classifies and nothing more — in particular, that it can never
refuse a call.
"""

from __future__ import annotations

import pytest

from firewall_aiops.governance.policy import (
    PolicyEngine,
    get_policy_engine,
    reset_policy_engine,
)


@pytest.fixture(autouse=True)
def _reset():
    reset_policy_engine()
    yield
    reset_policy_engine()


@pytest.mark.unit
def test_risk_level_maps_to_an_audit_tier():
    eng = get_policy_engine()
    assert eng.tier_for("low") == "none"
    assert eng.tier_for("medium") == "confirm"
    assert eng.tier_for("high") == "review"
    assert eng.tier_for("critical") == "review"


@pytest.mark.unit
def test_an_unknown_risk_level_is_tierless_not_an_error():
    assert get_policy_engine().tier_for("whatever") == "none"


@pytest.mark.unit
def test_the_engine_exposes_no_way_to_deny():
    """The authorization surface is gone by construction — a regression here
    would mean gating crept back in."""
    eng = PolicyEngine()
    for gone in ("check_allowed", "required_approval_tier"):
        assert not hasattr(eng, gone), f"{gone} must not exist — the skill does not authorize"


@pytest.mark.unit
def test_reset_rebuilds_the_singleton():
    first = get_policy_engine()
    reset_policy_engine()
    assert get_policy_engine() is not first
