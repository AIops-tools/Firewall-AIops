"""Unit tests for the three flagship analyses (pure functions, no I/O)."""

import pytest

from firewall_aiops.ops import analysis as ops


@pytest.mark.unit
def test_gateway_health_rca_ranks_down_first_and_classifies():
    gateways = [
        {"name": "healthy", "status": "none", "lossPercent": 0, "rttMs": 8},
        {"name": "lossy", "status": "none", "lossPercent": 12, "rttMs": 20},
        {"name": "dead", "status": "down", "lossPercent": 100, "rttMs": 0},
    ]
    out = ops.gateway_health_rca(gateways)
    assert out["gatewaysEvaluated"] == 3
    assert out["downCount"] == 1
    assert out["worst"][0]["name"] == "dead" and out["worst"][0]["down"] is True
    # the lossy one is degraded with a last-mile-loss cause
    lossy = next(g for g in out["worst"] if g["name"] == "lossy")
    assert lossy["degraded"] is True and "loss" in lossy["cause"].lower()


@pytest.mark.unit
def test_gateway_health_rca_healthy_needs_no_action():
    out = ops.gateway_health_rca([{"name": "ok", "status": "none", "lossPercent": 0, "rttMs": 5}])
    assert out["degradedCount"] == 0
    assert out["worst"][0]["action"] == "No action needed."


@pytest.mark.unit
def test_rule_shadow_analysis_flags_unused_shadowed_redundant():
    rules = [
        # broad terminating block on wan → shadows the later specific pass
        {"uuid": "block-all", "enabled": True, "action": "block", "interface": "wan",
         "protocol": "any", "source": "any", "destination": "any",
         "destinationPort": "", "evaluations": 500},
        {"uuid": "allow-web", "enabled": True, "action": "pass", "interface": "wan",
         "protocol": "tcp", "source": "any", "destination": "any",
         "destinationPort": "443", "evaluations": 0},
        # exact duplicate of allow-web → redundant
        {"uuid": "allow-web-dup", "enabled": True, "action": "pass", "interface": "wan",
         "protocol": "tcp", "source": "any", "destination": "any",
         "destinationPort": "443", "evaluations": 3},
    ]
    out = ops.rule_hit_and_shadow_analysis(rules)
    unused = {r["uuid"] for r in out["unusedRules"]}
    shadowed = {r["uuid"] for r in out["shadowedRules"]}
    redundant = {r["uuid"] for r in out["redundantRules"]}
    assert "allow-web" in unused  # evaluations == 0
    assert "allow-web" in shadowed  # covered by block-all
    assert "allow-web-dup" in redundant  # same sig as allow-web
    assert out["shadowedRules"][0]["shadowedBy"] == "block-all"


@pytest.mark.unit
def test_rule_shadow_analysis_ignores_disabled_rules():
    rules = [
        {"uuid": "d", "enabled": False, "action": "block", "interface": "wan",
         "protocol": "any", "source": "any", "destination": "any",
         "destinationPort": "", "evaluations": 0},
    ]
    out = ops.rule_hit_and_shadow_analysis(rules)
    assert out["unusedCount"] == 0 and out["shadowedCount"] == 0


@pytest.mark.unit
def test_blocked_traffic_rca_detects_scan_and_service_probe():
    scan = [
        {"action": "block", "source": "9.9.9.9", "destinationPort": str(p)}
        for p in range(1, 15)
    ]
    brute = [
        {"action": "block", "source": "8.8.8.8", "destinationPort": "22"}
        for _ in range(30)
    ]
    passes = [{"action": "pass", "source": "10.0.0.1", "destinationPort": "443"}]
    out = ops.blocked_traffic_rca(scan + brute + passes)
    assert out["blocksEvaluated"] == len(scan) + len(brute)
    assert out["distinctSources"] == 2
    top = {t["source"]: t for t in out["topSources"]}
    # scanner has many distinct ports
    assert "scan" in top["9.9.9.9"]["cause"].lower()
    # brute-forcer concentrated on SSH (port 22)
    assert "SSH" in top["8.8.8.8"]["cause"] and top["8.8.8.8"]["topPort"] == "22"


@pytest.mark.unit
def test_blocked_traffic_rca_empty():
    out = ops.blocked_traffic_rca([])
    assert out["blocksEvaluated"] == 0 and out["topSources"] == []
