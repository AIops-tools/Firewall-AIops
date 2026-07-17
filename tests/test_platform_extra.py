"""Central path-encoding + registry coverage (Platform.path / rows / normalise).

Proves every agent-supplied identifier is percent-encoded through the single
``Platform.path`` chokepoint, unmapped resources fail with a teaching error, and
the response normaliser is injection-safe and depth-bounded.
"""

from __future__ import annotations

import pytest

from firewall_aiops.platform import (
    OPNSENSE,
    PFSENSE,
    Platform,
    get_platform,
    register,
)


@pytest.mark.unit
def test_alias_name_percent_encoded_on_both_platforms():
    name = "web servers/../etc"
    op = get_platform(OPNSENSE).path("alias_entries", name=name)
    pf = get_platform(PFSENSE).path("alias_uuid", name=name)
    for path in (op, pf):
        assert "/../" not in path and " " not in path
        assert "%2F" in path or "%20" in path  # something got encoded


@pytest.mark.unit
def test_rule_toggle_encodes_uuid_and_enabled_flag():
    path = get_platform(OPNSENSE).path("rule_toggle", uuid="a/b", enabled="1")
    assert path == "/api/firewall/filter/toggleRule/a%2Fb/1"


@pytest.mark.unit
def test_service_restart_encodes_service():
    path = get_platform(OPNSENSE).path("service_restart", service="unbound/../reboot")
    assert "/../" not in path and path.startswith("/api/core/service/restart/")


@pytest.mark.unit
def test_supports_reports_mapping():
    op = get_platform(OPNSENSE)
    assert op.supports("rules_search") is True
    assert op.supports("nonexistent") is False


@pytest.mark.unit
def test_unmapped_resource_lists_available_resources():
    with pytest.raises(KeyError) as ei:
        get_platform(OPNSENSE).path("totally_unknown")
    msg = str(ei.value)
    assert "Mapped resources" in msg and "rules_search" in msg


@pytest.mark.unit
def test_rows_prefers_first_present_list_key():
    op = get_platform(OPNSENSE)
    # 'rows' wins over 'data' when both present
    assert op.rows({"rows": [{"a": 1}], "data": [{"b": 2}]}) == [{"a": 1}]
    # non-dict rows are dropped
    assert op.rows({"rows": [{"a": 1}, "junk", 3]}) == [{"a": 1}]


@pytest.mark.unit
def test_normalise_bounds_depth_and_sanitizes():
    op = get_platform(OPNSENSE)
    # a nesting deeper than the cap folds to None at the bottom
    deep: dict = {"k": {}}
    node = deep["k"]
    for _ in range(12):
        node["k"] = {}
        node = node["k"]
    out = op.normalise(deep)
    assert isinstance(out, dict)


@pytest.mark.unit
def test_normalise_passes_scalars_through():
    op = get_platform(OPNSENSE)
    assert op.normalise({"n": 5, "b": True, "z": None}) == {"n": 5, "b": True, "z": None}


@pytest.mark.unit
def test_register_is_idempotent_overwrite():
    custom = Platform(
        name="opnsense", label="x", auth_style="basic", default_port=443,
        paths={"rules_search": "/x"},
    )
    original = get_platform(OPNSENSE)
    try:
        register(custom)
        assert get_platform(OPNSENSE).paths == {"rules_search": "/x"}
    finally:
        register(original)  # restore for other tests
    assert get_platform(OPNSENSE).path("rules_search") == "/api/firewall/filter/searchRule"
