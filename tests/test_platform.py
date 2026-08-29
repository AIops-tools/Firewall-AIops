"""Platform registry + connection wiring (OPNsense + pfSense), config dispatch.

No real firewall is needed — the httpx client is injected. Proves the registry
maps each platform name to its API shape, path templates format, list payloads
unwrap across both response conventions, and the connection sends the right auth
(Basic for OPNsense, header key for pfSense) and translates errors.
"""

import httpx
import pytest

from firewall_aiops.config import TargetConfig
from firewall_aiops.connection import FirewallApiError, FirewallConnection
from firewall_aiops.platform import (
    OPNSENSE,
    PFSENSE,
    get_platform,
    platform_names,
)


@pytest.mark.unit
def test_both_platforms_registered():
    assert set(platform_names()) == {OPNSENSE, PFSENSE}
    assert get_platform(OPNSENSE).uses_basic_auth
    assert not get_platform(PFSENSE).uses_basic_auth


@pytest.mark.unit
def test_unknown_platform_raises_with_registered_names():
    with pytest.raises(ValueError, match="opnsense"):
        get_platform("smoothwall")


@pytest.mark.unit
def test_path_templates_differ_per_platform():
    op = get_platform(OPNSENSE)
    pf = get_platform(PFSENSE)
    assert op.path("rules_search") == "/api/firewall/filter/searchRule"
    assert pf.path("rules_search") == "/api/v2/firewall/rules"
    assert op.path("rule_get", uuid="abc").endswith("/getRule/abc")
    assert "id=abc" in pf.path("rule_get", uuid="abc")


@pytest.mark.unit
def test_unmapped_resource_raises_teaching_keyerror():
    with pytest.raises(KeyError, match="not mapped"):
        get_platform(OPNSENSE).path("does_not_exist")


@pytest.mark.unit
def test_rows_unwraps_both_conventions_and_bare_array():
    op = get_platform(OPNSENSE)
    assert op.rows({"rows": [{"a": 1}, {"a": 2}]}) == [{"a": 1}, {"a": 2}]
    assert op.rows({"data": [{"b": 3}]}) == [{"b": 3}]
    assert op.rows([{"c": 4}]) == [{"c": 4}]
    assert op.rows({"nope": 1}) == []


@pytest.mark.unit
def test_rows_sanitizes_strings():
    out = get_platform(PFSENSE).rows({"data": [{"x": "ok", "n": 5}]})
    assert out[0]["x"] == "ok" and out[0]["n"] == 5


class _Resp:
    def __init__(self, status, payload=None, content=b"{}"):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.content = content
        self.text = "body"

    def json(self):
        return self._payload


@pytest.mark.unit
def test_opnsense_uses_basic_auth(monkeypatch):
    monkeypatch.setenv("FIREWALL_FW1_SECRET", "s3cr3t")
    target = TargetConfig(name="fw1", platform=OPNSENSE, host="fw.local",
                          username="key1", verify_ssl=False)
    captured = {}

    class _Client:
        def request(self, method, path, **k):
            return _Resp(200, {"rows": [{"uuid": "1"}]})

        def close(self):
            pass

    # Build a real httpx client to confirm the auth object is Basic.
    auth = FirewallConnection._build_auth(target)
    assert isinstance(auth, httpx.BasicAuth)
    headers = FirewallConnection._build_headers(target)
    assert "X-API-Key" not in headers  # basic auth, not header key

    conn = FirewallConnection(target, client=_Client())
    assert conn.get(conn.platform.path("rules_search"))["rows"][0]["uuid"] == "1"
    assert captured == {}


@pytest.mark.unit
def test_pfsense_uses_header_key(monkeypatch):
    monkeypatch.setenv("FIREWALL_FW2_SECRET", "apikey-xyz")
    target = TargetConfig(name="fw2", platform=PFSENSE, host="pf.local", verify_ssl=False)
    assert FirewallConnection._build_auth(target) is None
    headers = FirewallConnection._build_headers(target)
    assert headers["X-API-Key"] == "apikey-xyz"


@pytest.mark.unit
def test_connection_translates_non_2xx(monkeypatch):
    monkeypatch.setenv("FIREWALL_FW1_SECRET", "s")
    target = TargetConfig(name="fw1", platform=OPNSENSE, host="h", username="k")

    class _Client:
        def request(self, method, path, **k):
            return _Resp(404, content=b"x")

        def close(self):
            pass

    conn = FirewallConnection(target, client=_Client())
    with pytest.raises(FirewallApiError) as ei:
        conn.get("/api/x")
    assert ei.value.status_code == 404
    assert "not found" in str(ei.value).lower()


@pytest.mark.unit
def test_config_rejects_bad_platform_and_defaults_port():
    with pytest.raises(ValueError):
        TargetConfig(name="x", platform="smoothwall", host="h")
    op = TargetConfig(name="o", platform=OPNSENSE, host="h")
    assert op.port == 443
    pf = TargetConfig(name="p", platform=PFSENSE, host="h")
    assert pf.port == 443
    assert op.base_url == "https://h:443"


# ── URL-encoding of agent-supplied path segments ─────────────────────────────


@pytest.mark.unit
def test_path_traversal_ids_are_url_encoded():
    """An id carrying ``../`` must not reach the HTTP client as a raw path
    traversal — every substituted value is URL-encoded in Platform.path()."""
    opn = get_platform(OPNSENSE)
    path = opn.path("rule_get", uuid="../../core/system/reboot")
    assert "../" not in path
    assert path.startswith("/api/firewall/filter/getRule/")

    pf = get_platform(PFSENSE)
    path = pf.path("alias_uuid", name="x&admin=1?y=../z")
    assert "../" not in path and "&admin" not in path


# ── endpoints proven absent on a live pfSense ────────────────────────────────


@pytest.mark.unit
def test_pfsense_registry_avoids_endpoints_no_pfsense_serves():
    """These paths 404 on a real pfSense and are in NO published API schema.

    They shipped for months, so the whole VPN status surface, the whole state
    table (including the ``kill_states`` write) and service restart never worked
    on pfSense — each failure surfacing as "that subsystem is not installed"
    rather than "this tool is calling a URL that does not exist". Checked live
    against pfSense CE 2.7.2 + pfSense-pkg-RESTAPI 2.4_3, and cross-checked
    against the package's own OpenAPI schema at both 2.4.3 and 2.10.2.

    The assertion is structural rather than a list of the current values, so a
    future edit that reaches for one of these names fails here instead of in
    somebody's firewall.
    """
    never_served = {
        "/api/v2/diagnostics/states",
        "/api/v2/status/wireguard",
        "/api/v2/status/openvpn",
        "/api/v2/status/ipsec",
        "/api/v2/services/{service}/restart",
    }
    offenders = {
        key: template
        for key, template in get_platform(PFSENSE).paths.items()
        if template.split("?")[0] in never_served
    }
    assert not offenders, f"pfSense path registry uses non-existent endpoints: {offenders}"


@pytest.mark.unit
def test_pfsense_singular_objects_are_never_addressed_by_name():
    """pfSense answers ``MODEL_REQUIRES_ID`` to a singular URL filtered by name.

    Filtering belongs on the *plural* endpoint (``/aliases?name=x``), which does
    honour it. A singular path carrying ``{name}`` can therefore never succeed.
    """
    # Named explicitly rather than guessed from the URL: "alias" is singular and
    # ends in "s", so any plural-by-suffix heuristic passes it and the check
    # silently tests nothing. A singular endpoint may be selected by ``id`` (that
    # is what pfSense asks for) but never by ``name``.
    singular_requiring_id = {
        "/api/v2/firewall/alias",
        "/api/v2/firewall/rule",
        "/api/v2/status/service",
        "/api/v2/services/dhcp_server/static_mapping",
    }
    by_name = {
        key: template
        for key, template in get_platform(PFSENSE).paths.items()
        if template.split("?")[0] in singular_requiring_id and "name=" in template
    }
    assert not by_name, f"singular pfSense paths filtered by name always 400: {by_name}"
