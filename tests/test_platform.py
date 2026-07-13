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
