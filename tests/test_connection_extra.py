"""Connection-layer coverage: central HTTP-error translation (401/400/500/…),
all verbs, empty/invalid bodies, transport-failure teaching message, and the
ConnectionManager session-reuse / disconnect lifecycle. The httpx client is
injected — no live firewall is contacted.
"""

from __future__ import annotations

import httpx
import pytest

from firewall_aiops.config import AppConfig, TargetConfig
from firewall_aiops.connection import (
    ConnectionManager,
    FirewallApiError,
    FirewallConnection,
)
from firewall_aiops.platform import OPNSENSE, PFSENSE


class _Resp:
    def __init__(self, status, payload=None, content=b"{}", text="body"):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.content = content
        self.text = text

    def json(self):
        if self._payload == "__invalid__":
            raise ValueError("no json")
        return self._payload


class _Client:
    """Records the last request and replays a queued response (or raises)."""

    def __init__(self, resp=None, raise_exc=None):
        self._resp = resp
        self._raise = raise_exc
        self.calls: list[tuple] = []
        self.closed = False

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        if self._raise is not None:
            raise self._raise
        return self._resp

    def close(self):
        self.closed = True


def _conn(client, platform=OPNSENSE):
    target = TargetConfig(name="fw", platform=platform, host="h", username="k")
    return FirewallConnection(target, client=client)


# ── error translation per status ─────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.parametrize(
    "status,needle",
    [
        (401, "authentication/authorization failed"),
        (403, "authentication/authorization failed"),
        (404, "not found"),
        (400, "bad request"),
        (500, "server error"),
        (503, "server error"),
        (418, "api error"),
    ],
)
def test_teaching_message_per_status(status, needle):
    conn = _conn(_Client(_Resp(status, content=b"x", text="detail")))
    with pytest.raises(FirewallApiError) as ei:
        conn.get("/api/x")
    assert needle in str(ei.value).lower()
    assert ei.value.status_code == status


@pytest.mark.unit
def test_transport_error_becomes_teaching_apierror():
    conn = _conn(_Client(raise_exc=httpx.ConnectError("refused")))
    with pytest.raises(FirewallApiError) as ei:
        conn.get("/api/x")
    assert "could not reach" in str(ei.value).lower()
    assert ei.value.status_code is None


# ── body handling ────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_empty_body_returns_empty_dict():
    conn = _conn(_Client(_Resp(204, content=b"")))
    assert conn.get("/api/x") == {}


@pytest.mark.unit
def test_invalid_json_body_returns_empty_dict():
    conn = _conn(_Client(_Resp(200, payload="__invalid__", content=b"notjson")))
    assert conn.get("/api/x") == {}


@pytest.mark.unit
def test_all_verbs_dispatch_the_right_method():
    client = _Client(_Resp(200, {"ok": True}))
    conn = _conn(client)
    conn.get("/g")
    conn.post("/p", json={"a": 1})
    conn.put("/pu")
    conn.patch("/pa")
    conn.delete("/d")
    methods = [c[0] for c in client.calls]
    assert methods == ["GET", "POST", "PUT", "PATCH", "DELETE"]
    # kwargs pass through to the client
    assert client.calls[1][2]["json"] == {"a": 1}


@pytest.mark.unit
def test_close_closes_underlying_client():
    client = _Client(_Resp(200))
    conn = _conn(client)
    conn.close()
    assert client.closed is True


# ── auth wiring ──────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_pfsense_header_key_and_no_basic(monkeypatch):
    monkeypatch.setenv("FIREWALL_FW_SECRET", "apikey")
    target = TargetConfig(name="fw", platform=PFSENSE, host="h")
    assert FirewallConnection._build_auth(target) is None
    headers = FirewallConnection._build_headers(target)
    assert headers["X-API-Key"] == "apikey"
    assert headers["Accept"] == "application/json"


@pytest.mark.unit
def test_no_global_content_type_header(monkeypatch):
    """Regression (live-found on real OPNsense 26.7, 2026-08-01): a global
    Content-Type: application/json makes OPNsense json-decode the empty body of
    every bodyless GET, failing with 400 "Invalid JSON syntax". httpx sets the
    header per-request when a call passes json=, so it must NOT be a default."""
    monkeypatch.setenv("FIREWALL_FW_SECRET", "s")
    for plat in (OPNSENSE, PFSENSE):
        target = TargetConfig(name="fw", platform=plat, host="h", username="k")
        headers = FirewallConnection._build_headers(target)
        assert "Content-Type" not in headers, f"{plat}: no default Content-Type"


# ── ConnectionManager lifecycle ──────────────────────────────────────────────


def _cfg():
    return AppConfig(targets=(
        TargetConfig(name="a", platform=OPNSENSE, host="h1", username="k"),
        TargetConfig(name="b", platform=PFSENSE, host="h2"),
    ))


@pytest.mark.unit
def test_manager_reuses_session_and_lists(monkeypatch):
    # Avoid building a real httpx client: inject a fake at connect time.
    import firewall_aiops.connection as connmod

    fake = _Client(_Resp(200))
    monkeypatch.setattr(
        connmod, "FirewallConnection",
        lambda target, client=None: FirewallConnection(target, client=fake),
    )
    mgr = ConnectionManager(_cfg())
    assert mgr.list_targets() == ["a", "b"]

    c1 = mgr.connect("a")
    c2 = mgr.connect("a")
    assert c1 is c2  # cached / reused
    assert mgr.list_connected() == ["a"]

    # default target is the first when no name is given
    cdef = mgr.connect()
    assert cdef.target.name == "a"


@pytest.mark.unit
def test_manager_disconnect_and_disconnect_all(monkeypatch):
    import firewall_aiops.connection as connmod

    monkeypatch.setattr(
        connmod, "FirewallConnection",
        lambda target, client=None: FirewallConnection(target, client=_Client(_Resp(200))),
    )
    mgr = ConnectionManager(_cfg())
    mgr.connect("a")
    mgr.connect("b")
    assert set(mgr.list_connected()) == {"a", "b"}
    mgr.disconnect("a")
    assert mgr.list_connected() == ["b"]
    mgr.disconnect_all()
    assert mgr.list_connected() == []
    # disconnecting an unknown name is a no-op
    mgr.disconnect("nope")


@pytest.mark.unit
def test_manager_from_config_uses_loader(monkeypatch):
    import firewall_aiops.connection as connmod

    monkeypatch.setattr(connmod, "load_config", lambda: _cfg())
    mgr = ConnectionManager.from_config()
    assert mgr.list_targets() == ["a", "b"]
