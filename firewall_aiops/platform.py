"""Platform descriptors — the firewalls firewall-aiops speaks to.

firewall-aiops is multi-platform by construction. A registry maps a *platform
name* to a :class:`Platform` descriptor that captures everything the connection
and ops layers need to talk to that firewall: how it authenticates, the concrete
REST path for each *logical resource*, and how a raw response is normalised
(injection-safe). Because OPNsense and pfSense expose the same firewall concepts
behind very different URLs and auth schemes, the ops modules ask the platform
for a path (``conn.platform.path("rules")``) and for the row list of a payload
(``conn.platform.rows(payload)``) instead of hard-coding either — so the same
tool works on both.

v0.1 registers two platforms:

  * **opnsense** — OPNsense REST API (``/api/...``) with the API *key+secret*
    presented as HTTP Basic auth.
  * **pfsense** — pfSense REST API v2 (``/api/v2/...``, the pfSense-pkg-RESTAPI
    package) with the API key presented in an ``X-API-Key`` header.

Additional firewalls can ``register`` their own descriptor later without
touching the ops / CLI / MCP layers — a registry keyed by ``platform`` name.

The concrete REST paths below are modelled from each project's public API and
are exercised against mocked HTTP responses only; see the README's preview note.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from firewall_aiops.governance import sanitize


def _seg(value: Any) -> str:
    """URL-encode one path/query value so agent-supplied identifiers (rule
    uuids, alias names, service names) cannot smuggle ``/``, ``../`` or query
    metacharacters into the request URL."""
    return quote(str(value), safe="")

# ─── registered platform names ──────────────────────────────────────────────
OPNSENSE = "opnsense"
PFSENSE = "pfsense"
PLATFORMS = (OPNSENSE, PFSENSE)

# Auth styles.
AUTH_BASIC = "basic"  # HTTP Basic: key as user, secret as password (OPNsense)
AUTH_HEADER_KEY = "header-key"  # X-API-Key: <key> (pfSense REST v2)

# Bounds for the response normaliser (defensive against a hostile firewall).
_MAX_STR = 512
_MAX_DEPTH = 8

# Keys under which each platform wraps a list payload, tried in order before
# falling back to a bare JSON array.
_LIST_KEYS = ("rows", "data", "results", "items")


def _sanitize_obj(obj: Any, depth: int = 0) -> Any:
    """Recursively fold firewall-returned JSON into injection-safe values.

    Every string leaf passes through ``sanitize`` (bounded length); numbers,
    booleans and ``None`` pass through unchanged. Depth is capped so a
    pathological nesting cannot exhaust the stack.
    """
    if depth > _MAX_DEPTH:
        return None
    if isinstance(obj, dict):
        return {str(k): _sanitize_obj(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize_obj(v, depth + 1) for v in obj]
    if isinstance(obj, str):
        return sanitize(obj, _MAX_STR)
    return obj


@dataclass(frozen=True)
class Platform:
    """A firewall's API shape: auth style + logical-resource path map + normaliser."""

    name: str
    label: str
    auth_style: str
    default_port: int
    paths: dict[str, str] = field(default_factory=dict)
    api_key_header: str = "X-API-Key"

    @property
    def uses_basic_auth(self) -> bool:
        return self.auth_style == AUTH_BASIC

    def path(self, resource: str, **fmt: Any) -> str:
        """Return the concrete REST path for a logical ``resource``.

        Raises a teaching ``KeyError`` when the resource is not mapped for this
        platform (so a caller asking for an unsupported surface fails fast with
        the list of what *is* available, rather than hitting a confusing 404).

        Every substituted value is URL-encoded (``quote(..., safe="")``) so an
        agent-supplied identifier can never rewrite the path (e.g. via ``../``).
        """
        try:
            template = self.paths[resource]
        except KeyError as exc:
            available = ", ".join(sorted(self.paths)) or "(none)"
            raise KeyError(
                f"Resource '{resource}' is not mapped for platform '{self.name}'. "
                f"Mapped resources: {available}."
            ) from exc
        if not fmt:
            return template
        return template.format(**{k: _seg(v) for k, v in fmt.items()})

    def supports(self, resource: str) -> bool:
        return resource in self.paths

    def rows(self, payload: Any) -> list[dict]:
        """Normalise a list payload to a sanitised list of dict rows.

        A bare JSON array passes through; a dict is unwrapped via the first of
        ``rows``/``data``/``results``/``items`` that is present. Every row is run
        through the injection-safe normaliser.
        """
        if isinstance(payload, dict):
            items: Any = []
            for key in _LIST_KEYS:
                value = payload.get(key)
                if isinstance(value, list):
                    items = value
                    break
        else:
            items = payload
        return [_sanitize_obj(r) for r in (items or []) if isinstance(r, dict)]

    def normalise(self, payload: Any) -> Any:
        """Return an injection-safe copy of a raw response payload."""
        return _sanitize_obj(payload)


# ─── registry ───────────────────────────────────────────────────────────────
_REGISTRY: dict[str, Platform] = {}


def register(platform: Platform) -> None:
    """Register a platform descriptor under its name (idempotent overwrite)."""
    _REGISTRY[platform.name] = platform


def get_platform(name: str) -> Platform:
    """Return the descriptor for ``name`` or raise with the registered names."""
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        available = ", ".join(sorted(_REGISTRY)) or "(none)"
        raise ValueError(
            f"Unknown platform '{name}'. Registered platforms: {available}."
        ) from exc


def platform_names() -> tuple[str, ...]:
    """All registered platform names (sorted)."""
    return tuple(sorted(_REGISTRY))


# ─── OPNsense (REST /api/..., HTTP Basic key+secret) ─────────────────────────
_OPNSENSE_PATHS = {
    # system
    "firmware": "/api/core/firmware/status",
    "system_info": "/api/diagnostics/system/systemInformation",
    "interfaces": "/api/diagnostics/interface/getInterfaceNames",
    "interface_config": "/api/diagnostics/interface/getInterfaceConfig",
    "gateways": "/api/routes/gateway/status",
    # rules
    "rules_search": "/api/firewall/filter/searchRule",
    "rule_get": "/api/firewall/filter/getRule/{uuid}",
    "rule_toggle": "/api/firewall/filter/toggleRule/{uuid}/{enabled}",
    "rule_stats": "/api/diagnostics/firewall/pfStatistics",
    "rule_states": "/api/diagnostics/firewall/queryStates",
    # nat
    "nat_port_forward": "/api/firewall/nat/rule/search",
    "nat_outbound": "/api/firewall/source_nat/rule/search",
    "nat_one_to_one": "/api/firewall/one_to_one/rule/search",
    # aliases
    "aliases_search": "/api/firewall/alias/searchItem",
    "alias_uuid": "/api/firewall/alias/getAliasUUID/{name}",
    "alias_entries": "/api/firewall/alias_util/list/{name}",
    "alias_add": "/api/firewall/alias_util/add/{name}",
    "alias_delete": "/api/firewall/alias_util/delete/{name}",
    # vpn
    "wireguard": "/api/wireguard/service/show",
    "openvpn": "/api/openvpn/service/searchSessions",
    "ipsec": "/api/ipsec/sessions/searchPhase1",
    # dhcp
    "dhcp_leases": "/api/dhcpv4/leases/searchLease",
    "dhcp_static": "/api/dhcpv4/settings/searchStaticMap",
    # diag / traffic
    "firewall_log": "/api/diagnostics/firewall/log",
    "states": "/api/diagnostics/firewall/queryStates",
    "kill_states": "/api/diagnostics/firewall/killStates",
    "top_talkers": "/api/diagnostics/firewall/queryStates",
    # writes / apply
    "apply": "/api/firewall/filter/apply",
    "reconfigure": "/api/firewall/filter/savepoint",
    "service_restart": "/api/core/service/restart/{service}",
    "reboot": "/api/core/system/reboot",
}

# ─── pfSense (REST v2 /api/v2/..., X-API-Key header) ─────────────────────────
_PFSENSE_PATHS = {
    # system
    "firmware": "/api/v2/system/version",
    "system_info": "/api/v2/status/system",
    "interfaces": "/api/v2/status/interfaces",
    "interface_config": "/api/v2/status/interfaces",
    "gateways": "/api/v2/status/gateways",
    # rules
    "rules_search": "/api/v2/firewall/rules",
    "rule_get": "/api/v2/firewall/rule?id={uuid}",
    "rule_toggle": "/api/v2/firewall/rule",
    "rule_stats": "/api/v2/firewall/rules",
    "rule_states": "/api/v2/diagnostics/states",
    # nat
    "nat_port_forward": "/api/v2/firewall/nat/port_forwards",
    "nat_outbound": "/api/v2/firewall/nat/outbound/mappings",
    "nat_one_to_one": "/api/v2/firewall/nat/one_to_one/mappings",
    # aliases
    "aliases_search": "/api/v2/firewall/aliases",
    "alias_uuid": "/api/v2/firewall/alias?name={name}",
    "alias_entries": "/api/v2/firewall/alias?name={name}",
    "alias_add": "/api/v2/firewall/alias",
    "alias_delete": "/api/v2/firewall/alias",
    # vpn
    "wireguard": "/api/v2/status/wireguard",
    "openvpn": "/api/v2/status/openvpn",
    "ipsec": "/api/v2/status/ipsec",
    # dhcp
    "dhcp_leases": "/api/v2/status/dhcp_server/leases",
    "dhcp_static": "/api/v2/services/dhcp_server/static_mappings",
    # diag / traffic
    "firewall_log": "/api/v2/status/logs/firewall",
    "states": "/api/v2/diagnostics/states",
    "kill_states": "/api/v2/diagnostics/states",
    "top_talkers": "/api/v2/diagnostics/states",
    # writes / apply
    "apply": "/api/v2/firewall/apply",
    "reconfigure": "/api/v2/firewall/apply",
    "service_restart": "/api/v2/services/{service}/restart",
    "reboot": "/api/v2/diagnostics/reboot",
}


register(
    Platform(
        name=OPNSENSE,
        label="OPNsense REST API",
        auth_style=AUTH_BASIC,
        default_port=443,
        paths=_OPNSENSE_PATHS,
    )
)
register(
    Platform(
        name=PFSENSE,
        label="pfSense REST API v2",
        auth_style=AUTH_HEADER_KEY,
        default_port=443,
        paths=_PFSENSE_PATHS,
    )
)


__all__ = [
    "OPNSENSE",
    "PFSENSE",
    "PLATFORMS",
    "AUTH_BASIC",
    "AUTH_HEADER_KEY",
    "Platform",
    "register",
    "get_platform",
    "platform_names",
]
