"""Configuration management for Firewall AIops.

Loads firewall connection targets from a YAML config file. Each target names its
``platform`` — ``opnsense`` (OPNsense REST API) or ``pfsense`` (pfSense REST API
v2) — so one config can span a mixed estate. See :mod:`firewall_aiops.platform`
for how the platform name selects the API shape (auth + resource paths).

The secret is NEVER stored in the config file or in plaintext on disk: it lives
in the encrypted store ``~/.firewall-aiops/secrets.enc`` (see
:mod:`firewall_aiops.secretstore`). For OPNsense the secret is the API **secret**
that pairs with the API **key** (``username``, presented together as HTTP Basic
auth); for pfSense it is the **API key** presented in an ``X-API-Key`` header. A
legacy env var (``FIREWALL_<TARGET>_SECRET``) is honoured as a fallback.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from firewall_aiops.governance.paths import ops_home
from firewall_aiops.platform import OPNSENSE, PLATFORMS, get_platform
from firewall_aiops.secretstore import (
    MasterPasswordError,
    SecretStoreError,
    get_secret,
    has_store,
)

if TYPE_CHECKING:
    from firewall_aiops.platform import Platform

CONFIG_DIR = ops_home()
CONFIG_FILE = CONFIG_DIR / "config.yaml"
ENV_FILE = CONFIG_DIR / ".env"

SECRET_ENV_PREFIX = "FIREWALL_"  # nosec B105 — env-var name, not a secret
SECRET_ENV_SUFFIX = "_SECRET"  # nosec B105 — env-var name, not a secret

_log = logging.getLogger("firewall-aiops.config")


def _secret_env_key(name: str) -> str:
    """Legacy per-target secret env var name, e.g. FIREWALL_FW1_SECRET."""
    return f"{SECRET_ENV_PREFIX}{name.upper().replace('-', '_')}{SECRET_ENV_SUFFIX}"


def _resolve_secret(name: str) -> str:
    """Return a target's secret: encrypted store first, then legacy env var."""
    if has_store():
        try:
            return get_secret(name)
        except MasterPasswordError:
            # A wrong or missing master password is NOT "this target has no
            # secret". Falling through resurfaced it as "No API key for target
            # X", sending the operator to add a credential that is already
            # there. MasterPasswordError subclasses SecretStoreError, so the
            # broad catch below would swallow it — re-raise first.
            raise
        except SecretStoreError:
            pass  # no secret stored for this target — try the legacy env var
    legacy = os.environ.get(_secret_env_key(name))
    if legacy:
        _log.warning(
            "Using plaintext env var %s. Migrate to the encrypted store with "
            "'firewall-aiops secret migrate'.",
            _secret_env_key(name),
        )
        return legacy
    raise OSError(
        f"No secret for target '{name}'. Add one with "
        f"'firewall-aiops secret set {name}' (stored encrypted), or run "
        f"'firewall-aiops init'."
    )


@dataclass(frozen=True)
class TargetConfig:
    """A connection target for one firewall.

    ``platform`` is ``opnsense`` or ``pfsense`` (validated at construction).
    ``username`` holds the OPNsense API **key** (unused for pfSense); the secret
    (OPNsense API secret / pfSense API key) comes from the encrypted store.
    """

    name: str
    platform: str = OPNSENSE
    host: str = ""
    port: int = 0
    username: str = ""
    verify_ssl: bool = True
    scheme: str = "https"
    """Transport scheme — ``https`` (default) or ``http``.

    Defaults to ``https``, so nothing changes for an existing config. It exists
    because a firewall's management GUI is often published on plain HTTP behind
    a reverse proxy that terminates TLS, and the URL was previously hardcoded to
    ``https://`` with no way to override it — which made such an instance simply
    unreachable, with a TLS record-layer error as the only clue.
    """

    def __post_init__(self) -> None:
        if self.platform not in PLATFORMS:
            raise ValueError(
                f"Target '{self.name}': platform must be one of {PLATFORMS}, "
                f"got '{self.platform}'."
            )
        if self.scheme not in ("https", "http"):
            raise ValueError(
                f"Target '{self.name}': scheme must be 'https' or 'http', "
                f"got '{self.scheme}'."
            )
        if not self.port:
            object.__setattr__(self, "port", self.platform_obj.default_port)

    @property
    def platform_obj(self) -> Platform:
        return get_platform(self.platform)

    @property
    def secret(self) -> str:
        return _resolve_secret(self.name)

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


@dataclass(frozen=True)
class AppConfig:
    """Top-level application config."""

    targets: tuple[TargetConfig, ...] = ()

    def get_target(self, name: str) -> TargetConfig:
        for t in self.targets:
            if t.name == name:
                return t
        available = ", ".join(t.name for t in self.targets) or "(none)"
        raise KeyError(f"Target '{name}' not found. Available: {available}")

    @property
    def default_target(self) -> TargetConfig:
        if not self.targets:
            raise ValueError("No targets configured. Check config.yaml")
        return self.targets[0]


def load_config(config_path: Path | None = None) -> AppConfig:
    """Load config from YAML; the secret comes from the encrypted store."""
    path = config_path or CONFIG_FILE
    if not path.exists():
        raise FileNotFoundError(
            f"Config file not found: {path}\n"
            f"Run 'firewall-aiops init' to set up an OPNsense or pfSense target, "
            f"or create {CONFIG_FILE} with a 'targets' list."
        )

    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    targets = tuple(
        TargetConfig(
            name=t["name"],
            platform=t.get("platform", OPNSENSE),
            host=t["host"],
            port=t.get("port", 0),
            username=t.get("username", ""),
            verify_ssl=t.get("verify_ssl", True),
            scheme=t.get("scheme", "https"),
        )
        for t in raw.get("targets", [])
    )

    return AppConfig(targets=targets)
