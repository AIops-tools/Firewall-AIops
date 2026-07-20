"""A firewall GUI behind a TLS-terminating proxy is plain HTTP; don't hardcode.

Same defect monitoring-aiops hit on a live Zabbix: base_url was built as
`https://{host}:{port}` with no override, so an http-only instance was simply
unreachable — the only clue being a TLS record-layer error.
"""

from __future__ import annotations

import pytest

from firewall_aiops import config
from firewall_aiops.config import TargetConfig
from firewall_aiops.platform import OPNSENSE, PFSENSE


@pytest.mark.unit
def test_scheme_defaults_to_https_so_existing_configs_are_unchanged():
    t = TargetConfig(name="fw1", platform=OPNSENSE, host="h", port=443)
    assert t.scheme == "https"
    assert t.base_url == "https://h:443"


@pytest.mark.unit
def test_scheme_http_is_honoured():
    t = TargetConfig(name="fw1", platform=OPNSENSE, host="h", port=8080, scheme="http")
    assert t.base_url == "http://h:8080"


@pytest.mark.unit
def test_invalid_scheme_is_rejected_at_construction():
    with pytest.raises(ValueError, match="scheme must be 'https' or 'http'"):
        TargetConfig(name="fw1", platform=OPNSENSE, host="h", scheme="ftp")


@pytest.mark.unit
def test_load_config_reads_scheme_and_defaults_it_to_https(tmp_path):
    """The loader carries the knob through, and a target that omits it keeps
    https — proving a config written before this field still behaves as before."""
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        "targets:\n"
        "  - name: fw1\n    platform: opnsense\n    host: h1\n    scheme: http\n"
        "  - name: edge\n    platform: pfsense\n    host: h2\n"
    )
    cfg = config.load_config(cfg_file)
    assert cfg.targets[0].scheme == "http"
    assert cfg.targets[0].base_url.startswith("http://h1:")
    assert cfg.targets[1].scheme == "https"
    assert cfg.targets[1].base_url.startswith("https://h2:")
    assert cfg.targets[1].platform == PFSENSE
