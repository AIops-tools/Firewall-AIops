"""Tests for the ``firewall-aiops init`` onboarding wizard.

The wizard is driven end-to-end through Typer's CliRunner with every path
(config.yaml, secrets.enc) isolated under tmp_path. The master password comes
from FIREWALL_AIOPS_MASTER_PASSWORD (the non-interactive path) and the hidden
API-secret prompt is patched at the getpass boundary.
"""

from __future__ import annotations

import getpass as getpass_mod

import pytest
import yaml
from typer.testing import CliRunner

import firewall_aiops.cli.init as init_mod
import firewall_aiops.config as config_mod
import firewall_aiops.doctor as doctor_mod
import firewall_aiops.secretstore as ss

MASTER_PW = "init-master-pw"
API_SECRET = "fw-api-secret-0123"

# Wizard answers: name, accept platform default (opnsense), host, accept default
# port, accept TLS-verify default (True), OPNsense API key, no second target,
# decline the trailing doctor run. The API secret itself comes via getpass.
WIZARD_INPUT = "fw1\n\nfw.example.com\n\n\nopnsense-key\nn\nn\n"


@pytest.fixture
def init_home(tmp_path, monkeypatch):
    """Isolate config + secret store + governance home under tmp_path."""
    config_file = tmp_path / "config.yaml"
    secrets_file = tmp_path / "secrets.enc"
    monkeypatch.setenv("FIREWALL_AIOPS_HOME", str(tmp_path))
    monkeypatch.setenv("FIREWALL_AIOPS_MASTER_PASSWORD", MASTER_PW)
    monkeypatch.setattr(init_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(init_mod, "CONFIG_FILE", config_file)
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "CONFIG_FILE", config_file)
    monkeypatch.setattr(ss, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(ss, "SECRETS_FILE", secrets_file)
    monkeypatch.setattr(ss, "LEGACY_ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(ss, "_cached", None)
    # The hidden API-secret prompt bypasses CliRunner stdin.
    monkeypatch.setattr(getpass_mod, "getpass", lambda prompt="": API_SECRET)
    return tmp_path


def _run_init(input_text: str = WIZARD_INPUT):
    from firewall_aiops.cli import app

    return CliRunner().invoke(app, ["init"], input=input_text)


@pytest.mark.unit
def test_init_writes_config_with_entered_values(init_home):
    result = _run_init()
    assert result.exit_code == 0, result.output
    raw = yaml.safe_load((init_home / "config.yaml").read_text("utf-8"))
    assert raw["targets"] == [
        {
            "name": "fw1",
            "platform": "opnsense",
            "host": "fw.example.com",
            "port": 443,
            "username": "opnsense-key",
            "verify_ssl": True,  # accepted TLS confirm default=True must land
        }
    ]


@pytest.mark.unit
def test_init_tls_confirm_can_be_declined_for_lab_certs(init_home):
    result = _run_init("fw1\n\nfw.example.com\n\nn\nopnsense-key\nn\nn\n")
    assert result.exit_code == 0, result.output
    raw = yaml.safe_load((init_home / "config.yaml").read_text("utf-8"))
    assert raw["targets"][0]["verify_ssl"] is False


@pytest.mark.unit
def test_init_pfsense_branch_skips_username_prompt(init_home):
    result = _run_init("fw2\npfsense\nfw2.example.com\n\n\nn\nn\n")
    assert result.exit_code == 0, result.output
    raw = yaml.safe_load((init_home / "config.yaml").read_text("utf-8"))
    assert raw["targets"][0]["platform"] == "pfsense"
    assert raw["targets"][0]["username"] == ""  # pfSense uses only the API key secret
    assert ss.SecretStore.unlock(MASTER_PW).get("fw2") == API_SECRET


@pytest.mark.unit
def test_init_rejects_unknown_platform_then_reprompts(init_home):
    result = _run_init("fw1\njunos\nfw1\n\nfw.example.com\n\n\nopnsense-key\nn\nn\n")
    assert result.exit_code == 0, result.output
    assert "Platform must be 'opnsense' or 'pfsense'." in result.output
    raw = yaml.safe_load((init_home / "config.yaml").read_text("utf-8"))
    assert [t["name"] for t in raw["targets"]] == ["fw1"]


@pytest.mark.unit
def test_init_stores_secret_encrypted_not_in_config(init_home):
    result = _run_init()
    assert result.exit_code == 0, result.output
    # API secret is readable back through the secret store API...
    assert ss.SecretStore.unlock(MASTER_PW).get("fw1") == API_SECRET
    # ...and never lands in plaintext in config.yaml or secrets.enc.
    assert API_SECRET not in (init_home / "config.yaml").read_text("utf-8")
    assert API_SECRET not in (init_home / "secrets.enc").read_text("utf-8")


@pytest.mark.unit
def test_init_writes_no_policy_rules(init_home):
    """The skill no longer authorizes, so init seeds no rules.yaml — a fresh
    install delivers full functionality and leaves permission to the account."""
    result = _run_init()
    assert result.exit_code == 0, result.output
    assert not (init_home / "rules.yaml").exists()


@pytest.mark.unit
def test_init_accepting_doctor_confirm_runs_doctor(init_home, monkeypatch):
    calls: list[bool] = []
    monkeypatch.setattr(doctor_mod, "run_doctor", lambda: calls.append(True) or 0)
    # Empty last answer accepts the confirm's default=True.
    result = _run_init("fw1\n\nfw.example.com\n\n\nopnsense-key\nn\n\n")
    assert result.exit_code == 0, result.output
    assert calls == [True]


@pytest.mark.unit
def test_init_overwrite_existing_target(init_home):
    result = _run_init()
    assert result.exit_code == 0, result.output
    # Same name again: confirm overwrite, new host, accept defaults.
    result = _run_init("fw1\ny\n\nfw-new.example.com\n\n\nopnsense-key\nn\nn\n")
    assert result.exit_code == 0, result.output
    raw = yaml.safe_load((init_home / "config.yaml").read_text("utf-8"))
    assert [t["host"] for t in raw["targets"]] == ["fw-new.example.com"]
