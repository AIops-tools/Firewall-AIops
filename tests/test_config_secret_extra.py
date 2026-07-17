"""Config resolution + secret-store branches + the ``secret`` CLI commands.

The secret store is redirected at a tmp dir (never the real ~/.firewall-aiops)
and the master password comes from the env var so nothing prompts.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

import firewall_aiops.secretstore as ss
from firewall_aiops import config
from firewall_aiops.config import AppConfig, TargetConfig
from firewall_aiops.platform import OPNSENSE


@pytest.fixture
def store_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(ss, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(ss, "SECRETS_FILE", tmp_path / "secrets.enc")
    monkeypatch.setattr(ss, "LEGACY_ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(ss, "_cached", None)
    return tmp_path


# ── config: target lookup + secret resolution ────────────────────────────────


@pytest.mark.unit
def test_get_target_not_found_lists_available():
    cfg = AppConfig(targets=(TargetConfig(name="a", platform=OPNSENSE, host="h"),))
    assert cfg.get_target("a").name == "a"
    with pytest.raises(KeyError, match="Available: a"):
        cfg.get_target("missing")


@pytest.mark.unit
def test_default_target_empty_raises():
    with pytest.raises(ValueError, match="No targets configured"):
        AppConfig().default_target


@pytest.mark.unit
def test_load_config_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError, match="init"):
        config.load_config(tmp_path / "nope.yaml")


@pytest.mark.unit
def test_load_config_parses_targets(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        "targets:\n"
        "  - name: fw1\n    platform: opnsense\n    host: h1\n    username: k\n"
        "  - name: fw2\n    platform: pfsense\n    host: h2\n    verify_ssl: false\n"
    )
    cfg = config.load_config(cfg_file)
    assert [t.name for t in cfg.targets] == ["fw1", "fw2"]
    assert cfg.targets[1].verify_ssl is False


@pytest.mark.unit
def test_resolve_secret_env_key_shape():
    assert config._secret_env_key("my-fw") == "FIREWALL_MY_FW_SECRET"


@pytest.mark.unit
def test_resolve_secret_legacy_env_fallback(monkeypatch, store_dir):
    # no encrypted store present → falls back to the legacy env var
    monkeypatch.setenv("FIREWALL_FW1_SECRET", "legacy")
    assert config._resolve_secret("fw1") == "legacy"


@pytest.mark.unit
def test_resolve_secret_missing_raises(monkeypatch, store_dir):
    monkeypatch.delenv("FIREWALL_FW1_SECRET", raising=False)
    with pytest.raises(OSError, match="No secret for target"):
        config._resolve_secret("fw1")


# ── secretstore: uncovered branches ──────────────────────────────────────────


@pytest.mark.unit
def test_resolve_master_password_from_env(monkeypatch):
    monkeypatch.setenv(ss.MASTER_PASSWORD_ENV, "envpw")
    assert ss.resolve_master_password() == "envpw"


@pytest.mark.unit
def test_resolve_master_password_non_tty_raises(monkeypatch):
    monkeypatch.delenv(ss.MASTER_PASSWORD_ENV, raising=False)
    monkeypatch.setattr(ss.sys.stdin, "isatty", lambda: False)
    with pytest.raises(ss.MasterPasswordError, match="Master password not set"):
        ss.resolve_master_password()


@pytest.mark.unit
def test_open_store_explicit_password_not_cached(store_dir):
    ss.SecretStore.unlock("pw").set("a", "1")
    s1 = ss.open_store("pw")  # explicit pw is never served from cache
    s2 = ss.open_store("pw")
    assert s1 is not s2 and s1.names() == s2.names()


@pytest.mark.unit
def test_open_store_cache_used_when_no_password(store_dir, monkeypatch):
    monkeypatch.setenv(ss.MASTER_PASSWORD_ENV, "pw")
    ss.SecretStore.unlock("pw").set("a", "1")
    monkeypatch.setattr(ss, "_cached", None)
    first = ss.open_store()
    second = ss.open_store()
    assert first is second  # cached for the process


@pytest.mark.unit
def test_contains_and_delete_missing(store_dir):
    store = ss.SecretStore.unlock("pw").set("a", "1")
    assert "a" in store and "b" not in store
    with pytest.raises(ss.SecretStoreError, match="No secret named 'b'"):
        store.delete("b")


@pytest.mark.unit
def test_with_password_empty_rejected(store_dir):
    store = ss.SecretStore.unlock("pw")
    with pytest.raises(ss.SecretStoreError, match="must not be empty"):
        store.with_password("")


@pytest.mark.unit
def test_has_store_and_check_permissions(store_dir):
    assert ss.has_store() is False
    assert ss.check_permissions() is None
    ss.SecretStore.unlock("pw").set("a", "1")
    assert ss.has_store() is True
    # freshly written store is 600 → no warning
    assert ss.check_permissions() is None
    (store_dir / "secrets.enc").chmod(0o644)
    warn = ss.check_permissions()
    assert warn and "chmod 600" in warn


@pytest.mark.unit
def test_migrate_no_legacy_file_returns_empty(store_dir):
    assert ss.migrate_legacy_env("FIREWALL_", "_SECRET", "pw") == []


# ── the `secret` CLI commands ────────────────────────────────────────────────


@pytest.fixture
def secret_cli(store_dir, monkeypatch):
    monkeypatch.setenv(ss.MASTER_PASSWORD_ENV, "clipw")
    from firewall_aiops.cli import app

    return app, store_dir


@pytest.mark.unit
def test_cli_secret_set_list_rm(secret_cli):
    app, _ = secret_cli
    runner = CliRunner()

    r = runner.invoke(app, ["secret", "set", "fw1", "--value", "k3y"])
    assert r.exit_code == 0, r.output
    assert "Stored encrypted API key" in r.output

    r = runner.invoke(app, ["secret", "list"])
    assert r.exit_code == 0 and "fw1" in r.output

    r = runner.invoke(app, ["secret", "rm", "fw1"])
    assert r.exit_code == 0 and "Deleted" in r.output

    r = runner.invoke(app, ["secret", "list"])
    assert "No secrets stored yet" in r.output


@pytest.mark.unit
def test_cli_secret_migrate(secret_cli, store_dir):
    app, _ = secret_cli
    (store_dir / ".env").write_text("FIREWALL_FW1_SECRET=legacy\n")
    r = CliRunner().invoke(app, ["secret", "migrate"])
    assert r.exit_code == 0
    assert "Imported 1 secret" in r.output and "fw1" in r.output


@pytest.mark.unit
def test_cli_secret_migrate_nothing(secret_cli):
    app, _ = secret_cli
    r = CliRunner().invoke(app, ["secret", "migrate"])
    assert r.exit_code == 0 and "Nothing to migrate" in r.output


@pytest.mark.unit
def test_cli_secret_rotate_password(secret_cli, monkeypatch):
    app, _ = secret_cli
    from firewall_aiops.cli import secret as secret_mod

    CliRunner().invoke(app, ["secret", "set", "fw1", "--value", "k"])
    # rotate prompts for new + confirm via getpass
    monkeypatch.setattr(secret_mod.getpass, "getpass", lambda *a, **k: "newpw")
    r = CliRunner().invoke(app, ["secret", "rotate-password"])
    assert r.exit_code == 0 and "rotated" in r.output.lower()


@pytest.mark.unit
def test_cli_secret_rotate_password_mismatch(secret_cli, monkeypatch):
    app, _ = secret_cli
    from firewall_aiops.cli import secret as secret_mod

    CliRunner().invoke(app, ["secret", "set", "fw1", "--value", "k"])
    answers = iter(["newpw", "different"])
    monkeypatch.setattr(secret_mod.getpass, "getpass", lambda *a, **k: next(answers))
    r = CliRunner().invoke(app, ["secret", "rotate-password"])
    assert r.exit_code == 1 and "did not match" in r.output.lower()
