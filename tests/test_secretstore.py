"""Tests for the encrypted secret store.

These tests redirect the store at the module's path constants to a tmp dir so
nothing touches the real ``~/.firewall-aiops``.
"""

from __future__ import annotations

import importlib

import pytest

import firewall_aiops.secretstore as ss


@pytest.fixture
def store_dir(tmp_path, monkeypatch):
    """Point the secret store at a throwaway directory."""
    monkeypatch.setattr(ss, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(ss, "SECRETS_FILE", tmp_path / "secrets.enc")
    monkeypatch.setattr(ss, "LEGACY_ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(ss, "_cached", None)
    return tmp_path


def test_roundtrip_set_get(store_dir):
    store = ss.SecretStore.unlock("master-pw")
    store = store.set("nas1", "p@ssw0rd-123")
    reopened = ss.SecretStore.unlock("master-pw")
    assert reopened.get("nas1") == "p@ssw0rd-123"


def test_value_not_plaintext_on_disk(store_dir):
    ss.SecretStore.unlock("master-pw").set("nas1", "super-secret-value")
    blob = (store_dir / "secrets.enc").read_text()
    assert "super-secret-value" not in blob
    assert "ciphertext" in blob


def test_wrong_password_rejected(store_dir):
    ss.SecretStore.unlock("right-pw").set("t", "v")
    with pytest.raises(ss.MasterPasswordError):
        ss.SecretStore.unlock("wrong-pw")


def test_immutability_returns_new_store(store_dir):
    s1 = ss.SecretStore.unlock("pw")
    s2 = s1.set("a", "1")
    assert s1.names() == ()
    assert s2.names() == ("a",)


def test_delete(store_dir):
    store = ss.SecretStore.unlock("pw").set("a", "1").set("b", "2")
    store = store.delete("a")
    assert store.names() == ("b",)
    with pytest.raises(ss.SecretStoreError):
        store.get("a")


def test_file_permissions_are_owner_only(store_dir):
    ss.SecretStore.unlock("pw").set("a", "1")
    mode = (store_dir / "secrets.enc").stat().st_mode & 0o777
    assert mode == 0o600


def test_rotate_password(store_dir):
    ss.SecretStore.unlock("old").set("a", "1")
    ss.SecretStore.unlock("old").with_password("new")
    assert ss.SecretStore.unlock("new").get("a") == "1"
    with pytest.raises(ss.MasterPasswordError):
        ss.SecretStore.unlock("old")


def test_migrate_legacy_env(store_dir):
    (store_dir / ".env").write_text(
        "FIREWALL_FW1_SECRET=legacy-pass\n# comment\nFOO=bar\n"
    )
    imported = ss.migrate_legacy_env("FIREWALL_", "_SECRET", "pw")
    assert imported == ["fw1"]
    assert ss.SecretStore.unlock("pw").get("fw1") == "legacy-pass"
    assert not (store_dir / ".env").exists()
    assert (store_dir / ".env.migrated").exists()


def test_empty_value_rejected(store_dir):
    with pytest.raises(ss.SecretStoreError):
        ss.SecretStore.unlock("pw").set("a", "")


def test_missing_secret_message_lists_available(store_dir):
    store = ss.SecretStore.unlock("pw").set("known", "1")
    with pytest.raises(ss.SecretStoreError, match="known"):
        store.get("unknown")


def test_module_reimport_clean(store_dir):
    # Guard: re-importing must not blow up (side-effect-free import).
    importlib.reload(ss)
