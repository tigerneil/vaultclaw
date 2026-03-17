"""Tests for the vault and storage modules."""

import json
import os
import tempfile

import pytest

from vaultclaw.exceptions import (
    InvalidPasswordError,
    SecretNotFoundError,
    VaultAlreadyExistsError,
    VaultCorruptedError,
    VaultNotFoundError,
)
from vaultclaw.storage import load_vault, save_vault, vault_exists
from vaultclaw.vault import Vault


@pytest.fixture
def vault_dir():
    """Provide a temporary directory for vault storage."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def initialized_vault(vault_dir):
    """Provide an initialized vault."""
    vault = Vault(vault_dir=vault_dir)
    vault.init("test-password")
    return vault, vault_dir, "test-password"


class TestStorage:
    """Tests for storage layer."""

    def test_vault_not_exists(self, vault_dir):
        assert not vault_exists(vault_dir)

    def test_vault_exists_after_save(self, vault_dir):
        data = {"version": 1, "salt": "aa", "verification_tag": "bb", "encrypted": {}}
        save_vault(data, vault_dir)
        assert vault_exists(vault_dir)

    def test_save_and_load_roundtrip(self, vault_dir):
        data = {
            "version": 1,
            "salt": "aabb",
            "verification_tag": "ccdd",
            "encrypted": {"nonce": "00", "ciphertext": "11", "tag": "22"},
        }
        save_vault(data, vault_dir)
        loaded = load_vault(vault_dir)
        assert loaded == data

    def test_load_nonexistent_raises(self, vault_dir):
        with pytest.raises(VaultNotFoundError):
            load_vault(vault_dir)

    def test_load_corrupted_json(self, vault_dir):
        vault_path = os.path.join(vault_dir, "vault.enc")
        with open(vault_path, "w") as f:
            f.write("not json{{{")
        with pytest.raises(VaultCorruptedError):
            load_vault(vault_dir)

    def test_load_missing_fields(self, vault_dir):
        vault_path = os.path.join(vault_dir, "vault.enc")
        with open(vault_path, "w") as f:
            json.dump({"version": 1}, f)
        with pytest.raises(VaultCorruptedError):
            load_vault(vault_dir)

    def test_file_permissions(self, vault_dir):
        data = {"version": 1, "salt": "aa", "verification_tag": "bb", "encrypted": {}}
        path = save_vault(data, vault_dir)
        mode = oct(os.stat(path).st_mode & 0o777)
        assert mode == "0o600"


class TestVaultInit:
    """Tests for vault initialization."""

    def test_init_creates_vault(self, vault_dir):
        vault = Vault(vault_dir=vault_dir)
        path = vault.init("my-password")
        assert os.path.exists(path)

    def test_init_already_exists(self, vault_dir):
        vault = Vault(vault_dir=vault_dir)
        vault.init("password")
        with pytest.raises(VaultAlreadyExistsError):
            vault.init("password")


class TestVaultOperations:
    """Tests for vault CRUD operations."""

    def test_set_and_get(self, initialized_vault):
        vault, _, password = initialized_vault
        vault.set(password, "api_key", "sk-12345")
        value = vault.get(password, "api_key")
        assert value == "sk-12345"

    def test_set_update(self, initialized_vault):
        vault, _, password = initialized_vault
        was_update = vault.set(password, "key", "v1")
        assert was_update is False
        was_update = vault.set(password, "key", "v2")
        assert was_update is True
        assert vault.get(password, "key") == "v2"

    def test_get_nonexistent(self, initialized_vault):
        vault, _, password = initialized_vault
        with pytest.raises(SecretNotFoundError):
            vault.get(password, "nonexistent")

    def test_get_wrong_password(self, initialized_vault):
        vault, _, password = initialized_vault
        vault.set(password, "key", "value")
        with pytest.raises(InvalidPasswordError):
            vault.get("wrong-password", "key")

    def test_delete(self, initialized_vault):
        vault, _, password = initialized_vault
        vault.set(password, "key", "value")
        vault.delete(password, "key")
        with pytest.raises(SecretNotFoundError):
            vault.get(password, "key")

    def test_delete_nonexistent(self, initialized_vault):
        vault, _, password = initialized_vault
        with pytest.raises(SecretNotFoundError):
            vault.delete(password, "nonexistent")

    def test_list_empty(self, initialized_vault):
        vault, _, password = initialized_vault
        keys = vault.list_keys(password)
        assert keys == []

    def test_list_keys(self, initialized_vault):
        vault, _, password = initialized_vault
        vault.set(password, "zebra", "z")
        vault.set(password, "alpha", "a")
        vault.set(password, "middle", "m")
        keys = vault.list_keys(password)
        assert keys == ["alpha", "middle", "zebra"]

    def test_reserved_key_metadata(self, initialized_vault):
        vault, _, password = initialized_vault
        with pytest.raises(ValueError):
            vault.set(password, "_metadata", "bad")

    def test_change_password(self, initialized_vault):
        vault, _, password = initialized_vault
        vault.set(password, "key", "value")
        vault.change_password(password, "new-password")

        # Old password should fail
        with pytest.raises(InvalidPasswordError):
            vault.get(password, "key")

        # New password should work
        assert vault.get("new-password", "key") == "value"

    def test_multiple_secrets(self, initialized_vault):
        vault, _, password = initialized_vault
        secrets = {f"key_{i}": f"value_{i}" for i in range(20)}
        for k, v in secrets.items():
            vault.set(password, k, v)

        for k, v in secrets.items():
            assert vault.get(password, k) == v

    def test_special_characters_in_values(self, initialized_vault):
        vault, _, password = initialized_vault
        special = 'p@$$w0rd!#%^&*(){}[]|\\:";\'<>?,./~`'
        vault.set(password, "special", special)
        assert vault.get(password, "special") == special

    def test_unicode_values(self, initialized_vault):
        vault, _, password = initialized_vault
        vault.set(password, "emoji", "🔐🗝️🔒")
        assert vault.get(password, "emoji") == "🔐🗝️🔒"
