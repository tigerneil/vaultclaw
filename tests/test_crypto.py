"""Tests for the crypto module."""

import json
import pytest

from vaultclaw.crypto import (
    compute_verification_tag,
    decrypt,
    decrypt_vault_data,
    derive_key,
    encrypt,
    encrypt_vault_data,
    generate_nonce,
    generate_salt,
)
from vaultclaw.exceptions import InvalidPasswordError, VaultCorruptedError


class TestKeyDerivation:
    """Tests for key derivation functions."""

    def test_generate_salt_length(self):
        salt = generate_salt()
        assert len(salt) == 16

    def test_generate_salt_unique(self):
        salt1 = generate_salt()
        salt2 = generate_salt()
        assert salt1 != salt2

    def test_generate_nonce_length(self):
        nonce = generate_nonce()
        assert len(nonce) == 12

    def test_derive_key_deterministic(self):
        salt = b"\x00" * 16
        key1 = derive_key("password", salt)
        key2 = derive_key("password", salt)
        assert key1 == key2

    def test_derive_key_length(self):
        salt = generate_salt()
        key = derive_key("password", salt)
        assert len(key) == 32

    def test_derive_key_different_passwords(self):
        salt = generate_salt()
        key1 = derive_key("password1", salt)
        key2 = derive_key("password2", salt)
        assert key1 != key2

    def test_derive_key_different_salts(self):
        key1 = derive_key("password", b"\x00" * 16)
        key2 = derive_key("password", b"\x01" * 16)
        assert key1 != key2


class TestVerificationTag:
    """Tests for password verification tags."""

    def test_tag_deterministic(self):
        key = b"\x42" * 32
        tag1 = compute_verification_tag(key)
        tag2 = compute_verification_tag(key)
        assert tag1 == tag2

    def test_tag_length(self):
        key = b"\x42" * 32
        tag = compute_verification_tag(key)
        assert len(tag) == 32

    def test_different_keys_different_tags(self):
        tag1 = compute_verification_tag(b"\x00" * 32)
        tag2 = compute_verification_tag(b"\x01" * 32)
        assert tag1 != tag2


class TestEncryptDecrypt:
    """Tests for encrypt/decrypt operations."""

    def test_roundtrip(self):
        key = derive_key("testpass", b"\x00" * 16)
        plaintext = b"hello world"
        encrypted = encrypt(plaintext, key)
        decrypted = decrypt(encrypted, key)
        assert decrypted == plaintext

    def test_roundtrip_empty(self):
        key = derive_key("testpass", b"\x00" * 16)
        plaintext = b""
        encrypted = encrypt(plaintext, key)
        decrypted = decrypt(encrypted, key)
        assert decrypted == plaintext

    def test_roundtrip_large(self):
        key = derive_key("testpass", b"\x00" * 16)
        plaintext = b"A" * 10000
        encrypted = encrypt(plaintext, key)
        decrypted = decrypt(encrypted, key)
        assert decrypted == plaintext

    def test_roundtrip_json(self):
        key = derive_key("testpass", b"\x00" * 16)
        data = {"key": "value", "nested": {"a": 1}}
        plaintext = json.dumps(data).encode()
        encrypted = encrypt(plaintext, key)
        decrypted = decrypt(encrypted, key)
        assert json.loads(decrypted) == data

    def test_encrypted_has_required_fields(self):
        key = derive_key("testpass", b"\x00" * 16)
        encrypted = encrypt(b"data", key)
        assert "nonce" in encrypted
        assert "ciphertext" in encrypted
        assert "tag" in encrypted

    def test_different_encryptions_differ(self):
        """Each encryption should use a different nonce."""
        key = derive_key("testpass", b"\x00" * 16)
        enc1 = encrypt(b"same data", key)
        enc2 = encrypt(b"same data", key)
        assert enc1["nonce"] != enc2["nonce"]
        assert enc1["ciphertext"] != enc2["ciphertext"]

    def test_tampered_ciphertext_detected(self):
        key = derive_key("testpass", b"\x00" * 16)
        encrypted = encrypt(b"secret", key)

        # Tamper with ciphertext
        ct_bytes = bytearray(bytes.fromhex(encrypted["ciphertext"]))
        ct_bytes[0] ^= 0xFF
        encrypted["ciphertext"] = ct_bytes.hex()

        with pytest.raises(VaultCorruptedError):
            decrypt(encrypted, key)

    def test_tampered_tag_detected(self):
        key = derive_key("testpass", b"\x00" * 16)
        encrypted = encrypt(b"secret", key)

        # Tamper with tag
        encrypted["tag"] = "00" * 32

        with pytest.raises(VaultCorruptedError):
            decrypt(encrypted, key)

    def test_wrong_key_fails(self):
        key1 = derive_key("pass1", b"\x00" * 16)
        key2 = derive_key("pass2", b"\x00" * 16)
        encrypted = encrypt(b"secret", key1)

        with pytest.raises(VaultCorruptedError):
            decrypt(encrypted, key2)


class TestVaultDataEncryption:
    """Tests for high-level vault data encrypt/decrypt."""

    def test_roundtrip(self):
        secrets = {"api_key": {"value": "sk-123"}, "db_pass": {"value": "pg_secret"}}
        encrypted = encrypt_vault_data(secrets, "master-password")
        decrypted = decrypt_vault_data(encrypted, "master-password")
        assert decrypted == secrets

    def test_wrong_password(self):
        secrets = {"key": {"value": "val"}}
        encrypted = encrypt_vault_data(secrets, "correct")
        with pytest.raises(InvalidPasswordError):
            decrypt_vault_data(encrypted, "wrong")

    def test_vault_data_structure(self):
        encrypted = encrypt_vault_data({}, "pass")
        assert encrypted["version"] == 1
        assert "salt" in encrypted
        assert "verification_tag" in encrypted
        assert "encrypted" in encrypted
        assert "nonce" in encrypted["encrypted"]
        assert "ciphertext" in encrypted["encrypted"]
        assert "tag" in encrypted["encrypted"]
