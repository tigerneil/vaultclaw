"""Core vault logic for VaultClaw."""

from datetime import datetime, timezone

from .crypto import decrypt_vault_data, encrypt_vault_data
from .exceptions import (
    SecretNotFoundError,
    VaultAlreadyExistsError,
    VaultNotFoundError,
)
from .storage import load_vault, save_vault, vault_exists


class Vault:
    """A secure secrets vault.

    The vault stores key-value pairs encrypted on disk. A master password
    is required for all operations.
    """

    def __init__(self, vault_dir: str | None = None):
        """Initialize vault manager.

        Args:
            vault_dir: Optional custom vault directory.
        """
        self.vault_dir = vault_dir

    def init(self, password: str) -> str:
        """Create a new vault with the given master password.

        Args:
            password: The master password for the vault.

        Returns:
            Path to the created vault file.

        Raises:
            VaultAlreadyExistsError: If a vault already exists.
        """
        if vault_exists(self.vault_dir):
            raise VaultAlreadyExistsError(
                "A vault already exists. Delete it first or use a different directory."
            )

        secrets_dict = {
            "_metadata": {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "version": 1,
            },
        }

        vault_data = encrypt_vault_data(secrets_dict, password)
        path = save_vault(vault_data, self.vault_dir)
        return str(path)

    def get(self, password: str, key: str) -> str:
        """Retrieve a secret by key.

        Args:
            password: The master password.
            key: The secret key to look up.

        Returns:
            The secret value.

        Raises:
            SecretNotFoundError: If the key doesn't exist.
            InvalidPasswordError: If the password is wrong.
        """
        secrets_dict = self._load_secrets(password)

        if key not in secrets_dict or key == "_metadata":
            raise SecretNotFoundError(f"Secret '{key}' not found in vault.")

        return secrets_dict[key]["value"]

    def set(self, password: str, key: str, value: str) -> bool:
        """Store or update a secret.

        Args:
            password: The master password.
            key: The secret key.
            value: The secret value.

        Returns:
            True if the key was updated, False if it was newly created.
        """
        if key == "_metadata":
            raise ValueError("'_metadata' is a reserved key.")

        secrets_dict = self._load_secrets(password)
        is_update = key in secrets_dict

        secrets_dict[key] = {
            "value": value,
            "created_at": (
                secrets_dict[key]["created_at"]
                if is_update
                else datetime.now(timezone.utc).isoformat()
            ),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

        self._save_secrets(secrets_dict, password)
        return is_update

    def delete(self, password: str, key: str) -> None:
        """Delete a secret.

        Args:
            password: The master password.
            key: The secret key to delete.

        Raises:
            SecretNotFoundError: If the key doesn't exist.
        """
        secrets_dict = self._load_secrets(password)

        if key not in secrets_dict or key == "_metadata":
            raise SecretNotFoundError(f"Secret '{key}' not found in vault.")

        del secrets_dict[key]
        self._save_secrets(secrets_dict, password)

    def list_keys(self, password: str) -> list[str]:
        """List all secret keys in the vault.

        Args:
            password: The master password.

        Returns:
            A sorted list of secret key names.
        """
        secrets_dict = self._load_secrets(password)
        return sorted(k for k in secrets_dict if k != "_metadata")

    def change_password(self, old_password: str, new_password: str) -> None:
        """Change the vault master password.

        Decrypts with the old password and re-encrypts with the new one.

        Args:
            old_password: The current master password.
            new_password: The new master password.
        """
        secrets_dict = self._load_secrets(old_password)
        self._save_secrets(secrets_dict, new_password)

    def _load_secrets(self, password: str) -> dict:
        """Load and decrypt the secrets dictionary."""
        vault_data = load_vault(self.vault_dir)
        return decrypt_vault_data(vault_data, password)

    def _save_secrets(self, secrets_dict: dict, password: str) -> None:
        """Encrypt and save the secrets dictionary."""
        vault_data = encrypt_vault_data(secrets_dict, password)
        save_vault(vault_data, self.vault_dir)
