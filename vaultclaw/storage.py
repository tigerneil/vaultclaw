"""File storage for VaultClaw encrypted vault data."""

import json
import os
import stat
from pathlib import Path

from .exceptions import VaultAlreadyExistsError, VaultCorruptedError, VaultNotFoundError

DEFAULT_VAULT_DIR = os.path.join(os.path.expanduser("~"), ".vaultclaw")
DEFAULT_VAULT_FILE = "vault.enc"


def get_vault_path(vault_dir: str | None = None) -> Path:
    """Get the full path to the vault file.

    Args:
        vault_dir: Optional custom vault directory. Defaults to ~/.vaultclaw.

    Returns:
        Path to the vault file.
    """
    directory = Path(vault_dir) if vault_dir else Path(DEFAULT_VAULT_DIR)
    return directory / DEFAULT_VAULT_FILE


def vault_exists(vault_dir: str | None = None) -> bool:
    """Check if a vault file exists."""
    return get_vault_path(vault_dir).exists()


def ensure_vault_dir(vault_dir: str | None = None) -> Path:
    """Create the vault directory with secure permissions if it doesn't exist.

    Returns:
        The vault directory path.
    """
    directory = Path(vault_dir) if vault_dir else Path(DEFAULT_VAULT_DIR)
    if not directory.exists():
        directory.mkdir(parents=True, mode=0o700)
    return directory


def save_vault(vault_data: dict, vault_dir: str | None = None) -> Path:
    """Save encrypted vault data to disk.

    The file is written with restrictive permissions (owner read/write only).

    Args:
        vault_data: The encrypted vault data dict.
        vault_dir: Optional custom vault directory.

    Returns:
        Path to the saved vault file.
    """
    ensure_vault_dir(vault_dir)
    vault_path = get_vault_path(vault_dir)

    # Write to a temp file first, then rename for atomic writes
    tmp_path = vault_path.with_suffix(".tmp")
    try:
        with open(tmp_path, "w") as f:
            json.dump(vault_data, f, indent=2)

        # Set restrictive permissions: owner read/write only
        os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)

        # Atomic rename
        tmp_path.rename(vault_path)
    except Exception:
        # Clean up temp file on failure
        if tmp_path.exists():
            tmp_path.unlink()
        raise

    return vault_path


def load_vault(vault_dir: str | None = None) -> dict:
    """Load encrypted vault data from disk.

    Args:
        vault_dir: Optional custom vault directory.

    Returns:
        The encrypted vault data dict.

    Raises:
        VaultNotFoundError: If no vault file exists.
        VaultCorruptedError: If the vault file is not valid JSON.
    """
    vault_path = get_vault_path(vault_dir)

    if not vault_path.exists():
        raise VaultNotFoundError(
            f"No vault found at {vault_path}. Run 'vaultclaw init' first."
        )

    try:
        with open(vault_path, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise VaultCorruptedError(f"Vault file is corrupted: {e}") from e

    # Basic structure validation
    required_keys = {"version", "salt", "verification_tag", "encrypted"}
    if not required_keys.issubset(data.keys()):
        raise VaultCorruptedError("Vault file is missing required fields.")

    return data


def delete_vault(vault_dir: str | None = None) -> None:
    """Delete the vault file.

    Args:
        vault_dir: Optional custom vault directory.

    Raises:
        VaultNotFoundError: If no vault file exists.
    """
    vault_path = get_vault_path(vault_dir)

    if not vault_path.exists():
        raise VaultNotFoundError(f"No vault found at {vault_path}.")

    vault_path.unlink()
