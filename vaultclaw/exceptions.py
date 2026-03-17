"""Custom exceptions for VaultClaw."""


class VaultClawError(Exception):
    """Base exception for VaultClaw."""


class VaultNotFoundError(VaultClawError):
    """Raised when the vault file does not exist."""


class VaultAlreadyExistsError(VaultClawError):
    """Raised when trying to initialize a vault that already exists."""


class VaultLockedError(VaultClawError):
    """Raised when trying to operate on a locked vault."""


class InvalidPasswordError(VaultClawError):
    """Raised when the master password is incorrect."""


class SecretNotFoundError(VaultClawError):
    """Raised when a requested secret key does not exist."""


class VaultCorruptedError(VaultClawError):
    """Raised when the vault data is corrupted or tampered with."""
