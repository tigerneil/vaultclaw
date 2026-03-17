# VaultClaw 🔐

A secure, open-source secrets vault CLI. Store and manage sensitive credentials locally with strong encryption.

## Security

- **Encryption:** HMAC-SHA256 stream cipher with Encrypt-then-MAC (HMAC-SHA256 authentication)
- **Key Derivation:** PBKDF2-HMAC-SHA256 with 600,000 iterations
- **Random Salt:** 16-byte per vault, 12-byte nonce per encryption
- **File Permissions:** Vault files are stored with `0600` (owner read/write only)
- **Atomic Writes:** Vault saves use temp file + rename to prevent corruption
- **No Plaintext on Disk:** All secrets are encrypted at rest

## Installation

```bash
pip install -e .
```

## Quick Start

```bash
# Create a new vault
vaultclaw init

# Store a secret
vaultclaw set api_key sk-your-secret-key

# Store a secret interactively (value not shown)
vaultclaw set db_password

# Retrieve a secret
vaultclaw get api_key

# List all stored keys
vaultclaw list

# Delete a secret
vaultclaw delete api_key

# Change master password
vaultclaw change-password
```

## Commands

| Command | Description |
|---------|-------------|
| `vaultclaw init` | Create a new encrypted vault |
| `vaultclaw set <key> [value]` | Store or update a secret |
| `vaultclaw get <key>` | Retrieve a secret value |
| `vaultclaw list` | List all secret key names |
| `vaultclaw delete <key>` | Delete a secret |
| `vaultclaw change-password` | Change the master password |

## Options

- `--vault-dir PATH` — Use a custom vault directory (default: `~/.vaultclaw`)
- `--version` — Show version info
- `-f, --force` — Skip delete confirmation

## Storage

The vault is stored at `~/.vaultclaw/vault.enc` as an encrypted JSON file. The file contains:

- Version identifier
- Random salt for key derivation
- Password verification tag (HMAC)
- Encrypted payload (nonce + ciphertext + authentication tag)

## Development

```bash
# Install in development mode
pip install -e .

# Run tests
pip install pytest
pytest
```

## License

MIT
