"""Command-line interface for VaultClaw."""

import argparse
import getpass
import sys

from . import __version__
from .exceptions import VaultClawError
from .vault import Vault


def get_password(prompt: str = "Master password: ") -> str:
    """Securely prompt for a password (no echo)."""
    try:
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(1)


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize a new vault."""
    vault = Vault(vault_dir=args.vault_dir)

    password = get_password("Set master password: ")
    if not password:
        print("Error: Password cannot be empty.", file=sys.stderr)
        return 1

    confirm = get_password("Confirm master password: ")
    if password != confirm:
        print("Error: Passwords do not match.", file=sys.stderr)
        return 1

    path = vault.init(password)
    print(f"Vault created at {path}")
    return 0


def cmd_set(args: argparse.Namespace) -> int:
    """Store a secret."""
    vault = Vault(vault_dir=args.vault_dir)
    password = get_password()

    if args.value is None:
        # Read value from stdin if not provided as argument
        value = get_password("Secret value: ")
    else:
        value = args.value

    was_update = vault.set(password, args.key, value)
    action = "Updated" if was_update else "Stored"
    print(f"{action} secret '{args.key}'.")
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    """Retrieve a secret."""
    vault = Vault(vault_dir=args.vault_dir)
    password = get_password()

    value = vault.get(password, args.key)
    print(value)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """List all secret keys."""
    vault = Vault(vault_dir=args.vault_dir)
    password = get_password()

    keys = vault.list_keys(password)
    if not keys:
        print("Vault is empty.")
    else:
        for key in keys:
            print(f"  {key}")
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    """Delete a secret."""
    vault = Vault(vault_dir=args.vault_dir)
    password = get_password()

    if not args.force:
        confirm = input(f"Delete secret '{args.key}'? [y/N] ")
        if confirm.lower() != "y":
            print("Aborted.")
            return 0

    vault.delete(password, args.key)
    print(f"Deleted secret '{args.key}'.")
    return 0


def cmd_change_password(args: argparse.Namespace) -> int:
    """Change the master password."""
    vault = Vault(vault_dir=args.vault_dir)

    old_password = get_password("Current master password: ")
    new_password = get_password("New master password: ")

    if not new_password:
        print("Error: Password cannot be empty.", file=sys.stderr)
        return 1

    confirm = get_password("Confirm new master password: ")
    if new_password != confirm:
        print("Error: Passwords do not match.", file=sys.stderr)
        return 1

    vault.change_password(old_password, new_password)
    print("Master password changed successfully.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="vaultclaw",
        description="VaultClaw - A secure, open-source secrets vault CLI",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--vault-dir",
        default=None,
        help="Custom vault directory (default: ~/.vaultclaw)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init
    subparsers.add_parser("init", help="Create a new vault")

    # set
    set_parser = subparsers.add_parser("set", help="Store a secret")
    set_parser.add_argument("key", help="The secret key name")
    set_parser.add_argument(
        "value", nargs="?", default=None, help="The secret value (prompted if omitted)"
    )

    # get
    get_parser = subparsers.add_parser("get", help="Retrieve a secret")
    get_parser.add_argument("key", help="The secret key name")

    # list
    subparsers.add_parser("list", help="List all secret keys")

    # delete
    del_parser = subparsers.add_parser("delete", help="Delete a secret")
    del_parser.add_argument("key", help="The secret key name")
    del_parser.add_argument(
        "-f", "--force", action="store_true", help="Skip confirmation"
    )

    # change-password
    subparsers.add_parser("change-password", help="Change the master password")

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    commands = {
        "init": cmd_init,
        "set": cmd_set,
        "get": cmd_get,
        "list": cmd_list,
        "delete": cmd_delete,
        "change-password": cmd_change_password,
    }

    try:
        return commands[args.command](args)
    except VaultClawError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":
    sys.exit(main())
