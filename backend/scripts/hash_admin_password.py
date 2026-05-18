#!/usr/bin/env python3
"""Generate a bcrypt hash for ADMIN_PASSWORD_HASH.

Usage:
  python backend/scripts/hash_admin_password.py
    -> prompts for password (no echo) and prints the hash.

  python backend/scripts/hash_admin_password.py 'my-pass'
    -> hashes the argument (avoid in shell history).

Paste the printed value into backend/.env as:
  ADMIN_USERNAME=<your username>
  ADMIN_PASSWORD_HASH=<the printed hash, single-quoted>
"""
import getpass
import sys

import bcrypt


def main() -> int:
    if len(sys.argv) > 2:
        print("Usage: hash_admin_password.py [password]", file=sys.stderr)
        return 2
    if len(sys.argv) == 2:
        password = sys.argv[1]
    else:
        password = getpass.getpass("Admin password: ")
        confirm = getpass.getpass("Confirm:         ")
        if password != confirm:
            print("Passwords do not match.", file=sys.stderr)
            return 1
    if not password:
        print("Password must not be empty.", file=sys.stderr)
        return 1

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
    print(hashed)
    print("\nAdd to backend/.env:", file=sys.stderr)
    print("  ADMIN_USERNAME=<your username>", file=sys.stderr)
    print(f"  ADMIN_PASSWORD_HASH='{hashed}'", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
