import sys

from . import PasswordVault

vault = PasswordVault()
sys.exit(vault.cmdloop())