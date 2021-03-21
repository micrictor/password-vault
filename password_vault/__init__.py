#!/usr/bin/env python3
import getpass
import io
import sys

from typing import Dict

import argparse
import cmd2

from password_vault.crypto import derive_from_password, EncryptedVault, HashedPassword

class PasswordVault(cmd2.Cmd):
    """The command-line interface for our password vault.
    Includes the following commands:
        1. `load` - Load a password-vault file. Will prompt for a password
        2. `create` - Create a new password-vault file. Will prompt for a password.
        3. `save` - Saves all changes made in a session to the created or loaded file
        4. `set-password` - Given a web host, prompts for and saves a password.
        5. `get-password` - Given a web host, return the password for it.
    """
    vault_file_name: str
    vault_database: Dict[str, str]
    vault_password: HashedPassword

    GET_SET_CATEGORY: str = "Get/Set Passwords"

    def __init__(self):
        super().__init__(self)
        self.completekey = "Tab"
        self.prompt = "vault > "
        self.do_exit = self.do_quit
        self.register_postloop_hook(self.exithook)
        self.disable_category(self.GET_SET_CATEGORY, "Must create or load database first")

    def _get_vault_password(self) -> HashedPassword:
        password = ""
        password = getpass.getpass("Password for the vault...")
        while len(password) < 8:
            print(f"Error! Password must be 8+ characters, got {len(password)}")
            password = getpass.getpass("Password for the vault...")

        self.vault_password = derive_from_password(password)
        return self.vault_password

    create_argparser = argparse.ArgumentParser()
    create_argparser.add_argument("filename", type=str, default="password-vault.enc")

    @cmd2.with_argparser(create_argparser)
    def do_create(self, args):
        """Create a new password vault."""
        self._get_vault_password()
        self.vault_file_name = args.filename
        self.vault_database = dict()
        self.enable_category(self.GET_SET_CATEGORY)

    load_argparser = argparse.ArgumentParser()
    load_argparser.add_argument("filename", type=str, default="password-vault.enc")

    @cmd2.with_argparser(load_argparser)
    def do_load(self, args):
        """Load a password vault from the specified file"""
        self._get_vault_password()
        self.vault_file_name = args.filename

        vault_handler = EncryptedVault(vault_file_name=self.vault_file_name, is_read=True)
        self.vault_database = vault_handler.read(key_bytes=self.vault_password.derived_key)

        self.enable_category(self.GET_SET_CATEGORY)

    @cmd2.with_category(GET_SET_CATEGORY)
    def do_save(self, args):
        """Save the password vault. Also done automatically."""
        vault_handler = EncryptedVault(vault_file_name=self.vault_file_name)
        vault_handler.write(
            key_bytes=self.vault_password.derived_key, 
            vault_database=self.vault_database
        )

    def exithook(self) -> None:
        self.do_save({})

    set_argparser = argparse.ArgumentParser()
    set_argparser.add_argument("hostname", type=str)

    @cmd2.with_category(GET_SET_CATEGORY)
    @cmd2.with_argparser(set_argparser)
    def do_set_password(self, args):
        """Set a password for a given hostname"""
        password = getpass.getpass(f"Password for {args.hostname}: ")
        self.vault_database[args.hostname] = password

    get_argparser = argparse.ArgumentParser()
    get_argparser.add_argument("hostname", type=str)

    @cmd2.with_category(GET_SET_CATEGORY)
    @cmd2.with_argparser(get_argparser)
    def do_get_password(self, args):
        """Retrieve a password for a given hostname"""
        try:
            password = self.vault_database[args.hostname]
        except KeyError:
            print(f"No password found for '{args.hostname}'!")
        
        print(f"\n\n{password}\n\n")


if __name__ == "__main__":
    vault = PasswordVault()
    sys.exit(vault.cmdloop())
