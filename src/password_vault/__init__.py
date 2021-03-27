#!/usr/bin/env python3
import getpass
import io
import json
import sys

from typing import Dict

import argparse
import cmd2

from password_vault.crypto import derive_from_password, HashedPassword
from password_vault.fileformat import VaultFile

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
        self.intro = cmd2.style(
            "Welcome to the password vault!\nTo start, either `create` or `load` a vault.",
            fg=cmd2.fg.white,
            bold=True
        )
        self.disable_category(self.GET_SET_CATEGORY, "Must create or load database first")

    def _get_vault_password(self) -> HashedPassword:
        password = ""
        for _ in range(0,3):
            password = getpass.getpass("Password for the vault: ")
            if len(password) < 8:
                print(f"Error! Password must be 8+ characters, got {len(password)}")
                password = getpass.getpass("Password for the vault: ")
                continue

            second_password = getpass.getpass("Re-enter the password: ")
            if password != second_password:
                print("\nPasswords do not match!\n")
                second_password = ""
                continue
            else:
                break
        else:
            raise RuntimeError("Failed password prompt too many times!")

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
        password = getpass.getpass("Vault password: ")
        self.vault_file_name = args.filename
        source_file = VaultFile(self.vault_file_name, "rb+")
        file_contents = source_file.read(password=password)
        self.vault_password = source_file.hashed_password
        self.vault_database = json.loads(file_contents)

        self.enable_category(self.GET_SET_CATEGORY)

    complete_load = cmd2.Cmd.path_complete

    @cmd2.with_category(GET_SET_CATEGORY)
    def do_save(self, args):
        """Save the password vault. Also done automatically."""
        destination_file = VaultFile(self.vault_file_name, "wb+")
        stream_to_write = json.dumps(self.vault_database).encode("utf-8")
        destination_file.write(stream_to_write, self.vault_password)

    def exithook(self) -> None:
        try:
            if self.vault_database is not None:
                self.do_save({})
        except AttributeError:
            pass

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

    def complete_get_password(self, text, line, begidx, endidx):
        possible_sites = list(self.vault_database.keys())
        if not text:
            return possible_sites
   
        return [site for site in possible_sites if site.startswith(text)]

    @cmd2.with_category(GET_SET_CATEGORY)
    def do_dump(self, args):
        for site, password in self.vault_database.items():
            print(f"Website: {site}\tPassword: {password}")

def main():
    vault = PasswordVault()
    sys.exit(vault.cmdloop())