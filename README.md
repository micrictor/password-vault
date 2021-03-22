# password-vault
A simple password vault in Python3. THIS SHOULD NOT BE USED FOR REAL DATA

## Overview

This is a simple password vault, implemented in Python 3. It was written for the purpose of the Cryptography class in the Master's of Science in Cybersecurity Engineering at University of San Diego. As such, I highly reccommend that you do _not_ use this for any real passwords. On top of the fact that I wrote this in a single weekend, there are much more feature rich password managers available at no cost. Use one of those.


## System Objectives

As a password manager, there are two primary requirements of the system. Users must be able to:

1. Store a username and password for any website
2. Retrieve the username and password for a given website


There are also two major security requirements:

1. Passwords cannot be accessed by unauthorized parties
2. A user only needs to have one password to store and retrieve passwords for all sites


## Design

Command-line interface built in [Cmd2](https://cmd2.readthedocs.io/en/latest/).

* PBKDF2_SHA256 will be used to derive a 256-bit key from a passphrase
* `os.urandom`, a crypographically secure psuedorandom source, is used to generate a 128-bit IV. This is because AES uses 128-bit blocks.
* AES256-CBC, seeded with the previously described IV, is used to symmetrically encrypt the password vault
* The password vault is represented by a utf-8 encoded JSON blob
* Before encryption, this blob is padded to the block length (128 bits) using PKCS7

### File Format

The vault file starts with a 32-byte salt used to derive the key from a password. This is immediately followed by the 16-byte IV used to encrypt the vault, then the AES256 encrypted bytes.

Bytes 0-31: PBKDF2_SHA256 salt; Used to derive a key from a password
Bytes 32-47: 16-byte IV used for AES256-CBC
Bytes 48-EOF: Raw encrypted bytes