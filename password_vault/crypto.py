import io
import json
import os

from typing import Dict

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from passlib.hash import pbkdf2_sha256
from passlib.utils.binary import ab64_decode, ab64_encode


class HashedPassword(object):
    """Stores the metadata about the PBKDF2 hash generated from a password"""
    rounds: int
    digest: str
    salt: bytes
    derived_key: bytes

    def __init__(self, pbkdf2_output: str):
        _, digest, rounds, salt, checksum = pbkdf2_output.split("$")

        self.digest = digest.split("-")[1]
        self.rounds = int(rounds)
        self.salt = ab64_decode(salt)
        self.derived_key = ab64_decode(checksum)


def derive_from_password(password: str) -> HashedPassword:
    """Given a password, generate a cryptographically secure 256-bit key from it"""
    hash_result = pbkdf2_sha256.using(rounds=50000, salt_size=32).hash(password)

    return HashedPassword(hash_result)


class EncryptedVault(object):
    """Handles encryption/decryption of the password vault files"""
    file_handle: io.IOBase

    IV_LENGTH: int = 16  # 16 bytes == 128 bit IV, same as block size
    PADDING_LENGTH: int = 128  # AES uses 128-bit blocks, requiring we pad to the same

    def __init__(self, *, vault_file_name: str, is_read: bool = False):
        self.file_handle = open(vault_file_name, f"{'r' if is_read else 'w'}b+")

    def _pad_input(self, input_bytes: bytes) -> bytes:
        padder = padding.PKCS7(self.PADDING_LENGTH).padder()
        return padder.update(input_bytes) + padder.finalize()

    def _encrypt_stream(self, input_bytes: bytes, key_bytes: bytes):
        iv = os.urandom(self.IV_LENGTH)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_content = encryptor.update(input_bytes) + encryptor.finalize()
        return iv + encrypted_content

    def write(self, *, key_bytes: bytes, vault_database: Dict[str, str]):
        input_string = json.dumps(vault_database).encode("utf-8")
        input_string = self._pad_input(input_string)
        encrypted_stream = self._encrypt_stream(input_string, key_bytes)
        self.file_handle.write(encrypted_stream)

    def _decrypt_stream(self, input_bytes: bytes, key_bytes: bytes):
        iv = input_bytes[:self.IV_LENGTH]
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_content = decryptor.update(input_bytes[self.IV_LENGTH:]) + decryptor.finalize()
        return decrypted_content

    def _unpad_input(self, input_bytes: bytes):
        padder = padding.PKCS7(self.PADDING_LENGTH).unpadder()
        return padder.update(input_bytes) + padder.finalize()

    def read(self, *, key_bytes: bytes) -> Dict[str, str]:
        """Read a database file and return a vault-like Dict"""
        content_stream = self.file_handle.read()
        print(content_stream)
        decrypted_content = self._decrypt_stream(content_stream, key_bytes)
        unpadded_content = self._unpad_input(decrypted_content)

        return json.loads(decrypted_content.decode("utf-8"))
