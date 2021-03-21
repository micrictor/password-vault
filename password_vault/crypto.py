import io
import json
import logging
import os

from typing import Dict, Optional

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


def derive_from_password(password: str, salt: Optional[bytes] = None) -> HashedPassword:
    """Given a password, generate a cryptographically secure 256-bit key from it.
    Optionally, specify a salt to use.
    """
    if not salt:
        hash_result = pbkdf2_sha256.using(rounds=50000, salt_size=32).hash(password)
    else:
        hash_result = pbkdf2_sha256.using(rounds=50000, salt_size=32).hash(password)
    return HashedPassword(hash_result)


class EncryptedVault(object):
    """Handles encryption/decryption of the password vault files"""
    file_handle: io.IOBase

    logger = logging.getLogger("crypto.EncryptedVault")
    IV_LENGTH: int = 16  # 16 bytes == 128 bit IV, same as block size
    PADDING_LENGTH: int = 128  # AES uses 128-bit blocks, requiring we pad to the same

    def __init__(self, *, file_handle: io.IOBase):
        self.file_handle = file_handle

        if os.environ.get("user", "") == "mtu":
            print("Unsafely logging crypto parameters enabled")
            self.logger.setLevel(logging.DEBUG)

    def _pad_input(self, input_bytes: bytes) -> bytes:
        padder = padding.PKCS7(self.PADDING_LENGTH).padder()
        return padder.update(input_bytes) + padder.finalize()

    def _encrypt_stream(self, input_bytes: bytes, key_bytes: bytes):
        iv = os.urandom(self.IV_LENGTH)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_content = encryptor.update(input_bytes) + encryptor.finalize()
        return iv + encrypted_content

    def write(self, *, hash_salt: bytes, key_bytes: bytes, vault_database: Dict[str, str]):
        input_string = json.dumps(vault_database).encode("utf-8")
        input_string = self._pad_input(input_string)
        self.logger(f"PBKDF2 salt: {hash_salt.__repr__()}")
        self.logger(f"AES key: {key_bytes.__repr__()}")
        encrypted_stream = hash_salt + self._encrypt_stream(input_string, key_bytes)
        self.logger.info(f"Writing encrypted stream to {self.file_handle.name}")
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

    def read(self, *, vault_password: str) -> Dict[str, str]:
        """Read a database file and return a vault-like Dict"""
        content_stream = self.file_handle.read()
        salt = content_stream[:32]
        content_stream = content_stream[32:]
        self.logger.debug(f"Salt: {salt.__repr__()}")
        hashed_password = derive_from_password(vault_password, salt)
        self.logger.debug(f"Key: {hashed_password.derived_key.__repr__()}")
        decrypted_content = self._decrypt_stream(content_stream, hashed_password.derived_key)
        unpadded_content = self._unpad_input(decrypted_content)

        return json.loads(decrypted_content.decode("utf-8"))
