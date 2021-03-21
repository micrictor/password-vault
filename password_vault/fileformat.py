import io
import logging
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from password_vault.crypto import derive_from_password, HashedPassword

class VaultFile(object):
    """Handles the file format for the password vault"""
    file_handle: io.IOBase
    hashed_password: HashedPassword

    IV_LENGTH: int = 16
    PAD_LENGTH: int = 128
    SALT_LENGTH: int = 32

    logger = logging.getLogger("crypto.EncryptedVault")


    def __init__(self, file_name: str, mode: str):
        self.file_handle = open(file_name, mode)

    def _padder(self, input_bytes: bytes) -> bytes:
        padder = padding.PKCS7(self.PAD_LENGTH).padder()
        return padder.update(input_bytes) + padder.finalize()

    def _unpadder(self, input_bytes: bytes) -> bytes:
        padder = padding.PKCS7(self.PAD_LENGTH).unpadder()
        return padder.update(input_bytes) + padder.finalize()

    def _decrypt(self, input_bytes: bytes, key: bytes):
        iv = input_bytes[:self.IV_LENGTH]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_content = decryptor.update(input_bytes[self.IV_LENGTH:]) + decryptor.finalize()
        return decrypted_content

    def _encrypt(self, input_bytes: bytes, key: bytes):
        iv = os.urandom(self.IV_LENGTH)
        padded_bytes = self._padder(input_bytes)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_content = encryptor.update(padded_bytes) + encryptor.finalize()
        return iv + encrypted_content

    def read(self, password: str) -> bytes:
        file_contents = self.file_handle.read()
        hash_salt = file_contents[:self.SALT_LENGTH]
        self.hashed_password = derive_from_password(password=password, salt=hash_salt)
        decrypted_content = self._decrypt(file_contents[self.SALT_LENGTH:], self.hashed_password.derived_key)
        return self._unpadder(decrypted_content)

    def write(self, input_stream: bytes, hashed_password: HashedPassword):
        self.file_handle.write(hashed_password.salt)
        encrypted_content = self._encrypt(input_stream, hashed_password.derived_key)
        self.file_handle.write(encrypted_content)
