import os

from unittest import mock

import pytest

from password_vault.fileformat import VaultFile


@pytest.fixture(scope='function')
def mock_vault_file():
    instance = VaultFile("/dev/null", "rb+")
    instance.file_handle = mock.MagicMock()
    return instance


def test_padder(mock_vault_file):
    test_string = "A" * mock_vault_file.PAD_LENGTH + "B" * 7
    result = mock_vault_file._padder(test_string.encode("utf-8"))

    assert b'BBBB' in result
    assert len(result) % 16 == 0


def test_unpadder(mock_vault_file):
    # First, we need to get a padded output, then test that unpadding works
    test_string = "A" * mock_vault_file.PAD_LENGTH + "B" * 7
    padded_result = mock_vault_file._padder(test_string.encode("utf-8"))

    unpadded_result = mock_vault_file._unpadder(padded_result)
    
    assert test_string.encode("utf-8") == unpadded_result


@mock.patch("password_vault.fileformat.Cipher")
@mock.patch("password_vault.fileformat.modes.CBC")
@mock.patch("password_vault.fileformat.algorithms.AES")
def test_decrypt(mock_aes, mock_cbc, mock_cipher, mock_vault_file):
    mock_cipher_object = mock_cipher.return_value
    mock_decryptor = mock_cipher_object.decryptor.return_value
    mock_decryptor.update.return_value(b'test input')
    mock_decryptor.finalize.return_value(b'')
    mock_vault_file._unpadder = mock.MagicMock(side_effect=lambda x: x)  # Disable padding

    iv = b'A' * mock_vault_file.IV_LENGTH
    mock_vault_file._decrypt(iv + b'test input', b'test key')

    mock_cbc.assert_called_once_with(iv)
    mock_aes.assert_called_once_with(b'test key')
    mock_cipher.assert_called_once()
    mock_decryptor.update.assert_called_once_with(b'test input')
    mock_decryptor.finalize.assert_called_once()


@mock.patch("password_vault.fileformat.Cipher")
@mock.patch("password_vault.fileformat.modes.CBC")
@mock.patch("password_vault.fileformat.algorithms.AES")
def test_encrypt(mock_aes, mock_cbc, mock_cipher, mock_vault_file):
    mock_cipher_object = mock_cipher.return_value
    mock_encryptor = mock_cipher_object.encryptor.return_value
    mock_vault_file._padder = mock.MagicMock(side_effect=lambda x: x)  # Disable padding
    result = mock_vault_file._encrypt(b'test input', b'test key')

    mock_vault_file._padder.assert_called_once()
    mock_cbc.assert_called_once()
    mock_aes.assert_called_once_with(b'test key')
    mock_cipher.assert_called_once()
    mock_encryptor.update.assert_called_once_with(b'test input')
    mock_encryptor.finalize.assert_called_once()


def test_integ_encrypt_decrypt(mock_vault_file):
    num_bytes_to_encrypt = int.from_bytes(os.urandom(1), byteorder="little")
    plaintext = os.urandom(num_bytes_to_encrypt)
    key = os.urandom(256//8)  # 256-bit key

    ciphertext = mock_vault_file._encrypt(plaintext, key)
    decrypt_result = mock_vault_file._decrypt(ciphertext, key)

    assert plaintext == decrypt_result