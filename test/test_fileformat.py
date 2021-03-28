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
    mock_vault_file._encrypt(b'test input', b'test key')

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


@mock.patch("password_vault.fileformat.derive_from_password")
def test_read(mock_derive, mock_vault_file):
    salt = b'A' * mock_vault_file.SALT_LENGTH
    iv = b'B' * mock_vault_file.IV_LENGTH
    ciphertext = b'C' * 128
    mock_vault_file.file_handle.read.return_value = salt + iv + ciphertext
    mock_derive.return_value = mock.MagicMock(derived_key=b'D'*(256//8))
    mock_vault_file._decrypt = mock.MagicMock()

    result = mock_vault_file.read("test password")

    mock_vault_file.file_handle.read.assert_called_once()
    mock_derive.assert_called_once_with(password="test password", salt=salt)
    mock_vault_file._decrypt.assert_called_once_with(iv + ciphertext, b'D'*(256//8))
    assert result == mock_vault_file._decrypt.return_value


def test_write(mock_vault_file):
    mock_password = mock.MagicMock(salt=b'A'*mock_vault_file.SALT_LENGTH, derived_key=b'B'*(256//8))
    mock_vault_file._encrypt = mock.MagicMock()

    mock_vault_file.write(b'test stream', mock_password)

    mock_vault_file._encrypt.assert_called_once_with(b'test stream', mock_password.derived_key)
    assert mock_vault_file.file_handle.write.call_count == 2
    expected_calls = [
        mock.call.write(mock_password.salt),
        mock.call.write(mock_vault_file._encrypt.return_value)
    ]
    mock_vault_file.file_handle.assert_has_calls(expected_calls)
