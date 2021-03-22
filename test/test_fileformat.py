from unittest import mock

import pytest

from password_vault.fileformat import VaultFile


@pytest.fixture(scope='session')
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
    iv = b'A' * mock_vault_file.IV_LENGTH
    mock_vault_file._decrypt(iv + b'test input', b'test key')

    mock_cbc.assert_called_once_with(iv)
    mock_aes.assert_called_once_with(b'test key')
    mock_cipher.assert_called_once()
    mock_decryptor.update.assert_called_once_with(b'test input')
    mock_decryptor.finalize.assert_called_once()


