from unittest import mock

from password_vault import PasswordVault, main
from password_vault.fileformat import VaultFile


import cmd2_ext_test
import pytest

class PasswordVaultTester(cmd2_ext_test.ExternalTestMixin, PasswordVault):
    def __init__(self, *args, **kwargs):
        # gotta have this or neither the plugin or cmd2 will initialize
        super().__init__(*args, **kwargs)


@pytest.fixture(scope="function")
def password_vault():
    app = PasswordVaultTester()
    app.fixture_setup()
    yield app
    app.fixture_teardown()


@mock.patch("password_vault.sys.exit")
@mock.patch("password_vault.PasswordVault")
def test_main(mock_vault, mock_exit):
    mock_vault.return_value = mock.MagicMock()

    main()

    mock_vault.assert_called_once()
    mock_vault.return_value.cmdloop.assert_called_once()


@mock.patch("password_vault.getpass.getpass")
def test_get_password_success(mock_getpass, password_vault):
    mock_getpass.return_value = "hunter123"

    password_vault._get_vault_password()

    assert mock_getpass.call_count == 2


@mock.patch("password_vault.getpass.getpass")
def test_get_password_fail(mock_getpass, password_vault):
    with pytest.raises(RuntimeError):
        mock_getpass.side_effect = ["hunter123", "123hunter"] * 3

        password_vault._get_vault_password()

        assert mock_getpass.call_count == 6


def test_cli_create(password_vault):
    password_vault._get_vault_password = mock.MagicMock()
    password_vault.app_cmd("create test_filename")
    
    password_vault._get_vault_password.assert_called_once()
    assert password_vault.vault_file_name == "test_filename"
    assert isinstance(password_vault.vault_database, dict)


@mock.patch("password_vault.VaultFile")
@mock.patch("password_vault.getpass.getpass")
def test_cli_load(mock_getpass, mock_vaultfile_class, password_vault):
    mock_vaultfile = mock.MagicMock(spec=VaultFile)
    mock_vaultfile.read = mock.MagicMock(return_value = "{}")
    mock_vaultfile_class.return_value = mock_vaultfile
    mock_getpass.return_value = "test_password"

    password_vault.app_cmd("load test_filename")
    
    mock_getpass.assert_called_once()
    assert password_vault.vault_file_name == "test_filename"
    mock_vaultfile_class.assert_called_once_with("test_filename", "rb+")
    mock_vaultfile.read.assert_called_once_with(password="test_password")