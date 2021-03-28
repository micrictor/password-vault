from unittest import mock

from password_vault import PasswordVault, main


import cmd2_ext_test
import pytest

class PasswordVaultTester(cmd2_ext_test.ExternalTestMixin, PasswordVault):
    def __init__(self, *args, **kwargs):
        # gotta have this or neither the plugin or cmd2 will initialize
        super().__init__(*args, **kwargs)


@pytest.fixture
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


def test_cli_create(password_vault):
    password_vault._get_vault_password = mock.MagicMock()
    password_vault.app_cmd("create test_filename")
    
    password_vault._get_vault_password.assert_called_once()
    assert password_vault.vault_file_name == "test_filename"
    assert isinstance(password_vault.vault_database, dict)
