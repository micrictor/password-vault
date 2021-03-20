from unittest import mock

from password_vault.crypto import derive_from_password

def test_derive_from_password():
    """Test that, even with the exact same password, we get different hashes every time"""

    results = []
    for i in range(0, 100):
        results.append(derive_from_password("password1234"))

    last_result = None
    for result in results:
        if not last_result:
            last_result = result
            continue

        assert last_result.derived_key != result.derived_key
        last_result = result