from unittest import mock

from password_vault.crypto import derive_from_password, HashedPassword

def test_derive_from_password():
    """Test that, even with the exact same password, we get different hashes every time"""

    results = []
    for _ in range(0, 100):
        results.append(derive_from_password("password1234"))

    last_result = None
    for result in results:
        if not last_result:
            last_result = result
            continue

        assert last_result.derived_key != result.derived_key
        last_result = result


def test_hashed_password():
    """Test that the HashedPassword class is properly parsing the returned strings"""

    test_hash = "$pbkdf2-sha256$50000$kfL.//8fQ8j5f48RIuRcKwVAqHWOcU6ptXZOKWVszdk$zYPVbRZMmpqpajtAzImxhBVPNRF9UnlEl7/WxjJDQMg"  # noqa

    test_object = HashedPassword(test_hash)

    assert test_object.digest == "sha256"
    assert test_object.rounds == 50000
    assert len(test_object.salt) == 32
    assert len(test_object.derived_key) == 256/8
