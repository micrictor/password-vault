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
    hash_result = pbkdf2_sha256.hash(password, rounds=50000, salt_size=64)

    return HashedPassword(hash_result)
