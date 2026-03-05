"""Fixture: crypto in test functions should get reduced risk."""
import hashlib
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

def test_md5_behavior():
    """Test function -- crypto here is not production usage."""
    result = hashlib.md5(b"test data")
    assert result is not None

class TestCryptoMigration:
    def test_rsa_still_works(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        assert key is not None
