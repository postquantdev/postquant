import hashlib

def test_md5_produces_hash():
    result = hashlib.md5(b"test data")
    assert result is not None
