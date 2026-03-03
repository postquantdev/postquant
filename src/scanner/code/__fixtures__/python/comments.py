"""Test fixture: Crypto mentions only in comments and strings — no real crypto calls."""

# rsa.generate_private_key(public_exponent=65537, key_size=2048)
# hashlib.md5(b"data")

"""
This is a docstring that mentions RSA and MD5:
rsa.generate_private_key(public_exponent=65537, key_size=2048)
hashlib.md5(b"data")
"""

message = "Use rsa.generate_private_key() for RSA keys"
another = 'hashlib.md5(b"test") is insecure'

def no_crypto():
    """This function mentions ec.generate_private_key(ec.SECP256R1()) but does not call it."""
    pass
