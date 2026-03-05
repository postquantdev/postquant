"""Fixture: aliased imports that regex cannot resolve."""
from cryptography.hazmat.primitives.asymmetric import rsa as r
from cryptography.hazmat.primitives.asymmetric import ec as elliptic

# Regex misses these because the call uses aliases
key = r.generate_private_key(public_exponent=65537, key_size=2048)
ec_key = elliptic.generate_private_key(elliptic.SECP256R1())
