"""Test fixture: Python code with quantum-vulnerable cryptography."""
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, dh
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.PublicKey import RSA as PycryptoRSA, ECC
from Crypto.Hash import MD5, SHA as SHA1_legacy
import hashlib

# RSA key generation (CRITICAL)
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# EC key generation (CRITICAL)
ec_key = ec.generate_private_key(ec.SECP256R1())

# Ed25519 (CRITICAL)
ed_key = Ed25519PrivateKey.generate()

# X25519 (CRITICAL)
x_key = X25519PrivateKey.generate()

# DSA (CRITICAL)
dsa_key = dsa.generate_private_key(key_size=2048)

# DH (CRITICAL)
dh_params = dh.generate_parameters(generator=2, key_size=2048)

# Pycryptodome RSA (CRITICAL)
pycrypto_rsa = PycryptoRSA.generate(2048)

# Pycryptodome ECC (CRITICAL)
pycrypto_ec = ECC.generate(curve='P-256')

# MD5 (CRITICAL)
md5_hash = hashlib.md5(b"data")

# SHA-1 (CRITICAL)
sha1_hash = hashlib.sha1(b"data")

# AES-128 (MODERATE)
# Using a 16-byte key implies AES-128
cipher = Cipher(algorithms.AES(b'\x00' * 16), modes.GCM(b'\x00' * 12))
