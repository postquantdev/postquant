"""Test fixture: Python code with quantum-safe cryptography."""
from cryptography.hazmat.primitives import hashes
import hashlib

# SHA-256 (SAFE)
sha256_hash = hashlib.sha256(b"data")

# SHA-384 (SAFE)
sha384_hash = hashlib.sha384(b"data")

# SHA-512 (SAFE)
sha512_hash = hashlib.sha512(b"data")

# SHA-3 (SAFE)
sha3_hash = hashlib.sha3_256(b"data")

# HMAC-SHA256 (SAFE - symmetric)
import hmac
mac = hmac.new(b"secret", b"data", hashlib.sha256)
