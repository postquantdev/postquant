"""Fixture: algorithm name stored in a variable."""
import hashlib

algo = "md5"
digest = hashlib.new(algo, b"data")

key_size = 2048
