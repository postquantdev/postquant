import hashlib
import uuid

def make_uuid3(namespace, name):
    hash = hashlib.md5(namespace.bytes + name.encode())
    return uuid.UUID(bytes=hash.digest()[:16])
