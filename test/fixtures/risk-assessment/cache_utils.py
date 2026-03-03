import hashlib

def compute_cache_key(url):
    checksum = hashlib.md5(url.encode()).hexdigest()
    return f"cache:{checksum}"
