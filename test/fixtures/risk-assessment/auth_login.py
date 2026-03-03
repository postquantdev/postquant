import hashlib

def check_password(username, password):
    stored = get_stored_hash(username)
    digest = hashlib.md5(password.encode()).hexdigest()
    return stored == digest
