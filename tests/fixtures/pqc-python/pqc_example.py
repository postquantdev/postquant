import oqs

kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()
ciphertext, shared_secret_enc = kem.encap_secret(public_key)
