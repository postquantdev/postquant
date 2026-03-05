use aes_gcm::Aes256Gcm;
use sha2::{Sha256, Digest};
use ring::aead;

fn main() {
    // AES-256-GCM (SAFE - quantum-resistant symmetric encryption)
    let cipher = Aes256Gcm::new(&key_bytes.into());

    // SHA-256 (SAFE - quantum-resistant hash)
    let hash = Sha256::digest(b"data");

    // ring AEAD (SAFE - quantum-resistant symmetric encryption)
    let key = aead::LessSafeKey::new(unbound_key);

    println!("Cipher: {:?}", cipher);
    println!("Hash: {:?}", hash);
}
