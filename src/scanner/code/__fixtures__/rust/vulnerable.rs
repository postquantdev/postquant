use rsa::{RsaPrivateKey, RsaPublicKey};
use ecdsa::SigningKey;
use ring::agreement;
use md5::Md5;
use ring::signature;
use digest::Digest;

fn main() {
    let mut rng = rand::thread_rng();

    // RSA key generation (CRITICAL - Shor's algorithm)
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);

    // ECDSA signing key (CRITICAL - Shor's algorithm)
    let signing_key = SigningKey::random(&mut rng);

    // ring ECDH key agreement (CRITICAL - Shor's algorithm)
    let ephemeral_private_key =
        agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();

    // MD5 hash (CRITICAL - cryptographically broken)
    let hash = Md5::digest(b"data");

    // ring Ed25519 signature (CRITICAL)
    let kp = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes).unwrap();

    println!("Private key: {:?}", private_key);
    println!("Signing key: {:?}", signing_key);
    println!("Hash: {:?}", hash);
}
