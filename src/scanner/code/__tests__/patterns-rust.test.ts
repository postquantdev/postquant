import { describe, it, expect } from 'vitest';
import { rustPatterns } from '../patterns/rust.js';
import type { CryptoPattern } from '../../../types/index.js';

const byId = (id: string): CryptoPattern => {
  const p = rustPatterns.find((pat) => pat.id === id);
  if (!p) throw new Error(`Pattern not found: ${id}`);
  return p;
};

const callMatches = (p: CryptoPattern, s: string): boolean =>
  p.callPatterns.some((r) => r.test(s));

const importMatches = (p: CryptoPattern, s: string): boolean =>
  (p.importPatterns ?? []).some((r) => r.test(s));

describe('Rust patterns', () => {
  it('exports 11 patterns', () => {
    expect(rustPatterns).toHaveLength(11);
  });

  describe.each(rustPatterns)('$id', (pattern) => {
    it('has valid structure', () => {
      expect(pattern.id).toMatch(/^rust-/);
      expect(pattern.language).toBe('rust');
      expect(pattern.callPatterns.length).toBeGreaterThan(0);
      expect(pattern.description).toBeTruthy();
      expect(pattern.migration).toBeTruthy();
      expect(['critical', 'moderate', 'safe']).toContain(pattern.risk);
    });
  });

  // --- Call pattern match tests ---
  const matchCases: [string, string][] = [
    // ring agreement
    ['rust-ring-agreement', 'let private_key = agreement::EphemeralPrivateKey::generate(&X25519, rng)?;'],
    ['rust-ring-agreement', 'agreement::agree_ephemeral(private_key, &peer_public_key, |shared| { ... })'],
    ['rust-ring-agreement', 'let peer_pub = agreement::UnparsedPublicKey::new(&X25519, peer_bytes);'],
    // ring signature
    ['rust-ring-signature', 'let kp = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes)?;'],
    ['rust-ring-signature', 'let kp = signature::RsaKeyPair::from_der(der_bytes)?;'],
    ['rust-ring-signature', 'let sig = key_pair.sign(msg);'],
    ['rust-ring-signature', 'let pub_key = signature::UnparsedPublicKey::new(&ED25519, bytes);'],
    ['rust-ring-signature', 'let kp = signature::EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8)?;'],
    // ring aead
    ['rust-ring-aead', 'let sealing_key = aead::SealingKey::new(unbound_key, nonce_seq);'],
    ['rust-ring-aead', 'let opening_key = aead::OpeningKey::new(unbound_key, nonce_seq);'],
    ['rust-ring-aead', 'let key = aead::LessSafeKey::new(unbound_key);'],
    ['rust-ring-aead', 'let unbound = aead::UnboundKey::new(&AES_256_GCM, key_bytes)?;'],
    // ring digest
    ['rust-ring-digest', 'let hash = digest::digest(&SHA256, data);'],
    ['rust-ring-digest', 'let mut ctx = digest::Context::new(&SHA256);'],
    // RustCrypto rsa
    ['rust-rsa-crate', 'let private_key = RsaPrivateKey::new(&mut rng, 2048)?;'],
    ['rust-rsa-crate', 'let public_key = RsaPublicKey::new(n, e)?;'],
    ['rust-rsa-crate', 'let key = RsaPrivateKey::from_pkcs8_der(der)?;'],
    ['rust-rsa-crate', 'let key = RsaPublicKey::from_pkcs1_der(der)?;'],
    // RustCrypto ecdsa
    ['rust-ecdsa-crate', 'let signing_key = SigningKey::random(&mut rng);'],
    ['rust-ecdsa-crate', 'let signing_key = SigningKey::from_bytes(bytes)?;'],
    ['rust-ecdsa-crate', 'let verifying_key = VerifyingKey::from_sec1_bytes(bytes)?;'],
    ['rust-ecdsa-crate', 'let key: ecdsa::SigningKey<NistP256> = ...;'],
    // RustCrypto aes
    ['rust-aes-crate', 'let cipher = Aes256Gcm::new(&key);'],
    ['rust-aes-crate', 'let cipher = Aes128Gcm::new(&key);'],
    ['rust-aes-crate', 'let cipher = Aes256Gcm::new_from_slice(key_bytes)?;'],
    ['rust-aes-crate', 'let cipher = Aes128Gcm::new_from_slice(key_bytes)?;'],
    ['rust-aes-crate', 'let cipher = ChaCha20Poly1305::new(&key);'],
    ['rust-aes-crate', 'let cipher = XChaCha20Poly1305::new(&key);'],
    // RustCrypto sha
    ['rust-sha-crate', 'let hash = Sha256::digest(data);'],
    ['rust-sha-crate', 'let mut hasher = Sha256::new();'],
    ['rust-sha-crate', 'let hash = Sha384::digest(data);'],
    ['rust-sha-crate', 'let hash = Sha512::digest(data);'],
    // RustCrypto md5
    ['rust-md5-crate', 'let hash = Md5::digest(data);'],
    ['rust-md5-crate', 'let mut hasher = Md5::new();'],
    // openssl crate rsa
    ['rust-openssl-rsa', 'let rsa = Rsa::generate(2048)?;'],
    ['rust-openssl-rsa', 'let pkey = PKey::from_rsa(rsa)?;'],
    ['rust-openssl-rsa', 'let rsa = Rsa::public_key_from_pem(pem)?;'],
    ['rust-openssl-rsa', 'let rsa = Rsa::private_key_from_pem(pem)?;'],
    // openssl crate ec
    ['rust-openssl-ec', 'let key = EcKey::generate(&group)?;'],
    ['rust-openssl-ec', 'let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;'],
    ['rust-openssl-ec', 'let key = EcKey::from_private_components(&group, &priv_num, &pub_point)?;'],
  ];

  it.each(matchCases)('%s matches: %s', (id, code) => {
    expect(callMatches(byId(id), code)).toBe(true);
  });

  // --- Non-match tests ---
  const noMatchCases: [string, string][] = [
    ['rust-ring-agreement', 'println!("hello world")'],
    ['rust-md5-crate', 'Sha256::digest(data)'],
    ['rust-sha-crate', 'Md5::digest(data)'],
    ['rust-rsa-crate', 'Aes256Gcm::new(&key)'],
    ['rust-ring-aead', 'RsaPrivateKey::new(&mut rng, 2048)'],
  ];

  it.each(noMatchCases)('%s does NOT match: %s', (id, code) => {
    expect(callMatches(byId(id), code)).toBe(false);
  });

  // --- Import pattern tests ---
  const importCases: [string, string][] = [
    ['rust-ring-agreement', 'use ring::agreement;'],
    ['rust-ring-signature', 'use ring::signature;'],
    ['rust-ring-aead', 'use ring::aead;'],
    ['rust-ring-digest', 'use ring::digest;'],
    ['rust-rsa-crate', 'use rsa::RsaPrivateKey;'],
    ['rust-ecdsa-crate', 'use ecdsa::SigningKey;'],
    ['rust-ecdsa-crate', 'use p256::ecdsa::SigningKey;'],
    ['rust-ecdsa-crate', 'use p384::ecdsa::VerifyingKey;'],
    ['rust-ecdsa-crate', 'use k256::ecdsa::SigningKey;'],
    ['rust-aes-crate', 'use aes_gcm::Aes256Gcm;'],
    ['rust-aes-crate', 'use aes::Aes256;'],
    ['rust-aes-crate', 'use chacha20poly1305::ChaCha20Poly1305;'],
    ['rust-sha-crate', 'use sha2::Sha256;'],
    ['rust-sha-crate', 'use sha3::Sha3_256;'],
    ['rust-md5-crate', 'use md5::Md5;'],
    ['rust-openssl-rsa', 'use openssl::rsa::Rsa;'],
    ['rust-openssl-rsa', 'use openssl::pkey::PKey;'],
    ['rust-openssl-ec', 'use openssl::ec::EcKey;'],
  ];

  it.each(importCases)('%s import matches: %s', (id, importLine) => {
    expect(importMatches(byId(id), importLine)).toBe(true);
  });

  // --- Risk level validation ---
  it('all asymmetric/signature/exchange patterns are critical', () => {
    const critical = rustPatterns.filter(
      (p) =>
        p.category === 'asymmetric-encryption' ||
        p.category === 'digital-signature' ||
        p.category === 'key-exchange',
    );
    critical.forEach((p) => expect(p.risk).toBe('critical'));
  });

  it('sha-crate is safe', () => {
    expect(byId('rust-sha-crate').risk).toBe('safe');
  });

  it('aes-crate is safe', () => {
    expect(byId('rust-aes-crate').risk).toBe('safe');
  });

  it('all patterns have medium confidence', () => {
    rustPatterns.forEach((p) => expect(p.confidence).toBe('medium'));
  });
});
