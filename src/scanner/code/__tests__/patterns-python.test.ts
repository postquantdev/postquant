import { describe, it, expect } from 'vitest';
import { pythonPatterns } from '../patterns/python.js';
import type { CryptoPattern } from '../../../types/index.js';

const byId = (id: string): CryptoPattern => {
  const p = pythonPatterns.find((pat) => pat.id === id);
  if (!p) throw new Error(`Pattern not found: ${id}`);
  return p;
};

const callMatches = (p: CryptoPattern, s: string): boolean =>
  p.callPatterns.some((r) => r.test(s));

const importMatches = (p: CryptoPattern, s: string): boolean =>
  (p.importPatterns ?? []).some((r) => r.test(s));

describe('Python patterns', () => {
  it('exports 13 patterns', () => {
    expect(pythonPatterns).toHaveLength(13);
  });

  describe.each(pythonPatterns)('$id', (pattern) => {
    it('has valid structure', () => {
      expect(pattern.id).toMatch(/^python-/);
      expect(pattern.language).toBe('python');
      expect(pattern.callPatterns.length).toBeGreaterThan(0);
      expect(pattern.description).toBeTruthy();
      expect(pattern.migration).toBeTruthy();
      expect(['critical', 'moderate', 'safe']).toContain(pattern.risk);
    });
  });

  // --- Call pattern match tests ---
  const matchCases: [string, string][] = [
    ['python-rsa-keygen', 'key = rsa.generate_private_key(public_exponent=65537, key_size=2048)'],
    ['python-rsa-keygen', 'key = RSA.generate(2048)'],
    ['python-rsa-sign', 'sig = private_key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())'],
    ['python-ec-keygen', 'key = ec.generate_private_key(ec.SECP256R1())'],
    ['python-ec-keygen', 'key = ECC.generate(curve="P-256")'],
    ['python-ecdsa-sign', 'sig = private_key.sign(data, ec.ECDSA(hashes.SHA256()))'],
    ['python-ecdh-exchange', 'shared = private_key.exchange(ec.ECDH(), peer_public_key)'],
    ['python-x25519', 'key = X25519PrivateKey.generate()'],
    ['python-ed25519', 'key = Ed25519PrivateKey.generate()'],
    ['python-ed25519', 'key = Ed448PrivateKey.generate()'],
    ['python-dsa-keygen', 'key = dsa.generate_private_key(key_size=2048)'],
    ['python-dsa-keygen', 'key = DSA.generate(2048)'],
    ['python-dh-keygen', 'params = dh.generate_parameters(generator=2, key_size=2048)'],
    ['python-md5', 'h = hashlib.md5(data)'],
    ['python-md5', "h = hashlib.new('md5', data)"],
    ['python-sha1', 'h = hashlib.sha1(data)'],
    ['python-sha256', 'h = hashlib.sha256(data)'],
    ['python-sha256', 'h = hashlib.sha384(data)'],
    ['python-aes', 'c = Cipher(algorithms.AES(key), modes.GCM(iv))'],
    ['python-aes', 'c = AES.new(key, AES.MODE_GCM)'],
  ];

  it.each(matchCases)('%s matches: %s', (id, code) => {
    expect(callMatches(byId(id), code)).toBe(true);
  });

  // --- Non-match tests ---
  const noMatchCases: [string, string][] = [
    ['python-rsa-keygen', 'print("hello world")'],
    ['python-md5', 'hashlib.sha256(data)'],
    ['python-sha256', 'hashlib.md5(data)'],
    ['python-aes', 'Cipher(algorithms.ChaCha20(key, nonce), mode=None)'],
  ];

  it.each(noMatchCases)('%s does NOT match: %s', (id, code) => {
    expect(callMatches(byId(id), code)).toBe(false);
  });

  // --- Import pattern tests ---
  const importCases: [string, string][] = [
    ['python-rsa-keygen', 'from cryptography.hazmat.primitives.asymmetric import rsa'],
    ['python-rsa-keygen', 'from Crypto.PublicKey import RSA'],
    ['python-x25519', 'from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey'],
    ['python-ed25519', 'from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey'],
  ];

  it.each(importCases)('%s import matches: %s', (id, importLine) => {
    expect(importMatches(byId(id), importLine)).toBe(true);
  });

  // --- Key size extractor tests ---
  it('python-rsa-keygen extracts key size', () => {
    const p = byId('python-rsa-keygen');
    const match = 'rsa.generate_private_key(public_exponent=65537, key_size=4096)'.match(p.keySizeExtractor!);
    expect(match).toBeTruthy();
    const size = parseInt(match![1] || match![2]);
    expect(size).toBe(4096);
  });

  it('python-aes keySizeRisk returns correct risk', () => {
    const p = byId('python-aes');
    expect(p.keySizeRisk!(128)).toBe('moderate');
    expect(p.keySizeRisk!(256)).toBe('safe');
  });

  // --- Risk level tests ---
  it('all asymmetric/signature/exchange patterns are critical', () => {
    const critical = pythonPatterns.filter(
      (p) =>
        p.category === 'asymmetric-encryption' ||
        p.category === 'digital-signature' ||
        p.category === 'key-exchange',
    );
    critical.forEach((p) => expect(p.risk).toBe('critical'));
  });

  it('sha256 is safe', () => {
    expect(byId('python-sha256').risk).toBe('safe');
  });
});
