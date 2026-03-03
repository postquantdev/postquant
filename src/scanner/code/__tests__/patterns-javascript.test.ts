import { describe, it, expect } from 'vitest';
import { javascriptPatterns } from '../patterns/javascript.js';
import type { CryptoPattern } from '../../../types/index.js';

const byId = (id: string): CryptoPattern => {
  const p = javascriptPatterns.find((pat) => pat.id === id);
  if (!p) throw new Error(`Pattern not found: ${id}`);
  return p;
};

const callMatches = (p: CryptoPattern, s: string): boolean =>
  p.callPatterns.some((r) => r.test(s));

const importMatches = (p: CryptoPattern, s: string): boolean =>
  (p.importPatterns ?? []).some((r) => r.test(s));

describe('JavaScript patterns', () => {
  it('exports 14 patterns', () => {
    expect(javascriptPatterns).toHaveLength(14);
  });

  describe.each(javascriptPatterns)('$id', (pattern) => {
    it('has valid structure', () => {
      expect(pattern.id).toMatch(/^js-/);
      expect(pattern.language).toBe('javascript');
      expect(pattern.callPatterns.length).toBeGreaterThan(0);
      expect(pattern.description).toBeTruthy();
      expect(pattern.migration).toBeTruthy();
      expect(['critical', 'moderate', 'safe']).toContain(pattern.risk);
    });
  });

  // --- Call pattern match tests ---
  const matchCases: [string, string][] = [
    ['js-rsa-keygen', "generateKeyPairSync('rsa', { modulusLength: 2048 })"],
    ['js-rsa-keygen', "generateKeyPair('rsa', { modulusLength: 4096 }, callback)"],
    ['js-ec-keygen', "generateKeyPairSync('ec', { namedCurve: 'P-256' })"],
    ['js-ed25519-keygen', "generateKeyPairSync('ed25519')"],
    ['js-ed25519-keygen', "generateKeyPairSync('x25519')"],
    ['js-dsa-keygen', "generateKeyPairSync('dsa', { modulusLength: 2048 })"],
    ['js-dh-exchange', 'createDiffieHellman(2048)'],
    ['js-ecdh-exchange', "createECDH('secp256k1')"],
    ['js-ecdh-exchange', "createECDH('prime256v1')"],
    ['js-md5-hash', "createHash('md5')"],
    ['js-sha1-hash', "createHash('sha1')"],
    ['js-sha256-hash', "createHash('sha256')"],
    ['js-sha256-hash', "createHash('sha384')"],
    ['js-aes', "createCipheriv('aes-128-gcm', key, iv)"],
    ['js-aes', "createCipheriv('aes-256-gcm', key, iv)"],
    ['js-3des', "createCipheriv('des-ede3-cbc', key, iv)"],
    ['js-webcrypto-rsa', "crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048 }, true, ['encrypt'])"],
    ['js-webcrypto-ec', "crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])"],
    ['js-jwt-sign', "jwt.sign(payload, rsaKey, { algorithm: 'RS256' })"],
    ['js-jwt-sign', "new SignJWT(payload).setProtectedHeader({ alg: 'ES256' })"],
  ];

  it.each(matchCases)('%s matches: %s', (id, code) => {
    expect(callMatches(byId(id), code)).toBe(true);
  });

  // --- Non-match tests ---
  const noMatchCases: [string, string][] = [
    ['js-rsa-keygen', 'console.log("hello")'],
    ['js-md5-hash', "createHash('sha256')"],
    ['js-sha256-hash', "createHash('md5')"],
    ['js-jwt-sign', "jwt.sign(payload, secret, { algorithm: 'HS256' })"],
  ];

  it.each(noMatchCases)('%s does NOT match: %s', (id, code) => {
    expect(callMatches(byId(id), code)).toBe(false);
  });

  // --- Import pattern tests ---
  const importCases: [string, string][] = [
    ['js-rsa-keygen', "import { generateKeyPairSync } from 'crypto'"],
    ['js-rsa-keygen', "import { generateKeyPairSync } from 'node:crypto'"],
    ['js-rsa-keygen', "const { generateKeyPairSync } = require('crypto')"],
    ['js-dh-exchange', "import { createDiffieHellman } from 'crypto'"],
  ];

  it.each(importCases)('%s import matches: %s', (id, importLine) => {
    expect(importMatches(byId(id), importLine)).toBe(true);
  });

  // --- Key size tests ---
  it('js-aes keySizeRisk differentiates 128 vs 256', () => {
    const p = byId('js-aes');
    expect(p.keySizeRisk!(128)).toBe('moderate');
    expect(p.keySizeRisk!(256)).toBe('safe');
  });

  it('js-aes extracts key size from cipher string', () => {
    const p = byId('js-aes');
    const match = "createCipheriv('aes-128-gcm', key, iv)".match(p.keySizeExtractor!);
    expect(match).toBeTruthy();
    expect(parseInt(match![1])).toBe(128);
  });

  it('all asymmetric/signature/exchange patterns are critical', () => {
    const critical = javascriptPatterns.filter(
      (p) =>
        p.category === 'asymmetric-encryption' ||
        p.category === 'digital-signature' ||
        p.category === 'key-exchange',
    );
    critical.forEach((p) => expect(p.risk).toBe('critical'));
  });
});
