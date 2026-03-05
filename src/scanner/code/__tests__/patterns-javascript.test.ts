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
  it('exports 17 patterns', () => {
    expect(javascriptPatterns).toHaveLength(17);
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

  // --- PQC patterns ---
  describe('PQC patterns', () => {
    it('js-pqc-liboqs matches import via require', () => {
      expect(importMatches(byId('js-pqc-liboqs'), "const oqs = require('liboqs')")).toBe(true);
    });

    it('js-pqc-liboqs matches import via from', () => {
      expect(importMatches(byId('js-pqc-liboqs'), "import { KeyEncapsulation } from 'liboqs'")).toBe(true);
    });

    it('js-pqc-liboqs matches KeyEncapsulation call', () => {
      expect(callMatches(byId('js-pqc-liboqs'), "new KeyEncapsulation('Kyber768')")).toBe(true);
    });

    it('js-pqc-liboqs matches Signature call', () => {
      expect(callMatches(byId('js-pqc-liboqs'), "new Signature('Dilithium3')")).toBe(true);
    });

    it('js-pqc-liboqs is safe', () => {
      expect(byId('js-pqc-liboqs').risk).toBe('safe');
    });

    it('js-pqc-crystals-kyber matches crystals-kyber require', () => {
      expect(importMatches(byId('js-pqc-crystals-kyber'), "const kyber = require('crystals-kyber')")).toBe(true);
    });

    it('js-pqc-crystals-kyber matches ml-kem import', () => {
      expect(importMatches(byId('js-pqc-crystals-kyber'), "import { MlKem768 } from 'ml-kem'")).toBe(true);
    });

    it('js-pqc-crystals-kyber matches MlKem768 call', () => {
      expect(callMatches(byId('js-pqc-crystals-kyber'), 'const kem = MlKem768(params)')).toBe(true);
    });

    it('js-pqc-crystals-kyber matches Kyber768 call', () => {
      expect(callMatches(byId('js-pqc-crystals-kyber'), 'const kem = Kyber768.encapsulate(pk)')).toBe(true);
    });

    it('js-pqc-crystals-kyber is safe', () => {
      expect(byId('js-pqc-crystals-kyber').risk).toBe('safe');
    });

    it('js-pqc-dilithium matches crystals-dilithium require', () => {
      expect(importMatches(byId('js-pqc-dilithium'), "const dil = require('crystals-dilithium')")).toBe(true);
    });

    it('js-pqc-dilithium matches ml-dsa import', () => {
      expect(importMatches(byId('js-pqc-dilithium'), "import { MlDsa65 } from 'ml-dsa'")).toBe(true);
    });

    it('js-pqc-dilithium matches MlDsa65 call', () => {
      expect(callMatches(byId('js-pqc-dilithium'), 'const sig = MlDsa65(params)')).toBe(true);
    });

    it('js-pqc-dilithium matches Dilithium3 call', () => {
      expect(callMatches(byId('js-pqc-dilithium'), 'const sig = Dilithium3.sign(msg, sk)')).toBe(true);
    });

    it('js-pqc-dilithium is safe', () => {
      expect(byId('js-pqc-dilithium').risk).toBe('safe');
    });

    it('all PQC patterns are categorized as pqc-algorithm', () => {
      const pqc = javascriptPatterns.filter((p) => p.id.includes('-pqc-'));
      expect(pqc).toHaveLength(3);
      pqc.forEach((p) => expect(p.category).toBe('pqc-algorithm'));
    });
  });
});
