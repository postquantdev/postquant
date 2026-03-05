import { describe, it, expect } from 'vitest';
import { goPatterns } from '../patterns/go.js';
import type { CryptoPattern } from '../../../types/index.js';

const byId = (id: string): CryptoPattern => {
  const p = goPatterns.find((pat) => pat.id === id);
  if (!p) throw new Error(`Pattern not found: ${id}`);
  return p;
};

const callMatches = (p: CryptoPattern, s: string): boolean =>
  p.callPatterns.some((r) => r.test(s));

const importMatches = (p: CryptoPattern, s: string): boolean =>
  (p.importPatterns ?? []).some((r) => r.test(s));

describe('Go patterns', () => {
  it('exports 16 patterns', () => {
    expect(goPatterns).toHaveLength(16);
  });

  describe.each(goPatterns)('$id', (pattern) => {
    it('has valid structure', () => {
      expect(pattern.id).toMatch(/^go-/);
      expect(pattern.language).toBe('go');
      expect(pattern.callPatterns.length).toBeGreaterThan(0);
      expect(pattern.description).toBeTruthy();
      expect(pattern.migration).toBeTruthy();
      expect(['critical', 'moderate', 'safe']).toContain(pattern.risk);
    });
  });

  // --- Call pattern match tests ---
  const matchCases: [string, string][] = [
    ['go-rsa-keygen', 'key, err := rsa.GenerateKey(rand.Reader, 2048)'],
    ['go-rsa-keygen', 'key, err := rsa.GenerateKey(rand.Reader, 4096)'],
    ['go-rsa-sign', 'sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)'],
    ['go-rsa-sign', 'sig, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed, opts)'],
    ['go-rsa-encrypt', 'ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, nil)'],
    ['go-rsa-encrypt', 'ct, err := rsa.EncryptPKCS1v15(rand.Reader, pub, plaintext)'],
    ['go-ecdsa-keygen', 'key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)'],
    ['go-ecdsa-sign', 'r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)'],
    ['go-ecdsa-sign', 'sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash)'],
    ['go-ed25519', 'pub, priv, err := ed25519.GenerateKey(rand.Reader)'],
    ['go-ed25519', 'sig := ed25519.Sign(privateKey, message)'],
    ['go-dsa-keygen', 'err = dsa.GenerateKey(&privateKey, rand.Reader)'],
    ['go-curve25519', 'shared, err := curve25519.X25519(scalar, point)'],
    ['go-curve25519', 'curve25519.ScalarMult(dst, scalar, point)'],
    ['go-nacl-box', 'pub, priv, err := box.GenerateKey(rand.Reader)'],
    ['go-nacl-box', 'out := box.Seal(nil, message, nonce, peerPublic, privateKey)'],
    ['go-md5', 'h := md5.New()'],
    ['go-md5', 'sum := md5.Sum(data)'],
    ['go-sha1', 'h := sha1.New()'],
    ['go-sha1', 'sum := sha1.Sum(data)'],
    ['go-sha256', 'h := sha256.New()'],
    ['go-sha256', 'sum := sha256.Sum256(data)'],
    ['go-sha256', 'h := sha512.New()'],
    ['go-aes', 'block, err := aes.NewCipher(key)'],
  ];

  it.each(matchCases)('%s matches: %s', (id, code) => {
    expect(callMatches(byId(id), code)).toBe(true);
  });

  // --- Non-match tests ---
  const noMatchCases: [string, string][] = [
    ['go-rsa-keygen', 'fmt.Println("hello")'],
    ['go-md5', 'sha256.New()'],
    ['go-sha256', 'md5.New()'],
  ];

  it.each(noMatchCases)('%s does NOT match: %s', (id, code) => {
    expect(callMatches(byId(id), code)).toBe(false);
  });

  // --- Import pattern tests ---
  const importCases: [string, string][] = [
    ['go-rsa-keygen', '"crypto/rsa"'],
    ['go-ecdsa-keygen', '"crypto/ecdsa"'],
    ['go-ed25519', '"crypto/ed25519"'],
    ['go-md5', '"crypto/md5"'],
    ['go-curve25519', '"golang.org/x/crypto/curve25519"'],
    ['go-nacl-box', '"golang.org/x/crypto/nacl/box"'],
  ];

  it.each(importCases)('%s import matches: %s', (id, importLine) => {
    expect(importMatches(byId(id), importLine)).toBe(true);
  });

  // --- Key size tests ---
  it('go-rsa-keygen extracts key size', () => {
    const p = byId('go-rsa-keygen');
    const match = 'rsa.GenerateKey(rand.Reader, 4096)'.match(p.keySizeExtractor!);
    expect(match).toBeTruthy();
    expect(parseInt(match![1])).toBe(4096);
  });

  it('all asymmetric/signature/exchange patterns are critical', () => {
    const critical = goPatterns.filter(
      (p) =>
        p.category === 'asymmetric-encryption' ||
        p.category === 'digital-signature' ||
        p.category === 'key-exchange',
    );
    critical.forEach((p) => expect(p.risk).toBe('critical'));
  });

  it('sha256 is safe', () => {
    expect(byId('go-sha256').risk).toBe('safe');
  });

  // --- PQC patterns ---
  describe('PQC patterns', () => {
    it('go-pqc-circl-kem matches circl/kem/mlkem import', () => {
      expect(importMatches(byId('go-pqc-circl-kem'), '"github.com/cloudflare/circl/kem/mlkem"')).toBe(true);
    });

    it('go-pqc-circl-kem matches circl/kem/kyber import', () => {
      expect(importMatches(byId('go-pqc-circl-kem'), '"github.com/cloudflare/circl/kem/kyber"')).toBe(true);
    });

    it('go-pqc-circl-kem matches mlkem.KeyGen call', () => {
      expect(callMatches(byId('go-pqc-circl-kem'), 'pk, sk := mlkem.KeyGen()')).toBe(true);
    });

    it('go-pqc-circl-kem matches kyber.Encapsulate call', () => {
      expect(callMatches(byId('go-pqc-circl-kem'), 'ct, ss := kyber.Encapsulate(pk)')).toBe(true);
    });

    it('go-pqc-circl-kem is safe', () => {
      expect(byId('go-pqc-circl-kem').risk).toBe('safe');
    });

    it('go-pqc-circl-sig matches circl/sign/mldsa import', () => {
      expect(importMatches(byId('go-pqc-circl-sig'), '"github.com/cloudflare/circl/sign/mldsa"')).toBe(true);
    });

    it('go-pqc-circl-sig matches circl/sign/dilithium import', () => {
      expect(importMatches(byId('go-pqc-circl-sig'), '"github.com/cloudflare/circl/sign/dilithium"')).toBe(true);
    });

    it('go-pqc-circl-sig matches mldsa.Sign call', () => {
      expect(callMatches(byId('go-pqc-circl-sig'), 'sig := mldsa.Sign(sk, msg)')).toBe(true);
    });

    it('go-pqc-circl-sig matches dilithium.Verify call', () => {
      expect(callMatches(byId('go-pqc-circl-sig'), 'ok := dilithium.Verify(pk, msg, sig)')).toBe(true);
    });

    it('go-pqc-circl-sig is safe', () => {
      expect(byId('go-pqc-circl-sig').risk).toBe('safe');
    });

    it('go-pqc-stdlib matches crypto/mlkem import', () => {
      expect(importMatches(byId('go-pqc-stdlib'), '"crypto/mlkem"')).toBe(true);
    });

    it('go-pqc-stdlib matches crypto/mldsa import', () => {
      expect(importMatches(byId('go-pqc-stdlib'), '"crypto/mldsa"')).toBe(true);
    });

    it('go-pqc-stdlib matches mlkem.GenerateKey call', () => {
      expect(callMatches(byId('go-pqc-stdlib'), 'pk, sk, err := mlkem.GenerateKey()')).toBe(true);
    });

    it('go-pqc-stdlib matches mldsa.Sign call', () => {
      expect(callMatches(byId('go-pqc-stdlib'), 'sig := mldsa.Sign(sk, msg)')).toBe(true);
    });

    it('go-pqc-stdlib is safe', () => {
      expect(byId('go-pqc-stdlib').risk).toBe('safe');
    });

    it('all PQC patterns are categorized as pqc-algorithm', () => {
      const pqc = goPatterns.filter((p) => p.id.includes('-pqc-'));
      expect(pqc).toHaveLength(3);
      pqc.forEach((p) => expect(p.category).toBe('pqc-algorithm'));
    });
  });
});
