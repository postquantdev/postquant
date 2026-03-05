import { describe, it, expect } from 'vitest';
import { javaPatterns } from '../patterns/java.js';
import type { CryptoPattern } from '../../../types/index.js';

const byId = (id: string): CryptoPattern => {
  const p = javaPatterns.find((pat) => pat.id === id);
  if (!p) throw new Error(`Pattern not found: ${id}`);
  return p;
};

const callMatches = (p: CryptoPattern, s: string): boolean =>
  p.callPatterns.some((r) => r.test(s));

const importMatches = (p: CryptoPattern, s: string): boolean =>
  (p.importPatterns ?? []).some((r) => r.test(s));

describe('Java patterns', () => {
  it('exports 17 patterns', () => {
    expect(javaPatterns).toHaveLength(17);
  });

  describe.each(javaPatterns)('$id', (pattern) => {
    it('has valid structure', () => {
      expect(pattern.id).toMatch(/^java-/);
      expect(pattern.language).toBe('java');
      expect(pattern.callPatterns.length).toBeGreaterThan(0);
      expect(pattern.description).toBeTruthy();
      expect(pattern.migration).toBeTruthy();
      expect(['critical', 'moderate', 'safe']).toContain(pattern.risk);
    });
  });

  // --- Call pattern match tests ---
  const matchCases: [string, string][] = [
    ['java-rsa-keygen', 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");'],
    ['java-ec-keygen', 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");'],
    ['java-dsa-keygen', 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");'],
    ['java-dh-keygen', 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");'],
    ['java-dh-keygen', 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");'],
    ['java-eddsa-keygen', 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("EdDSA");'],
    ['java-eddsa-keygen', 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");'],
    ['java-rsa-sign', 'Signature sig = Signature.getInstance("SHA256withRSA");'],
    ['java-rsa-sign', 'Signature sig = Signature.getInstance("RSASSA-PSS");'],
    ['java-ecdsa-sign', 'Signature sig = Signature.getInstance("SHA256withECDSA");'],
    ['java-key-agreement', 'KeyAgreement ka = KeyAgreement.getInstance("ECDH");'],
    ['java-key-agreement', 'KeyAgreement ka = KeyAgreement.getInstance("DH");'],
    ['java-key-agreement', 'KeyAgreement ka = KeyAgreement.getInstance("X25519");'],
    ['java-key-agreement', 'KeyAgreement ka = KeyAgreement.getInstance("XDH");'],
    ['java-rsa-cipher', 'Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");'],
    ['java-rsa-cipher', 'Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");'],
    ['java-3des', 'Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");'],
    ['java-3des', 'Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");'],
    ['java-md5', 'MessageDigest md = MessageDigest.getInstance("MD5");'],
    ['java-md5', 'Mac mac = Mac.getInstance("HmacMD5");'],
    ['java-sha1', 'MessageDigest md = MessageDigest.getInstance("SHA-1");'],
    ['java-sha1', 'Mac mac = Mac.getInstance("HmacSHA1");'],
    ['java-sha256', 'MessageDigest md = MessageDigest.getInstance("SHA-256");'],
    ['java-sha256', 'MessageDigest md = MessageDigest.getInstance("SHA-384");'],
    ['java-aes-keygen', 'KeyGenerator kg = KeyGenerator.getInstance("AES");'],
  ];

  it.each(matchCases)('%s matches: %s', (id, code) => {
    expect(callMatches(byId(id), code)).toBe(true);
  });

  // --- Non-match tests ---
  const noMatchCases: [string, string][] = [
    ['java-rsa-keygen', 'System.out.println("hello");'],
    ['java-md5', 'MessageDigest.getInstance("SHA-256");'],
    ['java-sha256', 'MessageDigest.getInstance("MD5");'],
    ['java-rsa-cipher', 'Cipher.getInstance("AES/GCM/NoPadding");'],
  ];

  it.each(noMatchCases)('%s does NOT match: %s', (id, code) => {
    expect(callMatches(byId(id), code)).toBe(false);
  });

  // --- Import pattern tests ---
  const importCases: [string, string][] = [
    ['java-rsa-keygen', 'import java.security.KeyPairGenerator;'],
    ['java-rsa-sign', 'import java.security.Signature;'],
    ['java-key-agreement', 'import javax.crypto.KeyAgreement;'],
    ['java-rsa-cipher', 'import javax.crypto.Cipher;'],
    ['java-md5', 'import java.security.MessageDigest;'],
  ];

  it.each(importCases)('%s import matches: %s', (id, importLine) => {
    expect(importMatches(byId(id), importLine)).toBe(true);
  });

  // --- Key size tests ---
  it('java-aes-keygen keySizeRisk differentiates 128 vs 256', () => {
    const p = byId('java-aes-keygen');
    expect(p.keySizeRisk!(128)).toBe('moderate');
    expect(p.keySizeRisk!(256)).toBe('safe');
  });

  it('java-aes-keygen extracts key size from init call', () => {
    const p = byId('java-aes-keygen');
    const match = 'kg.init(128);'.match(p.keySizeExtractor!);
    expect(match).toBeTruthy();
    expect(parseInt(match![1])).toBe(128);
  });

  it('all asymmetric/signature/exchange patterns are critical', () => {
    const critical = javaPatterns.filter(
      (p) =>
        p.category === 'asymmetric-encryption' ||
        p.category === 'digital-signature' ||
        p.category === 'key-exchange',
    );
    critical.forEach((p) => expect(p.risk).toBe('critical'));
  });

  it('sha256 is safe', () => {
    expect(byId('java-sha256').risk).toBe('safe');
  });

  describe('PQC patterns', () => {
    it('java-pqc-bc-provider matches Bouncy Castle PQC provider', () => {
      const p = byId('java-pqc-bc-provider');
      expect(callMatches(p, 'new BouncyCastlePQCProvider()')).toBe(true);
      expect(callMatches(p, 'KeyGenerator.getInstance("ML-KEM-768")')).toBe(true);
      expect(callMatches(p, 'KeyGenerator.getInstance("Kyber512")')).toBe(true);
      expect(callMatches(p, 'Signature.getInstance("Dilithium3")')).toBe(true);
      expect(callMatches(p, 'Signature.getInstance("SLH-DSA-SHA2-128s")')).toBe(true);
      expect(callMatches(p, 'Signature.getInstance("SPHINCS+-SHA2-128s")')).toBe(true);
    });

    it('java-pqc-bc-provider import matches', () => {
      const p = byId('java-pqc-bc-provider');
      expect(importMatches(p, 'import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;')).toBe(true);
      expect(importMatches(p, 'Security.addProvider(new BouncyCastlePQCProvider());')).toBe(true);
    });

    it('java-pqc-kem matches ML-KEM usage', () => {
      const p = byId('java-pqc-kem');
      expect(callMatches(p, 'KeyGenerator.getInstance("ML-KEM-768")')).toBe(true);
      expect(callMatches(p, 'KEM.getInstance("ML-KEM-768")')).toBe(true);
    });

    it('java-pqc-kem import matches', () => {
      const p = byId('java-pqc-kem');
      expect(importMatches(p, 'import org.example.mlkem.KeyEncapsulation;')).toBe(true);
      expect(importMatches(p, 'import com.example.kyber.KyberKEM;')).toBe(true);
      expect(importMatches(p, 'import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;')).toBe(true);
    });

    it('java-pqc-sig matches ML-DSA/SLH-DSA usage', () => {
      const p = byId('java-pqc-sig');
      expect(callMatches(p, 'Signature.getInstance("ML-DSA-65")')).toBe(true);
      expect(callMatches(p, 'Signature.getInstance("SLH-DSA-SHA2-128s")')).toBe(true);
    });

    it('java-pqc-sig import matches', () => {
      const p = byId('java-pqc-sig');
      expect(importMatches(p, 'import org.example.mldsa.Signer;')).toBe(true);
      expect(importMatches(p, 'import com.example.dilithium.DilithiumSig;')).toBe(true);
      expect(importMatches(p, 'import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;')).toBe(true);
    });

    it('all PQC patterns are safe', () => {
      const pqc = javaPatterns.filter((p) => p.category === 'pqc-algorithm');
      expect(pqc).toHaveLength(3);
      pqc.forEach((p) => expect(p.risk).toBe('safe'));
    });
  });
});
