import { describe, it, expect } from 'vitest';
import { classify } from './classifier.js';
import type { TlsScanResult } from '../types/index.js';

function makeScanResult(overrides: Partial<TlsScanResult> = {}): TlsScanResult {
  return {
    host: 'example.com',
    port: 443,
    protocol: 'TLSv1.3',
    cipher: {
      name: 'TLS_AES_256_GCM_SHA384',
      standardName: 'TLS_AES_256_GCM_SHA384',
      version: 'TLSv1.3',
      bits: 256,
    },
    certificate: {
      subject: 'example.com',
      issuer: 'Example CA',
      validFrom: '2025-01-01',
      validTo: '2026-01-01',
      serialNumber: 'ABC123',
      fingerprint256: 'AA:BB:CC',
      sigAlgorithm: 'sha256WithRSAEncryption',
      publicKeyAlgorithm: 'RSA',
      publicKeySize: 2048,
    },
    ephemeralKeyInfo: {
      type: 'ECDH',
      name: 'X25519',
      size: 253,
    },
    ...overrides,
  };
}

describe('classify', () => {
  describe('protocol classification', () => {
    it('classifies TLS 1.3 as safe', () => {
      const result = classify(makeScanResult({ protocol: 'TLSv1.3' }));
      const finding = result.findings.find((f) => f.component === 'protocol');
      expect(finding?.risk).toBe('safe');
    });

    it('classifies TLS 1.2 as moderate', () => {
      const result = classify(makeScanResult({ protocol: 'TLSv1.2' }));
      const finding = result.findings.find((f) => f.component === 'protocol');
      expect(finding?.risk).toBe('moderate');
    });

    it('classifies TLS 1.1 as critical', () => {
      const result = classify(makeScanResult({ protocol: 'TLSv1.1' }));
      const finding = result.findings.find((f) => f.component === 'protocol');
      expect(finding?.risk).toBe('critical');
    });

    it('classifies TLS 1.0 as critical', () => {
      const result = classify(makeScanResult({ protocol: 'TLSv1' }));
      const finding = result.findings.find((f) => f.component === 'protocol');
      expect(finding?.risk).toBe('critical');
    });

    it('classifies null protocol as critical', () => {
      const result = classify(makeScanResult({ protocol: null }));
      const finding = result.findings.find((f) => f.component === 'protocol');
      expect(finding?.risk).toBe('critical');
    });
  });

  describe('certificate classification', () => {
    it('classifies RSA as critical', () => {
      const result = classify(makeScanResult());
      const finding = result.findings.find((f) => f.component === 'certificate');
      expect(finding?.risk).toBe('critical');
      expect(finding?.reason).toContain('Shor');
    });

    it('classifies ECDSA as critical', () => {
      const scan = makeScanResult();
      scan.certificate!.publicKeyAlgorithm = 'EC';
      scan.certificate!.publicKeySize = 256;
      const result = classify(scan);
      const finding = result.findings.find((f) => f.component === 'certificate');
      expect(finding?.risk).toBe('critical');
    });

    it('classifies Ed25519 as critical', () => {
      const scan = makeScanResult();
      scan.certificate!.publicKeyAlgorithm = 'Ed25519';
      const result = classify(scan);
      const finding = result.findings.find((f) => f.component === 'certificate');
      expect(finding?.risk).toBe('critical');
    });

    it('classifies ML-DSA as safe', () => {
      const scan = makeScanResult();
      scan.certificate!.publicKeyAlgorithm = 'ML-DSA';
      const result = classify(scan);
      const finding = result.findings.find((f) => f.component === 'certificate');
      expect(finding?.risk).toBe('safe');
    });

    it('classifies null certificate as critical', () => {
      const result = classify(makeScanResult({ certificate: null }));
      const finding = result.findings.find((f) => f.component === 'certificate');
      expect(finding?.risk).toBe('critical');
    });
  });

  describe('key exchange classification', () => {
    it('classifies X25519 as critical', () => {
      const result = classify(makeScanResult());
      const finding = result.findings.find((f) => f.component === 'keyExchange');
      expect(finding?.risk).toBe('critical');
    });

    it('classifies ECDH as critical', () => {
      const scan = makeScanResult();
      scan.ephemeralKeyInfo = { type: 'ECDH', name: 'prime256v1', size: 256 };
      const result = classify(scan);
      const finding = result.findings.find((f) => f.component === 'keyExchange');
      expect(finding?.risk).toBe('critical');
    });

    it('classifies DH as critical', () => {
      const scan = makeScanResult();
      scan.ephemeralKeyInfo = { type: 'DH', size: 2048 };
      const result = classify(scan);
      const finding = result.findings.find((f) => f.component === 'keyExchange');
      expect(finding?.risk).toBe('critical');
    });

    it('classifies X25519Kyber768 as safe', () => {
      const scan = makeScanResult();
      scan.ephemeralKeyInfo = { type: 'ECDH', name: 'X25519Kyber768', size: 1216 };
      const result = classify(scan);
      const finding = result.findings.find((f) => f.component === 'keyExchange');
      expect(finding?.risk).toBe('safe');
    });

    it('classifies MLKEM in cipher name as safe', () => {
      const scan = makeScanResult();
      scan.ephemeralKeyInfo = null;
      scan.cipher!.name = 'TLS_AES_256_GCM_SHA384_MLKEM768';
      const result = classify(scan);
      const finding = result.findings.find((f) => f.component === 'keyExchange');
      expect(finding?.risk).toBe('safe');
    });

    it('classifies X25519MLKEM768 from openssl probe as safe', () => {
      const scan = makeScanResult();
      scan.ephemeralKeyInfo = { type: 'KEM', name: 'X25519MLKEM768', size: 0 };
      const result = classify(scan);
      const finding = result.findings.find((f) => f.component === 'keyExchange');
      expect(finding?.risk).toBe('safe');
      expect(finding?.algorithm).toBe('X25519MLKEM768');
    });

    it('infers X25519 for TLS 1.3 when ephemeral key info is empty', () => {
      const scan = makeScanResult();
      scan.ephemeralKeyInfo = null;
      const result = classify(scan);
      const finding = result.findings.find((f) => f.component === 'keyExchange');
      expect(finding?.risk).toBe('critical');
      expect(finding?.algorithm).toBe('X25519 (inferred)');
    });

    it('infers ECDHE from TLS 1.2 cipher name when ephemeral key info is empty', () => {
      const scan = makeScanResult();
      scan.protocol = 'TLSv1.2';
      scan.ephemeralKeyInfo = null;
      scan.cipher!.name = 'ECDHE-RSA-AES256-GCM-SHA384';
      const result = classify(scan);
      const finding = result.findings.find((f) => f.component === 'keyExchange');
      expect(finding?.risk).toBe('critical');
      expect(finding?.algorithm).toBe('ECDHE (inferred)');
    });

    it('classifies unknown key exchange as critical for non-TLS 1.3', () => {
      const scan = makeScanResult();
      scan.protocol = 'TLSv1.2';
      scan.ephemeralKeyInfo = null;
      scan.cipher!.name = 'TLS_AES_256_GCM_SHA384';
      const result = classify(scan);
      const finding = result.findings.find((f) => f.component === 'keyExchange');
      expect(finding?.risk).toBe('critical');
      expect(finding?.algorithm).toBe('Unknown');
    });
  });

  describe('cipher classification', () => {
    it('classifies AES-256-GCM as safe', () => {
      const result = classify(makeScanResult());
      const finding = result.findings.find((f) => f.component === 'cipher');
      expect(finding?.risk).toBe('safe');
    });

    it('classifies AES-128-GCM as moderate', () => {
      const scan = makeScanResult();
      scan.cipher!.name = 'TLS_AES_128_GCM_SHA256';
      scan.cipher!.bits = 128;
      const result = classify(scan);
      const finding = result.findings.find((f) => f.component === 'cipher');
      expect(finding?.risk).toBe('moderate');
    });

    it('classifies ChaCha20-Poly1305 as safe', () => {
      const scan = makeScanResult();
      scan.cipher!.name = 'TLS_CHACHA20_POLY1305_SHA256';
      scan.cipher!.bits = 256;
      const result = classify(scan);
      const finding = result.findings.find((f) => f.component === 'cipher');
      expect(finding?.risk).toBe('safe');
    });

    it('classifies null cipher as critical', () => {
      const result = classify(makeScanResult({ cipher: null }));
      const finding = result.findings.find((f) => f.component === 'cipher');
      expect(finding?.risk).toBe('critical');
    });
  });

  describe('hash classification', () => {
    it('classifies SHA384 as safe', () => {
      const result = classify(makeScanResult());
      const finding = result.findings.find((f) => f.component === 'hash');
      expect(finding?.risk).toBe('safe');
    });

    it('classifies SHA256 as moderate', () => {
      const scan = makeScanResult();
      scan.cipher!.name = 'TLS_AES_256_GCM_SHA256';
      const result = classify(scan);
      const finding = result.findings.find((f) => f.component === 'hash');
      expect(finding?.risk).toBe('moderate');
    });

    it('classifies SHA1 in TLS 1.2 cipher as critical', () => {
      const scan = makeScanResult();
      scan.cipher!.name = 'ECDHE-RSA-AES256-SHA';
      scan.cipher!.standardName = 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA';
      const result = classify(scan);
      const finding = result.findings.find((f) => f.component === 'hash');
      expect(finding?.risk).toBe('critical');
    });
  });

  describe('finding structure', () => {
    it('returns exactly 5 findings', () => {
      const result = classify(makeScanResult());
      expect(result.findings).toHaveLength(5);
    });

    it('includes all component types', () => {
      const result = classify(makeScanResult());
      const components = result.findings.map((f) => f.component);
      expect(components).toContain('protocol');
      expect(components).toContain('certificate');
      expect(components).toContain('keyExchange');
      expect(components).toContain('cipher');
      expect(components).toContain('hash');
    });

    it('includes migration recommendation for critical findings', () => {
      const result = classify(makeScanResult());
      const critical = result.findings.filter((f) => f.risk === 'critical');
      for (const finding of critical) {
        expect(finding.migration).toBeTruthy();
      }
    });

    it('preserves host and port', () => {
      const result = classify(makeScanResult({ host: 'test.com', port: 8443 }));
      expect(result.host).toBe('test.com');
      expect(result.port).toBe(8443);
    });
  });

  describe('unknown algorithms', () => {
    it('classifies unknown certificate algorithm as critical', () => {
      const scan = makeScanResult();
      scan.certificate!.publicKeyAlgorithm = 'UNKNOWN_ALGO';
      const result = classify(scan);
      const finding = result.findings.find((f) => f.component === 'certificate');
      expect(finding?.risk).toBe('critical');
      expect(finding?.reason).toContain('Unknown');
    });
  });
});
