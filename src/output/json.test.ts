import { describe, it, expect } from 'vitest';
import { formatJson } from './json.js';
import type { GradedResult } from '../types/index.js';

function makeGradedResult(overrides: Partial<GradedResult> = {}): GradedResult {
  return {
    host: 'example.com',
    port: 443,
    grade: 'C',
    baseGrade: 'C',
    modifier: '',
    findings: [
      {
        component: 'protocol',
        algorithm: 'TLS 1.3',
        risk: 'safe',
        reason: 'Current protocol version',
      },
      {
        component: 'certificate',
        algorithm: 'ECDSA',
        keySize: 256,
        curve: 'P-256',
        risk: 'critical',
        reason: "Vulnerable to Shor's algorithm",
        migration: 'ML-DSA (FIPS 204)',
      },
      {
        component: 'keyExchange',
        algorithm: 'X25519',
        risk: 'critical',
        reason: "Vulnerable to Shor's algorithm",
        migration: 'ML-KEM (FIPS 203)',
      },
      {
        component: 'cipher',
        algorithm: 'AES-256',
        keySize: 256,
        risk: 'safe',
        reason: 'Quantum-resistant at current key size',
      },
      {
        component: 'hash',
        algorithm: 'SHA-384',
        risk: 'safe',
        reason: 'Sufficient post-quantum security margin',
      },
    ],
    pqcDetected: false,
    migrationNotes: ['ML-DSA (FIPS 204)', 'ML-KEM (FIPS 203)'],
    summary: { critical: 2, moderate: 0, safe: 3, total: 5 },
    ...overrides,
  };
}

describe('formatJson', () => {
  it('returns valid JSON string', () => {
    const output = formatJson([makeGradedResult()]);
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('includes version and timestamp', () => {
    const output = formatJson([makeGradedResult()]);
    const parsed = JSON.parse(output);
    expect(parsed.version).toBeDefined();
    expect(parsed.timestamp).toBeDefined();
  });

  it('includes results array with correct structure', () => {
    const output = formatJson([makeGradedResult()]);
    const parsed = JSON.parse(output);
    expect(parsed.results).toHaveLength(1);
    expect(parsed.results[0].target).toBe('example.com:443');
    expect(parsed.results[0].grade).toBe('C');
    expect(parsed.results[0].findings).toHaveLength(5);
    expect(parsed.results[0].summary.critical).toBe(2);
  });

  it('includes baseGrade and modifier in output', () => {
    const output = formatJson([makeGradedResult({ grade: 'C+', baseGrade: 'C', modifier: '+' })]);
    const parsed = JSON.parse(output);
    expect(parsed.results[0].grade).toBe('C+');
    expect(parsed.results[0].baseGrade).toBe('C');
    expect(parsed.results[0].modifier).toBe('+');
  });

  it('handles multiple results', () => {
    const r1 = makeGradedResult({ host: 'a.com' });
    const r2 = makeGradedResult({ host: 'b.com', grade: 'D', baseGrade: 'D', modifier: '' });
    const output = formatJson([r1, r2]);
    const parsed = JSON.parse(output);
    expect(parsed.results).toHaveLength(2);
    expect(parsed.results[0].target).toBe('a.com:443');
    expect(parsed.results[1].target).toBe('b.com:443');
  });

  it('includes pqcDetected in JSON output', () => {
    const output = formatJson([makeGradedResult({ pqcDetected: false })]);
    const parsed = JSON.parse(output);
    expect(parsed.results[0].pqcDetected).toBe(false);
  });

  it('includes pqcDetected true when set', () => {
    const output = formatJson([makeGradedResult({ pqcDetected: true })]);
    const parsed = JSON.parse(output);
    expect(parsed.results[0].pqcDetected).toBe(true);
  });

  it('formats with 2-space indentation', () => {
    const output = formatJson([makeGradedResult()]);
    expect(output).toContain('\n  ');
  });
});
