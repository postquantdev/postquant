import { describe, it, expect } from 'vitest';
import { formatTerminal } from './terminal.js';
import type { GradedResult } from '../types/index.js';

function makeGradedResult(overrides: Partial<GradedResult> = {}): GradedResult {
  return {
    host: 'example.com',
    port: 443,
    grade: 'C',
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
    migrationNotes: [
      'ML-DSA (FIPS 204)',
      'ML-KEM (FIPS 203) hybrid key exchange',
    ],
    summary: { critical: 2, moderate: 0, safe: 3, total: 5 },
    ...overrides,
  };
}

function stripAnsi(str: string): string {
  return str.replace(/\u001b\[[0-9;]*m/g, '');
}

describe('formatTerminal', () => {
  it('includes PostQuant header', () => {
    const output = stripAnsi(formatTerminal(makeGradedResult()));
    expect(output).toContain('PostQuant');
  });

  it('includes target host and port', () => {
    const output = stripAnsi(formatTerminal(makeGradedResult()));
    expect(output).toContain('example.com:443');
  });

  it('includes the grade', () => {
    const output = stripAnsi(formatTerminal(makeGradedResult()));
    expect(output).toContain('C');
  });

  it('includes certificate algorithm', () => {
    const output = stripAnsi(formatTerminal(makeGradedResult()));
    expect(output).toContain('ECDSA');
  });

  it('includes key exchange', () => {
    const output = stripAnsi(formatTerminal(makeGradedResult()));
    expect(output).toContain('X25519');
  });

  it('includes cipher', () => {
    const output = stripAnsi(formatTerminal(makeGradedResult()));
    expect(output).toContain('AES-256');
  });

  it('includes quantum vulnerability indicators', () => {
    const output = stripAnsi(formatTerminal(makeGradedResult()));
    expect(output).toContain('Quantum Vulnerable');
    expect(output).toContain('Quantum Safe');
  });

  it('includes summary counts', () => {
    const output = stripAnsi(formatTerminal(makeGradedResult()));
    expect(output).toContain('2');
    expect(output).toContain('3');
  });

  it('includes migration notes', () => {
    const output = stripAnsi(formatTerminal(makeGradedResult()));
    expect(output).toContain('ML-DSA');
    expect(output).toContain('ML-KEM');
  });

  it('shows A+ grade correctly', () => {
    const output = stripAnsi(
      formatTerminal(makeGradedResult({ grade: 'A+' })),
    );
    expect(output).toContain('A+');
  });
});
