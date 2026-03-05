import { describe, it, expect } from 'vitest';
import { formatCodeTerminal } from './terminal-code.js';
import type { CodeGradedResult, CodeFinding, FileBreakdown } from '../types/index.js';

function makeFinding(overrides: Partial<CodeFinding> = {}): CodeFinding {
  return {
    patternId: 'python-rsa-keygen',
    file: 'src/auth.py',
    line: 42,
    matchedLine: 'rsa.generate_private_key(public_exponent=65537, key_size=2048)',
    language: 'python',
    category: 'asymmetric-encryption',
    algorithm: 'RSA-2048',
    risk: 'critical',
    reason: "Vulnerable to Shor's algorithm",
    migration: 'Replace with ML-DSA (FIPS 204)',
    confidence: 'high',
    ...overrides,
  };
}

function makeCodeGradedResult(overrides: Partial<CodeGradedResult> = {}): CodeGradedResult {
  return {
    scanRoot: '/project',
    grade: 'C',
    baseGrade: 'C',
    modifier: '',
    pqcDetected: false,
    findings: [
      makeFinding(),
      makeFinding({
        patternId: 'python-ecdsa',
        file: 'src/auth.py',
        line: 55,
        matchedLine: 'ec.generate_private_key(ec.SECP256R1())',
        algorithm: 'ECDSA-P256',
        category: 'digital-signature',
        migration: 'Replace with ML-DSA (FIPS 204)',
      }),
      makeFinding({
        patternId: 'python-aes-128',
        file: 'src/encrypt.py',
        line: 10,
        matchedLine: 'Cipher(algorithms.AES(key), modes.GCM(iv))',
        algorithm: 'AES-128',
        risk: 'moderate',
        category: 'weak-symmetric',
        migration: 'Upgrade to AES-256',
      }),
    ],
    migrationNotes: [
      'Replace with ML-DSA (FIPS 204)',
      'Upgrade to AES-256',
    ],
    summary: {
      critical: 2,
      moderate: 1,
      safe: 0,
      total: 3,
      filesScanned: 15,
      filesWithFindings: 2,
    },
    fileBreakdown: [
      {
        file: 'src/auth.py',
        language: 'python',
        findings: [makeFinding(), makeFinding({
          patternId: 'python-ecdsa',
          file: 'src/auth.py',
          line: 55,
          matchedLine: 'ec.generate_private_key(ec.SECP256R1())',
          algorithm: 'ECDSA-P256',
          category: 'digital-signature',
        })],
        criticalCount: 2,
        moderateCount: 0,
        safeCount: 0,
      },
      {
        file: 'src/encrypt.py',
        language: 'python',
        findings: [makeFinding({
          patternId: 'python-aes-128',
          file: 'src/encrypt.py',
          line: 10,
          matchedLine: 'Cipher(algorithms.AES(key), modes.GCM(iv))',
          algorithm: 'AES-128',
          risk: 'moderate',
          category: 'weak-symmetric',
        })],
        criticalCount: 0,
        moderateCount: 1,
        safeCount: 0,
      },
    ],
    ...overrides,
  };
}

function stripAnsi(str: string): string {
  return str.replace(/\u001b\[[0-9;]*m/g, '');
}

describe('formatCodeTerminal', () => {
  it('includes PostQuant header with version', () => {
    const output = stripAnsi(formatCodeTerminal(makeCodeGradedResult()));
    expect(output).toContain('PostQuant');
    expect(output).toContain('Code Scanner');
  });

  it('includes scan root path', () => {
    const output = stripAnsi(formatCodeTerminal(makeCodeGradedResult()));
    expect(output).toContain('/project');
  });

  it('includes the overall grade', () => {
    const output = stripAnsi(formatCodeTerminal(makeCodeGradedResult()));
    expect(output).toContain('Overall Grade');
    expect(output).toContain('C');
  });

  it('shows A+ grade correctly', () => {
    const output = stripAnsi(formatCodeTerminal(makeCodeGradedResult({
      grade: 'A+',
      baseGrade: 'A+',
      modifier: '',
      findings: [],
      fileBreakdown: [],
      summary: { critical: 0, moderate: 0, safe: 0, total: 0, filesScanned: 5, filesWithFindings: 0 },
    })));
    expect(output).toContain('A+');
  });

  it('includes summary counts', () => {
    const output = stripAnsi(formatCodeTerminal(makeCodeGradedResult()));
    expect(output).toContain('2');
    expect(output).toContain('1');
  });

  it('includes files scanned count', () => {
    const output = stripAnsi(formatCodeTerminal(makeCodeGradedResult()));
    expect(output).toContain('15');
  });

  it('includes per-file breakdown with file paths', () => {
    const output = stripAnsi(formatCodeTerminal(makeCodeGradedResult()));
    expect(output).toContain('src/auth.py');
    expect(output).toContain('src/encrypt.py');
  });

  it('includes finding line numbers', () => {
    const output = stripAnsi(formatCodeTerminal(makeCodeGradedResult()));
    expect(output).toContain('42');
    expect(output).toContain('55');
  });

  it('includes algorithm names in findings', () => {
    const output = stripAnsi(formatCodeTerminal(makeCodeGradedResult()));
    expect(output).toContain('RSA-2048');
    expect(output).toContain('ECDSA-P256');
    expect(output).toContain('AES-128');
  });

  it('includes risk indicators', () => {
    const output = stripAnsi(formatCodeTerminal(makeCodeGradedResult()));
    expect(output).toContain('Quantum Vulnerable');
    expect(output).toContain('Moderate Risk');
  });

  it('includes migration notes', () => {
    const output = stripAnsi(formatCodeTerminal(makeCodeGradedResult()));
    expect(output).toContain('ML-DSA');
    expect(output).toContain('AES-256');
  });

  it('includes NIST timeline in migration notes', () => {
    const output = stripAnsi(formatCodeTerminal(makeCodeGradedResult()));
    expect(output).toContain('NIST');
    expect(output).toContain('2030');
  });

  it('hides migration notes when noMigration is true', () => {
    const output = stripAnsi(formatCodeTerminal(makeCodeGradedResult(), { noMigration: true }));
    expect(output).not.toContain('Migration');
    expect(output).not.toContain('ML-DSA');
  });

  it('shows safe findings when verbose is true', () => {
    const safeFinding = makeFinding({
      patternId: 'python-sha512',
      file: 'src/hash.py',
      line: 5,
      matchedLine: 'hashlib.sha512(data)',
      algorithm: 'SHA-512',
      risk: 'safe',
      category: 'safe-hash',
    });
    const result = makeCodeGradedResult({
      findings: [
        ...makeCodeGradedResult().findings,
        safeFinding,
      ],
      fileBreakdown: [
        ...makeCodeGradedResult().fileBreakdown,
        {
          file: 'src/hash.py',
          language: 'python',
          findings: [safeFinding],
          criticalCount: 0,
          moderateCount: 0,
          safeCount: 1,
        },
      ],
      summary: { critical: 2, moderate: 1, safe: 1, total: 4, filesScanned: 15, filesWithFindings: 3 },
    });
    const output = stripAnsi(formatCodeTerminal(result, { verbose: true }));
    expect(output).toContain('SHA-512');
    expect(output).toContain('Quantum Safe');
  });

  it('hides safe-only files when verbose is false (default)', () => {
    const safeFinding = makeFinding({
      patternId: 'python-sha512',
      file: 'src/hash.py',
      line: 5,
      matchedLine: 'hashlib.sha512(data)',
      algorithm: 'SHA-512',
      risk: 'safe',
      category: 'safe-hash',
    });
    const result = makeCodeGradedResult({
      fileBreakdown: [
        ...makeCodeGradedResult().fileBreakdown,
        {
          file: 'src/hash.py',
          language: 'python',
          findings: [safeFinding],
          criticalCount: 0,
          moderateCount: 0,
          safeCount: 1,
        },
      ],
    });
    const output = stripAnsi(formatCodeTerminal(result));
    expect(output).not.toContain('src/hash.py');
  });

  it('shows PQC Readiness: Detected when pqcDetected is true', () => {
    const output = stripAnsi(formatCodeTerminal(makeCodeGradedResult({ pqcDetected: true })));
    expect(output).toContain('PQC Readiness');
    expect(output).toContain('Detected');
  });

  it('shows PQC Readiness: Not detected when pqcDetected is false', () => {
    const output = stripAnsi(formatCodeTerminal(makeCodeGradedResult({ pqcDetected: false })));
    expect(output).toContain('PQC Readiness');
    expect(output).toContain('Not detected');
  });

  it('shows no findings message for A grade', () => {
    const result = makeCodeGradedResult({
      grade: 'A',
      baseGrade: 'A',
      modifier: '',
      findings: [],
      fileBreakdown: [],
      migrationNotes: [],
      summary: { critical: 0, moderate: 0, safe: 0, total: 0, filesScanned: 10, filesWithFindings: 0 },
    });
    const output = stripAnsi(formatCodeTerminal(result));
    expect(output).toContain('No quantum-vulnerable');
  });
});
