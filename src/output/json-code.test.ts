import { describe, it, expect } from 'vitest';
import { formatCodeJson } from './json-code.js';
import type { CodeGradedResult, CodeFinding } from '../types/index.js';

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
    grade: 'C+',
    baseGrade: 'C',
    modifier: '+',
    findings: [
      makeFinding(),
      makeFinding({
        patternId: 'python-aes-128',
        file: 'src/encrypt.py',
        line: 10,
        algorithm: 'AES-128',
        risk: 'moderate',
        category: 'weak-symmetric',
        migration: 'Upgrade to AES-256',
      }),
    ],
    migrationNotes: ['Replace with ML-DSA (FIPS 204)', 'Upgrade to AES-256'],
    summary: {
      critical: 1,
      moderate: 1,
      safe: 0,
      total: 2,
      filesScanned: 10,
      filesWithFindings: 2,
    },
    fileBreakdown: [
      {
        file: 'src/auth.py',
        language: 'python',
        findings: [makeFinding()],
        criticalCount: 1,
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

describe('formatCodeJson', () => {
  it('returns valid JSON string', () => {
    const output = formatCodeJson(makeCodeGradedResult());
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('includes version and timestamp', () => {
    const parsed = JSON.parse(formatCodeJson(makeCodeGradedResult()));
    expect(parsed.version).toBeDefined();
    expect(parsed.timestamp).toBeDefined();
  });

  it('includes scanRoot', () => {
    const parsed = JSON.parse(formatCodeJson(makeCodeGradedResult()));
    expect(parsed.scanRoot).toBe('/project');
  });

  it('includes grade, baseGrade, and modifier', () => {
    const parsed = JSON.parse(formatCodeJson(makeCodeGradedResult()));
    expect(parsed.grade).toBe('C+');
    expect(parsed.baseGrade).toBe('C');
    expect(parsed.modifier).toBe('+');
  });

  it('includes all findings with correct fields', () => {
    const parsed = JSON.parse(formatCodeJson(makeCodeGradedResult()));
    expect(parsed.findings).toHaveLength(2);
    const first = parsed.findings[0];
    expect(first.patternId).toBe('python-rsa-keygen');
    expect(first.file).toBe('src/auth.py');
    expect(first.line).toBe(42);
    expect(first.algorithm).toBe('RSA-2048');
    expect(first.risk).toBe('critical');
    expect(first.language).toBe('python');
    expect(first.category).toBe('asymmetric-encryption');
  });

  it('includes summary with all counts', () => {
    const parsed = JSON.parse(formatCodeJson(makeCodeGradedResult()));
    expect(parsed.summary.critical).toBe(1);
    expect(parsed.summary.moderate).toBe(1);
    expect(parsed.summary.safe).toBe(0);
    expect(parsed.summary.total).toBe(2);
    expect(parsed.summary.filesScanned).toBe(10);
    expect(parsed.summary.filesWithFindings).toBe(2);
  });

  it('includes fileBreakdown', () => {
    const parsed = JSON.parse(formatCodeJson(makeCodeGradedResult()));
    expect(parsed.fileBreakdown).toHaveLength(2);
    expect(parsed.fileBreakdown[0].file).toBe('src/auth.py');
    expect(parsed.fileBreakdown[0].criticalCount).toBe(1);
    expect(parsed.fileBreakdown[1].file).toBe('src/encrypt.py');
  });

  it('includes migrationNotes', () => {
    const parsed = JSON.parse(formatCodeJson(makeCodeGradedResult()));
    expect(parsed.migrationNotes).toContain('Replace with ML-DSA (FIPS 204)');
    expect(parsed.migrationNotes).toContain('Upgrade to AES-256');
  });

  it('formats with 2-space indentation', () => {
    const output = formatCodeJson(makeCodeGradedResult());
    expect(output).toContain('\n  ');
  });

  it('handles empty findings gracefully', () => {
    const result = makeCodeGradedResult({
      findings: [],
      fileBreakdown: [],
      migrationNotes: [],
      summary: { critical: 0, moderate: 0, safe: 0, total: 0, filesScanned: 5, filesWithFindings: 0 },
      grade: 'A',
      baseGrade: 'A',
      modifier: '',
    });
    const parsed = JSON.parse(formatCodeJson(result));
    expect(parsed.grade).toBe('A');
    expect(parsed.findings).toEqual([]);
    expect(parsed.fileBreakdown).toEqual([]);
  });
});
