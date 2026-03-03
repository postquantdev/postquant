import { describe, it, expect } from 'vitest';
import { classifyCodeFindings } from '../classifier.js';
import type { CodeFinding, Language } from '../../../types/index.js';

function makeFinding(overrides: Partial<CodeFinding> = {}): CodeFinding {
  return {
    patternId: 'test-pattern',
    file: 'src/auth.py',
    line: 10,
    matchedLine: 'rsa.generate_private_key(key_size=2048)',
    language: 'python' as Language,
    category: 'asymmetric-encryption',
    algorithm: 'RSA-2048',
    risk: 'critical',
    reason: 'Vulnerable to Shor\'s algorithm',
    migration: 'Use ML-KEM (FIPS 203)',
    confidence: 'high',
    ...overrides,
  };
}

describe('classifyCodeFindings', () => {
  it('returns empty result for no findings', () => {
    const result = classifyCodeFindings([], '/project', 5, 100);
    expect(result.findings).toEqual([]);
    expect(result.filesScanned).toBe(5);
    expect(result.filesWithFindings).toBe(0);
    expect(result.languagesDetected).toEqual([]);
  });

  it('preserves scanRoot', () => {
    const result = classifyCodeFindings([], '/my/project', 0, 50);
    expect(result.scanRoot).toBe('/my/project');
  });

  it('counts filesWithFindings from unique file paths', () => {
    const findings = [
      makeFinding({ file: 'src/a.py', line: 1 }),
      makeFinding({ file: 'src/a.py', line: 5 }),
      makeFinding({ file: 'src/b.py', line: 3 }),
    ];
    const result = classifyCodeFindings(findings, '/project', 10, 100);
    expect(result.filesWithFindings).toBe(2);
  });

  it('detects unique languages across findings', () => {
    const findings = [
      makeFinding({ language: 'python' }),
      makeFinding({ language: 'python', file: 'src/b.py' }),
      makeFinding({ language: 'go', file: 'src/c.go' }),
      makeFinding({ language: 'java', file: 'src/D.java' }),
    ];
    const result = classifyCodeFindings(findings, '/project', 20, 100);
    expect(result.languagesDetected).toContain('python');
    expect(result.languagesDetected).toContain('go');
    expect(result.languagesDetected).toContain('java');
    expect(result.languagesDetected).toHaveLength(3);
  });

  it('passes through all findings unchanged', () => {
    const findings = [
      makeFinding({ algorithm: 'RSA-2048', risk: 'critical' }),
      makeFinding({ algorithm: 'AES-128', risk: 'moderate', category: 'weak-symmetric', file: 'src/enc.py' }),
    ];
    const result = classifyCodeFindings(findings, '/project', 10, 100);
    expect(result.findings).toHaveLength(2);
    expect(result.findings[0].algorithm).toBe('RSA-2048');
    expect(result.findings[1].algorithm).toBe('AES-128');
  });

  it('stores durationMs from the provided value', () => {
    const result = classifyCodeFindings([], '/project', 5, 42);
    expect(result.durationMs).toBe(42);
  });

  it('handles single finding correctly', () => {
    const findings = [makeFinding()];
    const result = classifyCodeFindings(findings, '/project', 1, 10);
    expect(result.findings).toHaveLength(1);
    expect(result.filesWithFindings).toBe(1);
    expect(result.filesScanned).toBe(1);
    expect(result.languagesDetected).toEqual(['python']);
  });
});
